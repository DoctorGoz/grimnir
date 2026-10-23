#!/usr/bin/env python3
"""Extract the durable slice of a Caido project before it is retired.

A Caido project splits into two SQLite files:

  database.caido      the index -- request metadata, sitemap, findings, scopes,
                      environments, AND replay_entries.raw (the crafted replay
                      REQUEST bodies). Typically a few percent of total size.
  database_raw.caido  intercepted request/response bodies and WebSocket payloads.
                      Typically 95%+ of total size, and overwhelmingly noise.

The rotation archives database.caido wholesale, so this script only has to rescue
what lives exclusively in the raw file: replay RESPONSE bodies, and WebSocket
payloads worth keeping.

WebSocket filtering is by volume, not by name: any host whose total payload
exceeds --ws-max-host-mb is treated as a telemetry firehose (market data feeds,
analytics beacons, sync channels) and dropped. This keeps the rule generic
instead of encoding a site-specific denylist.

Writes its outputs into --out-dir and prints a JSON summary on stdout.
"""

from __future__ import annotations

import argparse
import base64
import gzip
import json
import os
import sqlite3
import sys


def connect(project_dir: str) -> sqlite3.Connection:
    index_db = os.path.join(project_dir, "database.caido")
    raw_db = os.path.join(project_dir, "database_raw.caido")
    for path in (index_db, raw_db):
        if not os.path.exists(path):
            sys.exit(f"caido_extract: missing {path}")
    con = sqlite3.connect(f"file:{index_db}?mode=ro", uri=True)
    con.execute("ATTACH DATABASE ? AS raw", (f"file:{raw_db}?mode=ro",))
    return con


def extract_replay(con: sqlite3.Connection, out_dir: str) -> dict:
    """Replay response bodies. The requests already live in the archived index."""
    out = os.path.join(out_dir, "replay-responses.jsonl.gz")
    rows = con.execute("""
        SELECT e.id, e.session_id, s.name, e.created_at, e.error,
               r.host, r.method, r.path, r.query, r.is_tls, r.port,
               resp.status_code, resp.length, resp.roundtrip_time, rr.data
        FROM replay_entries e
        JOIN replay_sessions s ON s.id = e.session_id
        LEFT JOIN requests  r    ON r.id    = e.request_id
        LEFT JOIN responses resp ON resp.id = r.response_id
        LEFT JOIN raw.responses_raw rr ON rr.id = resp.raw_id
        ORDER BY e.id
    """)

    n = with_body = total = 0
    with gzip.open(out, "wt", encoding="utf-8") as fh:
        for (eid, sid, sname, created, err, host, method, path, query,
             tls, port, code, length, rtt, data) in rows:
            rec = {
                "replay_entry_id": eid, "session_id": sid, "session_name": sname,
                "created_at": created, "error": err,
                "host": host, "method": method, "path": path, "query": query,
                "is_tls": tls, "port": port,
                "status_code": code, "length": length, "roundtrip_ms": rtt,
            }
            if data is not None:
                rec["response_b64"] = base64.b64encode(data).decode("ascii")
                with_body += 1
                total += len(data)
            fh.write(json.dumps(rec) + "\n")
            n += 1

    return {"entries": n, "with_body": with_body, "bytes": total,
            "file": os.path.basename(out)}


def extract_ws(con: sqlite3.Connection, out_dir: str, max_host_mb: float,
               extra_excludes: list[str]) -> dict:
    """WebSocket payloads, minus per-host telemetry firehoses."""
    out = os.path.join(out_dir, "ws-messages.jsonl.gz")
    budget = int(max_host_mb * 1024 * 1024)

    excluded = {}
    for host, total in con.execute("""
        SELECT s.host, SUM(m.length)
        FROM streams s JOIN stream_ws_messages m ON m.stream_id = s.id
        GROUP BY s.host
    """):
        if total is not None and total > budget:
            excluded[host] = total
    for host in extra_excludes:
        excluded.setdefault(host, 0)

    if excluded:
        placeholders = ",".join("?" for _ in excluded)
        where = f"WHERE s.host NOT IN ({placeholders})"
        params = tuple(excluded)
    else:
        where, params = "", ()

    rows = con.execute(f"""
        SELECT s.host, s.path, s.port, s.is_tls, s.protocol, s.created_at,
               m.id, m.direction, m.format, m.length, mr.data
        FROM streams s
        JOIN stream_ws_messages m ON m.stream_id = s.id
        JOIN raw.stream_messages_raw mr ON mr.id = m.raw_id
        {where}
        ORDER BY s.host, m.id
    """, params)

    n = total = 0
    hosts: dict[str, int] = {}
    with gzip.open(out, "wt", encoding="utf-8") as fh:
        for (host, path, port, tls, proto, screated,
             mid, direction, fmt, length, data) in rows:
            fh.write(json.dumps({
                "host": host, "path": path, "port": port, "is_tls": tls,
                "protocol": proto, "stream_created_at": screated,
                "message_id": mid, "direction": direction,
                "format": fmt, "length": length,
                "payload_b64": base64.b64encode(data).decode("ascii"),
            }) + "\n")
            n += 1
            total += len(data)
            hosts[host] = hosts.get(host, 0) + 1

    return {
        "messages": n, "bytes": total, "hosts": len(hosts),
        "excluded_hosts": {h: b for h, b in
                           sorted(excluded.items(), key=lambda kv: -kv[1])},
        "file": os.path.basename(out),
    }


def dump_tables(con: sqlite3.Connection, out_dir: str) -> dict:
    """Small JSON dumps that stay readable without sqlite3."""
    queries = {
        "scopes.json": "SELECT * FROM scopes",
        "findings.json": "SELECT * FROM findings",
        "replay-sessions.json": "SELECT id, name FROM replay_sessions ORDER BY id",
        "host-coverage.json": """
            SELECT host, COUNT(*) AS requests, COUNT(DISTINCT path) AS distinct_paths,
                   MIN(created_at) AS first_seen, MAX(created_at) AS last_seen
            FROM requests GROUP BY host ORDER BY requests DESC
        """,
    }
    written = {}
    for name, sql in queries.items():
        try:
            cur = con.execute(sql)
        except sqlite3.Error as exc:            # table absent in older projects
            written[name] = f"skipped: {exc}"
            continue
        cols = [d[0] for d in cur.description]
        rows = [dict(zip(cols, r)) for r in cur]
        with open(os.path.join(out_dir, name), "w", encoding="utf-8") as fh:
            json.dump(rows, fh, indent=2)
        written[name] = len(rows)
    return written


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--project-dir", required=True, help="Caido project directory")
    ap.add_argument("--out-dir", required=True, help="where to write the archive parts")
    ap.add_argument("--ws-max-host-mb", type=float, default=50.0,
                    help="drop WS hosts whose total payload exceeds this (default: 50)")
    ap.add_argument("--ws-exclude-host", action="append", default=[],
                    help="additionally drop this WS host (repeatable)")
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    con = connect(args.project_dir)

    summary = {
        "replay": extract_replay(con, args.out_dir),
        "websocket": extract_ws(con, args.out_dir,
                                args.ws_max_host_mb, args.ws_exclude_host),
        "dumps": dump_tables(con, args.out_dir),
    }
    con.close()
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
