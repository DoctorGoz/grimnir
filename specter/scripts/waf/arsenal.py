#!/usr/bin/env python3
"""
WAF arsenal — orchestrator + CLI.

Ties the three pieces into one targeted flow:

    fingerprint the WAF  ->  probe reflection context  ->  emit ranked variants

Discipline (from the waf-bypass skill): a variant is a CANDIDATE. A 200 through the WAF
is not a finding -- the underlying payload must actually fire at the origin, confirmed
with the underlying class's confirm primitive before validate-finding.sh promotes it.

Modes
-----
  encode    Offline. Given --payload (+ optional --waf/--context), print ranked variants.
            Fully deterministic; used by the selftest.
  probe     Given --url and --param, send a marker and report the reflection context
            (needs network).
  run       Given --url, --param, --payload: fingerprint + probe + ranked variants
            (needs network). This is the operator/agent entry point.

All output is JSON on stdout.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Dict, List, Optional
from urllib import request as _request, parse as _parse
from urllib.error import HTTPError, URLError

# allow running as a script (python3 specter/scripts/waf/arsenal.py) or as a module
try:
    from . import catalog, context, fingerprint
except ImportError:  # pragma: no cover - script invocation
    import catalog, context, fingerprint  # type: ignore


def _inject(url: str, param: str, value: str) -> str:
    parts = _parse.urlsplit(url)
    q = dict(_parse.parse_qsl(parts.query, keep_blank_values=True))
    q[param] = value
    return _parse.urlunsplit(parts._replace(query=_parse.urlencode(q)))


def _fetch(url: str, timeout: float, ua: str) -> Optional[str]:
    # probe/run are target traffic: ride the program's egress proxy (fail closed via EgressError,
    # caught in main) rather than going direct. The opener builder lives in fingerprint.
    req = _request.Request(url, headers={"User-Agent": ua, "Accept": "*/*"})
    try:
        with fingerprint._egress_opener().open(req, timeout=timeout) as resp:
            return resp.read(200000).decode("utf-8", "replace")
    except HTTPError as e:
        try:
            return e.read(200000).decode("utf-8", "replace")
        except Exception:
            return ""
    except (URLError, OSError, ValueError):
        return None


_UA = "Mozilla/5.0 (compatible; grimnir-waf/1.0)"


def cmd_encode(a: argparse.Namespace) -> Dict:
    ctxs = a.context.split(",") if a.context else None
    variants = catalog.encode_payload(
        a.payload, waf=a.waf, contexts=ctxs,
        max_variants=a.max_variants, max_tier=a.max_tier)
    return {
        "mode": "encode",
        "payload": a.payload,
        "waf": a.waf or "unknown",
        "contexts": ctxs or ["*"],
        "variant_count": len(variants),
        "variants": [v.to_dict() for v in variants],
        "note": "candidates only -- confirm the payload fires at the origin before reporting",
    }


def probe_context(url: str, param: str, timeout: float, ua: str) -> Dict:
    probe = context.new_probe()
    body = _fetch(_inject(url, param, probe), timeout, ua)
    if body is None:
        return {"error": "fetch failed", "reflected": False, "contexts": ["none"], "breakouts": []}
    res = context.analyze_reflection(body, probe)
    res["probe"] = probe
    return res


def cmd_probe(a: argparse.Namespace) -> Dict:
    res = probe_context(a.url, a.param, a.timeout, _UA)
    res["mode"] = "probe"
    res["url"] = a.url
    res["param"] = a.param
    return res


def cmd_run(a: argparse.Namespace) -> Dict:
    fp = fingerprint.detect(a.url, timeout=a.timeout, active=not a.no_active_probe)
    waf = fp.get("waf") if fp.get("waf") != "none" else None
    ctx = probe_context(a.url, a.param, a.timeout, _UA)
    contexts = ctx.get("contexts") if ctx.get("reflected") else None
    variants = catalog.encode_payload(
        a.payload, waf=waf, contexts=contexts,
        max_variants=a.max_variants, max_tier=a.max_tier)
    return {
        "mode": "run",
        "url": a.url,
        "param": a.param,
        "payload": a.payload,
        "waf": fp,
        "reflection": ctx,
        "variant_count": len(variants),
        "variants": [v.to_dict() for v in variants],
        "note": "candidates only -- a 200 through the WAF is not a finding; confirm the "
                "underlying payload fires at the origin, then validate-finding.sh.",
    }


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="waf-arsenal", description="Targeted WAF-evasion payload engineering")
    sub = p.add_subparsers(dest="cmd", required=True)

    pe = sub.add_parser("encode", help="offline: rank encoded variants of a payload")
    pe.add_argument("--payload", required=True)
    pe.add_argument("--waf", help=f"one of: {', '.join(fingerprint.WAF_IDS)}")
    pe.add_argument("--context", help="comma-separated reflection contexts (see context.py)")
    pe.add_argument("--max-variants", type=int, default=12)
    pe.add_argument("--max-tier", type=int, default=5)
    pe.set_defaults(func=cmd_encode)

    pp = sub.add_parser("probe", help="network: report reflection context for a param")
    pp.add_argument("--url", required=True)
    pp.add_argument("--param", required=True)
    pp.add_argument("--timeout", type=float, default=12.0)
    pp.set_defaults(func=cmd_probe)

    pr = sub.add_parser("run", help="network: fingerprint + probe + ranked variants")
    pr.add_argument("--url", required=True)
    pr.add_argument("--param", required=True)
    pr.add_argument("--payload", required=True)
    pr.add_argument("--timeout", type=float, default=12.0)
    pr.add_argument("--no-active-probe", action="store_true",
                    help="skip the single benign fingerprint probe")
    pr.add_argument("--max-variants", type=int, default=12)
    pr.add_argument("--max-tier", type=int, default=5)
    pr.set_defaults(func=cmd_run)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        out = args.func(args)
    except fingerprint._egress_mod().EgressError as e:
        # a configured-but-unusable egress proxy: refuse cleanly rather than crash or go direct.
        # (offline `encode` never raises here, so this except is only evaluated on a real failure.)
        print(f"waf-arsenal: refusing to run — {e}", file=sys.stderr)
        return 2
    json.dump(out, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
