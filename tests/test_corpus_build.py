"""corpus-build.py: merge every recon source into asset-map.json, scope-gated.

The failure this guards is silent: an engagement with real recon on disk ending up with
endpoints[] == 0, which makes lane-synth emit nothing and still exit 0. Each test builds a tiny
project dir with placeholder domains and asserts on the merged asset map.
"""
import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent


def _load():
    spec = importlib.util.spec_from_file_location("grimnir_corpus_build", REPO / "huginn/scripts/corpus-build.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["grimnir_corpus_build"] = mod
    spec.loader.exec_module(mod)
    return mod


cb = _load()

SCOPE_MD = """# Scope

## In scope
- `*.acme.example`

## Out of scope
- `legacy.acme.example`
"""


def project(tmp_path, scope=True, asset_map=None):
    (tmp_path / "recon").mkdir()
    if scope:
        (tmp_path / "scope.md").write_text(SCOPE_MD)
    if asset_map is not None:
        (tmp_path / "asset-map.json").write_text(json.dumps(asset_map))
    return tmp_path


def write(p: Path, rel: str, text: str):
    f = p / "recon" / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(text)


def httpx(*hosts):
    return "\n".join(json.dumps({"url": f"https://{h}", "host": h, "status_code": 200, "title": "t",
                                 "tech": ["nginx"], "cdn_name": "", "failed": False}) for h in hosts) + "\n"


def run(p, **kw):
    base = json.loads((p / "asset-map.json").read_text()) if (p / "asset-map.json").exists() else {}
    return cb.build(p, base, **kw)


def by_url(am):
    return {e["url"]: e for e in am["endpoints"]}


def test_multi_source_merge_with_provenance(tmp_path):
    p = project(tmp_path)
    write(p, "httpx-all.jsonl", httpx("api.acme.example"))
    write(p, "crawl-katana.txt", "https://api.acme.example/v1/users?page=2\n")
    write(p, "urls-gau.txt", "https://api.acme.example/v1/users?page=9\nhttps://api.acme.example/v1/old\n")
    write(p, "js-endpoints.txt", "  [source: https://api.acme.example/static/app.js]\n/internal/config\n")
    am, s = run(p)
    eps = by_url(am)
    users = next(e for e in am["endpoints"] if e["url"].split("?")[0].endswith("/v1/users"))
    assert users["sources"] == ["crawl", "archive"] and users["seen_live"] is True
    assert users["parameters"] == ["page"]
    assert eps["https://api.acme.example/v1/old"]["sources"] == ["archive"]
    assert eps["https://api.acme.example/v1/old"]["seen_live"] is False
    assert eps["https://api.acme.example/internal/config"]["sources"] == ["js"]
    # unknown auth must NOT be asserted False (lane-synth skips auth_required is False)
    assert all("auth_required" not in e for e in am["endpoints"])
    assert s["endpoints_before"] == 0 and s["endpoints_after"] == len(am["endpoints"]) == 3


def test_hosts_filled_from_httpx(tmp_path):
    p = project(tmp_path)
    write(p, "httpx-results.json", httpx("api.acme.example", "www.acme.example", "evil.other.example"))
    am, s = run(p)
    assert [h["host"] for h in am["hosts"]] == ["api.acme.example", "www.acme.example"]
    assert set(am["hosts"][0]) == {"url", "host", "status", "title", "tech", "cdn"}
    assert s["hosts_oos_dropped"] == 1


def test_archive_requires_live_host(tmp_path):
    p = project(tmp_path)
    write(p, "httpx-all.jsonl", httpx("api.acme.example"))
    write(p, "urls-wayback.txt", "https://api.acme.example/live\nhttps://dead.acme.example/gone\n")
    am, s = run(p)
    assert list(by_url(am)) == ["https://api.acme.example/live"]
    assert s["archive_not_live"] == 1


def test_static_assets_and_non_http_dropped(tmp_path):
    p = project(tmp_path)
    write(p, "crawl-katana.txt", "\n".join([
        "https://www.acme.example/logo.png", "https://www.acme.example/a.css", "https://www.acme.example/f.woff2",
        "https://www.acme.example/app.js", "https://www.acme.example/app.js.map", "https://www.acme.example/v.mp4",
        "ftp://www.acme.example/x", "mailto:a@acme.example", "https://www.acme.example/api/items#frag"]) + "\n")
    am, _ = run(p)
    assert list(by_url(am)) == ["https://www.acme.example/api/items"]


def test_template_dedupe_keeps_three_concrete_examples(tmp_path):
    p = project(tmp_path)
    urls = [f"https://api.acme.example/orders/{n}" for n in range(1000, 1010)]
    urls.append("https://api.acme.example/orders/3f2b8a10-1111-4222-8333-444455556666")
    write(p, "crawl-katana.txt", "\n".join(urls) + "\n")
    am, s = run(p)
    assert len(am["endpoints"]) == 3
    assert all("/orders/" in e["url"] for e in am["endpoints"])
    assert s["template_capped"] == 8
    assert cb.template_path("/a/123/b/deadbeefdeadbeef00/c/Ab3dEf6hIj9kLm2nOp5q") == "/a/{id}/b/{id}/c/{id}"
    assert cb.template_path("/blog/my-long-article-title-about-things-2024") == "/blog/my-long-article-title-about-things-2024"


def test_cap_prefers_seen_live(tmp_path):
    p = project(tmp_path)
    write(p, "httpx-all.jsonl", httpx("api.acme.example"))
    write(p, "crawl-katana.txt", "https://api.acme.example/live/one\nhttps://api.acme.example/live/two\n")
    write(p, "urls-gau.txt", "\n".join(f"https://api.acme.example/old/x{i}" for i in range(20)) + "\n")
    am, s = run(p, max_endpoints=4)
    urls = set(by_url(am))
    assert {"https://api.acme.example/live/one", "https://api.acme.example/live/two"} <= urls
    # archive-only is held to 0.4 x 4 = 1 slot, and the unused room is not backfilled
    assert len(urls) == 3 and s["capped"] == 0 and s["archive_capped"] == 19


def _ranking_project(tmp_path):
    p = project(tmp_path)
    write(p, "httpx-all.jsonl", httpx("api.acme.example"))
    write(p, "urls-gau.txt", "\n".join(f"https://api.acme.example/old{i}/x?q=1" for i in range(50)) + "\n")
    write(p, "crawl-katana.txt", "\n".join(f"https://api.acme.example/crawl{i}/x" for i in range(10)) + "\n")
    write(p, "js-endpoints.txt", "[source: https://api.acme.example/app.js]\n"
          + "\n".join(f"/js{i}/x" for i in range(5)) + "\n")
    return p


def test_archive_subcap_keeps_crawl_and_js(tmp_path):
    p = _ranking_project(tmp_path)
    am, s = run(p, max_endpoints=20, archive_share=0.4)
    urls = list(by_url(am))
    assert sum("/crawl" in u for u in urls) == 10 and sum("/js" in u for u in urls) == 5
    # 0.4 x 20 = 8 archive slots, but crawl + js already hold 15 of the 20, so the global cap trims 3
    assert sum("/old" in u for u in urls) == 5 and len(urls) == 20
    assert s["archive_capped"] == 42 and s["capped"] == 3


def test_provenance_outranks_query_shape(tmp_path):
    p = _ranking_project(tmp_path)
    am, _ = run(p, max_endpoints=15, archive_share=1.0)
    assert not any("/old" in u for u in by_url(am))      # query-bearing archive no longer wins


def test_existing_never_dropped_under_archive_cap(tmp_path):
    prior = {"hosts": [], "auth_mechanisms": [],
             "endpoints": [{"url": f"https://api.acme.example/keep{i}", "source": "authed-crawl"} for i in range(5)]}
    p = project(tmp_path, asset_map=prior)
    write(p, "httpx-all.jsonl", httpx("api.acme.example"))
    write(p, "urls-gau.txt", "\n".join(f"https://api.acme.example/old{i}" for i in range(10)) + "\n")
    am, s = run(p, max_endpoints=5)
    assert len(am["endpoints"]) == 5 and s["archive_capped"] == 10


def test_summary_line_reports_archive_capped(tmp_path, capsys):
    p = _ranking_project(tmp_path)
    assert cb.main(["--project-dir", str(p), "--dry-run", "--max-endpoints", "20"]) == 0
    assert "archive_capped 42" in capsys.readouterr().out


def test_existing_entries_preserved_and_idempotent(tmp_path):
    prior = {"target": "t", "custom_key": {"x": 1}, "hosts": [], "auth_mechanisms": [],
             "endpoints": [{"url": "https://legacy.acme.example/keep", "method": "POST", "source": "authed-crawl",
                            "auth_required": True, "tags": ["x"], "status_code": 200},
                           {"url": "https://api.acme.example/v1/users?page=1", "source": "katana"}]}
    p = project(tmp_path, asset_map=prior)
    write(p, "crawl-katana.txt", "https://api.acme.example/v1/users?page=5\nhttps://api.acme.example/v1/new\n")
    am, s = run(p)
    assert am["custom_key"] == {"x": 1}
    first = am["endpoints"][0]
    assert first["url"] == "https://legacy.acme.example/keep" and first["auth_required"] is True
    assert first["source"] == "authed-crawl" and first["sources"] == ["authed-crawl"] and first["seen_live"] is True
    legacy = am["endpoints"][1]
    assert legacy["source"] == "katana" and legacy["sources"] == ["crawl"]
    assert legacy["url"].endswith("page=1")           # existing url wins over the re-seen one
    assert s["preexisting_oos"] == 1                   # counted, never deleted
    assert len(am["endpoints"]) == 3
    # a second pass over its own output changes nothing
    (p / "asset-map.json").write_text(json.dumps(am))
    am2, _ = run(p)
    assert am2["endpoints"] == am["endpoints"]


def test_scope_drops_oos_host_but_not_without_scope(tmp_path):
    p = project(tmp_path)
    write(p, "crawl-katana.txt", "https://api.acme.example/a\nhttps://legacy.acme.example/b\nhttps://other.example/c\n")
    am, s = run(p)
    assert list(by_url(am)) == ["https://api.acme.example/a"]
    assert s["scope"] == "enforced" and s["oos_dropped"] == 2
    assert s["oos_sample_hosts"] == ["legacy.acme.example", "other.example"]

    q = tmp_path / "noscope"
    q.mkdir()
    q = project(q, scope=False)
    write(q, "crawl-katana.txt", "https://api.acme.example/a\nhttps://legacy.acme.example/b\n")
    am2, s2 = run(q)
    assert len(am2["endpoints"]) == 2 and s2["scope"] == "unavailable" and s2["oos_dropped"] == 0


OPENAPI = {
    "openapi": "3.0.0", "info": {"title": "Acme"},
    "servers": [{"url": "https://api.acme.example/api"}],
    "components": {"securitySchemes": {"k": {"type": "apiKey", "in": "header", "name": "X-Key"}}},
    "security": [{"k": []}],
    "paths": {
        "/wallets/{wallet_id}": {"get": {"tags": ["w"]}},
        "/wallets": {"post": {"requestBody": {"content": {"application/json": {"schema": {
            "type": "object", "properties": {"name": {}, "chain": {}}}}}}}},
    },
}


def test_spec_ingest_via_openapi_to_assetmap(tmp_path):
    p = project(tmp_path)
    write(p, "docs/api-openapi-prod.json", json.dumps(OPENAPI))
    write(p, "random.json", json.dumps({"not": "a spec"}))
    am, s = run(p)
    eps = {(e["method"], e["url"]): e for e in am["endpoints"]}
    g = eps[("GET", "https://api.acme.example/api/wallets/{wallet_id}")]
    assert g["sources"] == ["spec"] and g["source"] == "openapi" and g["auth_required"] is True
    assert eps[("POST", "https://api.acme.example/api/wallets")]["body_fields"] == ["chain", "name"]
    assert s["specs"] == [{"file": "docs/api-openapi-prod.json", "operations": 2}]
    assert [a["type"] for a in am["auth_mechanisms"]] == ["api_key_header"]


def test_auth_mechanisms_from_paths_and_not_guessed(tmp_path):
    p = project(tmp_path)
    write(p, "crawl-katana.txt", "https://id.acme.example/.well-known/openid-configuration\n"
                                 "https://id.acme.example/oauth/authorize?client_id=x\nhttps://id.acme.example/home\n")
    am, _ = run(p)
    assert sorted(a["type"] for a in am["auth_mechanisms"]) == ["oauth2", "oidc"]
    q = tmp_path / "plain"
    q.mkdir()
    q = project(q)
    write(q, "crawl-katana.txt", "https://id.acme.example/home\n")
    assert run(q)[0]["auth_mechanisms"] == []


def test_cli_dry_run_writes_nothing_and_out_is_atomic(tmp_path, capsys):
    p = project(tmp_path)
    write(p, "crawl-katana.txt", "https://api.acme.example/a\n")
    assert cb.main(["--project-dir", str(p), "--dry-run", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["endpoints_after"] == 1
    assert not (p / "asset-map.json").exists()
    out = tmp_path / "out" / "am.json"
    assert cb.main(["--project-dir", str(p), "--out", str(out)]) == 0
    assert json.loads(out.read_text())["endpoints"][0]["url"] == "https://api.acme.example/a"
    assert not list(out.parent.glob("*.tmp"))
    assert not (p / "asset-map.json").exists()
