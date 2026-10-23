"""caido-export.py: proxied traffic as a corpus source.

What must hold: only in-scope requests are written, no header value, body value, or secret-named
query value leaves Caido, and corpus-build turns the records into endpoints that keep their body
field names and the authed-traffic tag.
"""
import importlib.util
import json
import sys
import time
from pathlib import Path

from test_session import FakeCaido, jwt

REPO = Path(__file__).resolve().parent.parent


def test_export_and_merge(caido_export_mod, tmp_path):
    pd = tmp_path / "eng"
    (pd / "recon").mkdir(parents=True)
    (pd / "scope.md").write_text("## In scope\n- `*.acme.example`\n\n## Out of scope\n- `legacy.acme.example`\n")
    caido = FakeCaido(str(tmp_path / "caido"))
    tok = jwt(sub="s", exp=9e9)
    caido.add("GET", "api.acme.example", "/v1/orders?id=7&access_token=SECRETVALUE1", [("Authorization", f"Bearer {tok}")],
              "", 200, {"ok": 1}, t=time.time() - 60)
    caido.add("POST", "api.acme.example", "/v1/profile", [("Content-Type", "application/json"),
              ("Cookie", "session_id=SECRETVALUE2")], json.dumps({"bio": "PRIVATEBIO", "nested": {"x": 1}}),
              200, {"ok": 1}, t=time.time() - 50)
    caido.add("GET", "legacy.acme.example", "/old", [], "", 200, "x", t=time.time() - 40)
    caido.add("GET", "api.acme.example", "/missing", [], "", 404, "nf", t=time.time() - 30)
    caido.add("GET", "cdn.acme.example", "/app.js", [], "", 200, "js", t=time.time() - 20)
    assert caido_export_mod.main(["--project-dir", str(pd), "--caido-dir", caido.root]) == 0
    text = (pd / "recon" / "caido-traffic.jsonl").read_text()
    assert "SECRETVALUE" not in text and "PRIVATEBIO" not in text and tok not in text
    recs = {r["url"]: r for r in map(json.loads, text.splitlines())}
    assert set(recs) == {"https://api.acme.example/v1/orders?id=7&access_token=",
                         "https://api.acme.example/v1/profile"}
    assert recs["https://api.acme.example/v1/profile"]["body_fields"] == ["bio", "nested.x"]
    assert all("authed-traffic" in r["tags"] for r in recs.values())

    spec = importlib.util.spec_from_file_location("cb_for_export", REPO / "huginn/scripts/corpus-build.py")
    cb = importlib.util.module_from_spec(spec)
    sys.modules["cb_for_export"] = cb
    spec.loader.exec_module(cb)
    am, _summary = cb.build(pd, {"endpoints": []})
    prof = next(e for e in am["endpoints"] if e["url"].endswith("/v1/profile"))
    assert prof["method"] == "POST" and "bio" in prof["body_fields"] and "authed-traffic" in prof["tags"]
