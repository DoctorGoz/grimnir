"""sqli-confirm.py is the in-band SQL injection oracle. The fake backend is real SQLite, so the
payloads meet real SQL semantics: a string literal, a numeric predicate, a LIKE pattern, and a
parameterized query that must come back negative. The failures that would be silent: a reflected
payload read as a changed response, a site-wide error page read as a database error, a page that
changes on its own read as a boolean differential, and a WAF that blocks every probe reported as a
clean negative. No network.
"""
import html
import json
import secrets
import sqlite3
from urllib.parse import parse_qs, urlsplit

import pytest

DB = sqlite3.connect(":memory:", check_same_thread=False)
DB.executescript("""
CREATE TABLE items (id INTEGER, name TEXT, cat TEXT);
INSERT INTO items VALUES (1, 'red shoes', 'shoes'), (2, 'blue shoes', 'shoes'), (3, 'green hat', 'hats');
""")


def _q(url, name):
    return parse_qs(urlsplit(url).query, keep_blank_values=True).get(name, [""])[0]


def _page(rows, echo=""):
    lines = "\n".join(f"<li>{html.escape(r[0])}</li>" for r in rows)
    return f"<html>\n<h1>Results</h1>\n<p>for {html.escape(echo)}</p>\n<ul>\n{lines}\n</ul>\n</html>"


def app(sql_of, verbose=True, param="q", parameterized=False):
    def get(url):
        v = _q(url, param)
        try:
            if parameterized:
                rows = DB.execute("SELECT name FROM items WHERE cat = ?", (v,)).fetchall()
            else:
                rows = DB.execute(sql_of(v)).fetchall()
        except sqlite3.Error as e:
            body = f"sqlite3.OperationalError: {e}" if verbose else "<html>Something went wrong</html>"
            return {"status": 500, "body": body, "headers": {}}
        return {"status": 200, "body": _page(rows, v), "headers": {}}
    return get


string_literal = lambda v: f"SELECT name FROM items WHERE cat = '{v}'"
numeric = lambda v: f"SELECT name FROM items WHERE id = {v}"
like = lambda v: f"SELECT name FROM items WHERE name LIKE '%{v}%'"


def _run(mod, get, url="https://app.example.com/list?q=shoes&page=1", param="q"):
    sent = []

    def g(u):
        sent.append(u)
        return get(u)
    return mod.probe_sqli(g, url, param), sent


def test_quote_balance_pair_confirms_a_string_literal(sqli_confirm_mod):
    res, sent = _run(sqli_confirm_mod, app(string_literal))
    assert res["verdict"] == "confirmed" and res["dbms"] == "sqlite"
    assert res["error_probe"][0]["healed"] and len(sent) == 4
    assert all("page=1" in u for u in sent)


def test_numeric_predicate_confirms_by_boolean(sqli_confirm_mod):
    res, _ = _run(sqli_confirm_mod, app(numeric, param="id"), "https://app.example.com/item?id=1", "id")
    assert res["verdict"] == "confirmed" and res["boolean"][0]["context"] == "numeric"
    assert res["error_probe"][0]["healed"] is False   # 1'' still errors: not a literal


def test_blind_string_confirms_by_boolean(sqli_confirm_mod):
    res, _ = _run(sqli_confirm_mod, app(string_literal, verbose=False))
    assert res["verdict"] == "confirmed" and res["error_probe"][0]["errors"] == []
    b = res["boolean"][-1]
    assert b["context"] == "string" and b["junk"] == "differs" and b["repeat"]["true"] == "same"


def test_like_pattern_confirms_with_the_wildcard_variant(sqli_confirm_mod):
    res, _ = _run(sqli_confirm_mod, app(like, verbose=False), "https://app.example.com/s?q=shoe")
    assert res["verdict"] == "confirmed" and res["boolean"][-1]["context"] == "string-like"


@pytest.mark.parametrize("url", ["https://app.example.com/list?q=shoes", "https://app.example.com/list?q=7"])
def test_parameterized_query_is_negative(sqli_confirm_mod, url):
    # reflected and echoed: the stripped payload must not read as a changed response
    res, _ = _run(sqli_confirm_mod, app(None, parameterized=True), url)
    assert res["verdict"] == "negative"


def test_site_wide_error_text_does_not_count(sqli_confirm_mod):
    base = app(None, parameterized=True)

    def footer(url):
        r = base(url)
        r["body"] += "\n<!-- You have an error in your SQL syntax (old banner) -->"
        return r
    res, _ = _run(sqli_confirm_mod, footer)
    assert res["verdict"] == "negative" and all(not e["errors"] for e in res["error_probe"])


def test_suffix_ignoring_app_is_not_confirmed(sqli_confirm_mod):
    """Not SQL: it drops any 'x'='y' with unequal sides and ignores everything else, so TRUE and the
    misspelled TRUE both look like the baseline. The misspelled control is what stops a confirm."""
    import re
    base = app(None, parameterized=True)

    def quirky(url):
        v = _q(url, "q")
        m = re.search(r"'?(\w+)'?=\'?(\w+)", v)
        if m and m.group(1) != m.group(2):
            return {"status": 200, "body": _page([], v), "headers": {}}
        return base(f"https://x/?q={v.split(chr(39))[0].split(' ')[0]}")
    res, _ = _run(sqli_confirm_mod, quirky)
    assert res["verdict"] == "sqli-likely" and "misspelled" in res["why"]


def test_dynamic_page_without_errors_is_inconclusive(sqli_confirm_mod):
    def dynamic(url):
        return {"status": 200, "headers": {},
                "body": "\n".join(secrets.token_hex(8) for _ in range(30))}
    res, _ = _run(sqli_confirm_mod, dynamic)
    assert res["verdict"] == "inconclusive" and "on its own" in res["why"]


def test_blocked_probes_are_inconclusive(sqli_confirm_mod):
    base = app(None, parameterized=True)

    def waf(url):
        if any(c in _q(url, "q") for c in "'\" ="):
            return {"status": 403, "body": "Forbidden", "headers": {}}
        return base(url)
    res, _ = _run(sqli_confirm_mod, waf)
    assert res["verdict"] == "inconclusive" and "blocked" in res["why"]


def test_transport_failure_is_inconclusive(sqli_confirm_mod):
    res, _ = _run(sqli_confirm_mod, lambda u: {"status": 0, "body": "", "headers": {}})
    assert res["verdict"] == "inconclusive"


def test_cli_writes_the_verdict_the_gate_reads(sqli_confirm_mod, tmp_path, monkeypatch):
    monkeypatch.setattr(sqli_confirm_mod._params, "fetch", lambda u, h, t: app(string_literal)(u))
    monkeypatch.setattr("sys.argv", ["sqli-confirm.py", "--finding-id", "SPE-001", "--project-dir",
                                     str(tmp_path), "--url", "https://app.example.com/l?q=shoes", "--param", "q"])
    assert sqli_confirm_mod.main() == 0
    rec = json.loads((tmp_path / "evidence" / "SPE-001" / "verdict.json").read_text())
    assert rec["verdict"] == "confirmed" and rec["vuln_class"] == "sqli"
