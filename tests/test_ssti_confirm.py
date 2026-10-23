"""ssti-confirm.py is the in-band template-evaluation oracle. The failures that would be silent: a
calculator or formula feature read as SSTI (the bare-expression control exists to kill it), a
site-wide error page read as an engine error, a filter that strips every payload reported as a clean
negative, and a parameter that isn't reflected reported as negative instead of untestable. Each fake
server below is one of those targets; no network.
"""
import html
import json
import re
from urllib.parse import parse_qs, urlsplit

import pytest


def _q(url):
    return parse_qs(urlsplit(url).query, keep_blank_values=True).get("q", [""])[0]


def _resp(body, status=200, headers=None):
    return {"status": status, "body": body, "headers": headers or {}}


def jinja_like(url):
    """Evaluates {{a*b}} and {{n*'m'}} (string repetition); everything else is literal text."""
    v = _q(url)
    v = re.sub(r"\{\{(\d+)\*'(\d+)'\}\}", lambda m: m.group(2) * int(m.group(1)), v)
    v = re.sub(r"\{\{(\d+)\*(\d+)\}\}", lambda m: str(int(m.group(1)) * int(m.group(2))), v)
    return _resp(f"<p>Hello {html.escape(v)}</p>")


def escaped_echo(url):
    return _resp(f"<p>you searched {html.escape(_q(url))}</p>")


def calculator(url):
    """An intentional expression evaluator: any a*b computes, and template punctuation is left as is."""
    v = re.sub(r"(\d+)\*(\d+)", lambda m: str(int(m.group(1)) * int(m.group(2))), _q(url))
    return _resp(f"<p>result {html.escape(v)}</p>")


def stripping_calculator(url):
    """A formula feature that strips punctuation it doesn't know, then computes: the template
    syntax looks consumed, but the bare operands compute too."""
    return calculator(f"https://x/?q={re.sub(r'[{}$#<>%=@\[\]()]', '', _q(url))}")


def erroring(url):
    if "{{" in _q(url):
        return _resp("jinja2.exceptions.TemplateSyntaxError: unexpected '*'", status=500)
    return escaped_echo(url)


def smarty_like(url):
    """Breaks on {{ (so the combined request shows nothing), evaluates {a*b} alone."""
    v = _q(url)
    if "{{" in v:
        return _resp("<p>error</p>", status=500)
    v = re.sub(r"\{(\d+)\*(\d+)\}", lambda m: str(int(m.group(1)) * int(m.group(2))), v)
    return _resp(f"<p>{html.escape(v)}</p>")


def not_reflected(url):
    return _resp("<p>static page</p>")


def dead(url):
    return {"status": 0, "body": "", "headers": {}, "error": "connection refused"}


def blocked(url):
    """A WAF that rejects anything with template punctuation; plain values pass."""
    if re.search(r"[{}<>%@\[\]#$]", _q(url)):
        return _resp("Forbidden", status=403)
    return escaped_echo(url)


class Once:
    """Evaluates {{a*b}} on the first injected request only."""
    def __init__(self):
        self.n = 0

    def __call__(self, url):
        if "{{" in _q(url):
            self.n += 1
            if self.n == 1:
                return jinja_like(url)
        return escaped_echo(url)


def _run(mod, server):
    sent = []

    def get(u):
        sent.append(u)
        return server(u)
    return mod.probe_ssti(get, "https://app.example.com/search?q=a&page=1", "q"), sent


def test_evaluating_engine_is_confirmed(ssti_confirm_mod):
    res, sent = _run(ssti_confirm_mod, jinja_like)
    assert res["verdict"] == "confirmed"
    c = res["confirmation"]
    assert c["family"] == "double-curly" and c["repeat"]["evaluated"] and not c["bare_control"]["evaluated"]
    assert c["repeat"]["expected"] in c["repeat"]["excerpt"]
    assert "string repetition" in res["fingerprint"]["hint"]
    # control, combined, repeat, bare, fingerprint; other params on the URL are left alone
    assert res["requests"] == len(sent) == 5
    assert all("page=1" in u for u in sent)


def test_escaped_reflection_is_negative(ssti_confirm_mod):
    res, sent = _run(ssti_confirm_mod, escaped_echo)
    assert res["verdict"] == "negative" and len(sent) == 2
    assert {f["result"] for f in res["families"]} == {"raw"}


def test_calculator_that_leaves_the_delimiters_is_negative(ssti_confirm_mod):
    # {{a*b}} came back as {{product}}: the delimiters weren't consumed, so nothing evaluated them
    res, _ = _run(ssti_confirm_mod, calculator)
    assert res["verdict"] == "negative"


def test_formula_feature_is_not_confirmed(ssti_confirm_mod):
    res, _ = _run(ssti_confirm_mod, stripping_calculator)
    assert res["verdict"] == "ssti-likely" and "bare expression" in res["why"]
    assert res["confirmation"]["bare_control"]["evaluated"]


def test_engine_error_differential_is_a_candidate(ssti_confirm_mod):
    res, _ = _run(ssti_confirm_mod, erroring)
    assert res["verdict"] == "ssti-likely" and res["errors"][0]["engine"] == "jinja2"


def test_site_wide_error_text_does_not_count(ssti_confirm_mod):
    def always_mentions_jinja(url):
        r = escaped_echo(url)
        r["body"] += "<!-- jinja2.exceptions logged -->"
        return r
    res, _ = _run(ssti_confirm_mod, always_mentions_jinja)
    assert res["verdict"] == "negative" and res["errors"] == []


def test_family_broken_by_the_combined_value_is_retried_alone(ssti_confirm_mod):
    res, _ = _run(ssti_confirm_mod, smarty_like)
    assert res["verdict"] == "confirmed" and res["confirmation"]["family"] == "single-curly"
    singles = {f["family"] for f in res["families"] if f["request"] == "single"}
    assert len(singles) == len(ssti_confirm_mod.SYNTAXES)


def test_unstable_evaluation_is_a_candidate(ssti_confirm_mod):
    res, _ = _run(ssti_confirm_mod, Once())
    assert res["verdict"] == "ssti-likely" and "unstable" in res["why"]


@pytest.mark.parametrize("server,why", [(not_reflected, "not reflected"), (dead, "transport"),
                                        (blocked, "could not be tested")])
def test_untestable_is_inconclusive_not_negative(ssti_confirm_mod, server, why):
    res, _ = _run(ssti_confirm_mod, server)
    assert res["verdict"] == "inconclusive" and why in res["why"]


def test_with_param_appends_a_missing_parameter(ssti_confirm_mod):
    u = ssti_confirm_mod._params.with_param("https://x.example.com/p?a=1", "q", "{{1*1}}")
    assert parse_qs(urlsplit(u).query) == {"a": ["1"], "q": ["{{1*1}}"]}


def test_cli_writes_the_verdict_the_gate_reads(ssti_confirm_mod, tmp_path, monkeypatch):
    monkeypatch.setattr(ssti_confirm_mod._params, "fetch", lambda u, h, t: jinja_like(u))
    monkeypatch.setattr("sys.argv", ["ssti-confirm.py", "--finding-id", "SPE-001", "--project-dir",
                                     str(tmp_path), "--url", "https://app.example.com/s?q=a", "--param", "q"])
    assert ssti_confirm_mod.main() == 0
    rec = json.loads((tmp_path / "evidence" / "SPE-001" / "verdict.json").read_text())
    assert rec["verdict"] == "confirmed" and rec["vuln_class"] == "ssti" and rec["param"] == "q"


def test_cli_refuses_a_non_get_method(ssti_confirm_mod, tmp_path, monkeypatch):
    monkeypatch.setattr("sys.argv", ["ssti-confirm.py", "--finding-id", "X", "--project-dir", str(tmp_path),
                                     "--method", "POST", "--url", "https://x/", "--param", "q"])
    assert ssti_confirm_mod.main() == 2 and not (tmp_path / "evidence").exists()
