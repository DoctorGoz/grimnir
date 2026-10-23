#!/usr/bin/env python3
"""
ssti-confirm.py — the template-evaluation oracle (Grimnir confirmation harness).

Server-side template injection is proven in-band: put template syntax with arithmetic in a reflected
parameter and read the computed result back from the response. Every probe is a GET that sets one
query parameter, the same request a browser following a link would send, so it changes nothing.

  ssti-confirm.py --finding-id SPE-007 --project-dir ~/workspace/prog \
     --method GET --url 'https://host/search?q=a' --param q [-H 'Name: value']...

Each expression is bracketed by its own unique tags and uses fresh random operands, so the result
can only be read as `<open><product><close>`. The sequence:

  1. control      the parameter set to an inert canary. It must come back (positive control): a
                  parameter that isn't reflected can't show an in-band result. Template error text
                  already in this response is site-wide and never counts.
  2. detect       one request carrying every syntax family, each with its own tags and operands.
                  A family whose tags don't come back (the combined value broke the page, or a filter
                  stripped it) is retried alone.
  3. repeat       an evaluated family is fired again with new operands; the result must track them.
  4. bare         the same operands with no template syntax. If they evaluate too, the parameter
                  feeds an expression evaluator (a calculator or formula feature, or code eval), not
                  a template: a human decides.
  5. fingerprint  best-effort: number-times-string separates engines that repeat strings (Python and
                  Ruby families) from engines that coerce to a number (PHP, JS, and Java families).

Verdicts (evidence/<id>/verdict.json, the file validate-finding.sh's evidence gate reads for ssti):
  confirmed     evaluated, the repeat tracked the new operands, and the bare control did not evaluate
  ssti-likely   evaluated but unstable or also evaluated bare, or a template-engine error appeared
                that the control response lacks: a candidate for a human
  negative      reflected, and every syntax family came back unevaluated with no engine error
  inconclusive  transport failure, the parameter isn't reflected, or a syntax family could not be
                tested (blocked or stripped): nothing is ruled out

Escalating a confirmed evaluation toward code execution is a human step. Response bodies are not
written to evidence: only statuses, lengths, and a short excerpt around the evaluated result.
"""
import argparse
import json
import os
import re
import secrets
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _pace  # noqa: E402  RoE pacing around every live request (sibling module; puts scripts/ on the path)
import params as _params  # noqa: E402  the probe's fetch: no redirects, capped body, browser UA
import egress as _egress  # noqa: E402  the program's egress proxy (params.fetch honors it)

# (family, wrapper with EXPR as the expression, engines it reaches). Order is output order.
SYNTAXES = (
    ("double-curly", "{{EXPR}}", "Jinja2, Twig, Nunjucks, Tornado, Pebble, Django (error only)"),
    ("dollar-curly", "${EXPR}", "FreeMarker, Mako, Java EL / Spring EL, Groovy, JS template literal"),
    ("hash-curly", "#{EXPR}", "Ruby interpolation, Thymeleaf, Pug, JSF EL"),
    ("erb", "<%= EXPR %>", "ERB, EJS, JSP"),
    ("single-curly", "{EXPR}", "Smarty, Latte"),
    ("razor", "@(EXPR)", "Razor (.NET)"),
    ("thymeleaf-inline", "[[${EXPR}]]", "Thymeleaf inlining"),
    ("velocity", "#set($zq=EXPR)${zq}", "Velocity"),
)
_SYNTAX = {name: (wrap, engines) for name, wrap, engines in SYNTAXES}

# Engine error text. Matched only as a differential (injected response minus control response), so
# a page that always carries one of these strings never counts.
_ERRORS = (
    ("jinja2", r"jinja2\.exceptions|TemplateSyntaxError|UndefinedError: '"),
    ("django", r"django\.template\.(?:exceptions|base)"),
    ("twig", r"Twig[_\\](?:Error|Sandbox)"),
    ("freemarker", r"freemarker\.(?:core|template)\.|FreeMarker template error"),
    ("velocity", r"org\.apache\.velocity"),
    ("thymeleaf", r"org\.thymeleaf\.exceptions"),
    ("spring-el", r"SpelEvaluationException|org\.springframework\.expression"),
    ("smarty", r"Smarty(?:Compiler)?Exception|Syntax error in template"),
    ("mako", r"mako\.exceptions"),
    ("tornado", r"tornado\.template"),
    ("erb", r"\(erb\):\d+"),
    ("nunjucks", r"Template render error"),
    ("handlebars", r"Parse error on line \d+:[\s\S]{0,200}Expecting"),
    ("liquid", r"Liquid syntax error"),
    ("razor", r"RazorEngine|Razor\.TemplateCompilationException"),
)
ERROR_PATTERNS = [(n, re.compile(r)) for n, r in _ERRORS]
FINGERPRINT_FAMILIES = ("double-curly", "dollar-curly", "hash-curly", "erb")


def _hay(resp: dict) -> str:
    return (resp.get("body") or "") + "\n" + "\n".join(str(v) for v in (resp.get("headers") or {}).values())


def engine_errors(text: str) -> list[str]:
    return [name for name, rx in ERROR_PATTERNS if rx.search(text or "")]


def _operands() -> tuple[int, int]:
    return 101 + secrets.randbelow(899), 101 + secrets.randbelow(899)


def new_probe(family: str) -> dict:
    """One tagged expression: {family, open, close, a, b, value, expect}."""
    a, b = _operands()
    tag = _params.new_canary()
    p = {"family": family, "open": tag + "o", "close": tag + "c", "a": a, "b": b, "expect": str(a * b)}
    p["value"] = p["open"] + _SYNTAX[family][0].replace("EXPR", f"{a}*{b}") + p["close"]
    return p


def bare_probe() -> dict:
    a, b = _operands()
    tag = _params.new_canary()
    p = {"family": "bare", "open": tag + "o", "close": tag + "c", "a": a, "b": b, "expect": str(a * b)}
    p["value"] = f"{p['open']}{a}*{b}{p['close']}"
    return p


def read(p: dict, resp: dict) -> str:
    """evaluated | raw (tags back, expression not computed) | unresolved (tags never came back)."""
    hay = _hay(resp)
    if p["open"] + p["expect"] + p["close"] in hay:
        return "evaluated"
    return "raw" if p["open"] in hay else "unresolved"


def excerpt(p: dict, resp: dict, width: int = 60) -> str:
    """The evaluated result with a little of its surroundings, cut from the body or the one header
    that carries it, so the evidence shows where it landed without holding the response."""
    hit = p["open"] + p["expect"] + p["close"]
    for name, text in [("body", resp.get("body") or "")] + \
            [(f"header:{k.lower()}", str(v)) for k, v in (resp.get("headers") or {}).items()]:
        i = text.find(hit)
        if i >= 0:
            snippet = text[max(0, i - width): i + len(hit) + width]
            return snippet if name == "body" else f"{name}: {snippet}"
    return ""


def _fingerprint(get, url: str, param: str, family: str) -> dict:
    """n*'mm' renders as 'mm' repeated n times (Python, Ruby families) or as the product (PHP, JS,
    Java families). Anything else, or an error, is unknown: a hint for the human, never a verdict."""
    n, m = 3 + secrets.randbelow(4), 10 + secrets.randbelow(89)
    tag = _params.new_canary()
    o, c = tag + "o", tag + "c"
    expr = f"{n}*'{m}'"
    resp = get(_params.with_param(url, param, o + _SYNTAX[family][0].replace("EXPR", expr) + c))
    hay = _hay(resp)
    if f"{o}{str(m) * n}{c}" in hay:
        hint = "string repetition: Python or Ruby family (Jinja2, Mako, Tornado, ERB)"
    elif f"{o}{n * m}{c}" in hay:
        hint = "numeric coercion: PHP, JS, or Java family (Twig, Nunjucks, FreeMarker, EL)"
    else:
        hint = "unknown"
    return {"family": family, "expression": expr, "status": resp.get("status", 0), "hint": hint}


def probe_ssti(get, url: str, param: str) -> dict:
    """The whole oracle against one parameter. `get(url) -> {status, body, headers}` sends one paced
    GET. Returns the evidence record minus the run metadata."""
    out: dict = {"requests": 0, "families": [], "errors": [], "confirmation": None, "fingerprint": None}

    def send(u):
        out["requests"] += 1
        return get(u)

    canary = _params.new_canary()
    ctl = send(_params.with_param(url, param, canary))
    out["control"] = {"status": ctl.get("status", 0), "length": len(ctl.get("body") or "")}
    if not ctl.get("status"):
        return {**out, "verdict": "inconclusive", "why": "control request failed (transport error)"}
    if canary not in _hay(ctl):
        return {**out, "verdict": "inconclusive",
                "why": "parameter not reflected, so an in-band result can't be read "
                       "(blind SSTI needs an out-of-band or timing probe)"}
    site_errors = set(engine_errors(_hay(ctl)))

    def note_errors(resp, families):
        for e in engine_errors(_hay(resp)):
            if e not in site_errors and e not in [x["engine"] for x in out["errors"]]:
                out["errors"].append({"engine": e, "families": families, "status": resp.get("status", 0)})

    probes = [new_probe(f) for f, _, _ in SYNTAXES]
    combined = send(_params.with_param(url, param, "".join(p["value"] for p in probes)))
    if not combined.get("status"):
        return {**out, "verdict": "inconclusive", "why": "detection request failed (transport error)"}
    note_errors(combined, [p["family"] for p in probes])
    results = {p["family"]: (read(p, combined), "combined", combined.get("status", 0)) for p in probes}
    for f in [f for f, (r, _, _) in results.items() if r == "unresolved"]:
        p = new_probe(f)
        resp = send(_params.with_param(url, param, p["value"]))
        note_errors(resp, [f])
        results[f] = (read(p, resp), "single", resp.get("status", 0))
    out["families"] = [{"family": f, "engines": _SYNTAX[f][1], "result": r, "request": how, "status": st}
                       for f, (r, how, st) in results.items()]

    hits = [f for f, (r, _, _) in results.items() if r == "evaluated"]
    if hits:
        fam = hits[0]
        rep = new_probe(fam)
        rep_resp = send(_params.with_param(url, param, rep["value"]))
        bare = bare_probe()
        bare_resp = send(_params.with_param(url, param, bare["value"]))
        tracked = read(rep, rep_resp) == "evaluated"
        bare_eval = read(bare, bare_resp) == "evaluated"
        out["confirmation"] = {
            "family": fam, "engines": _SYNTAX[fam][1],
            "repeat": {"expression": f"{rep['a']}*{rep['b']}", "expected": rep["expect"],
                       "evaluated": tracked, "status": rep_resp.get("status", 0),
                       "poc_url": _params.with_param(url, param, rep["value"]), "excerpt": excerpt(rep, rep_resp)},
            "bare_control": {"expression": f"{bare['a']}*{bare['b']}", "evaluated": bare_eval,
                             "status": bare_resp.get("status", 0)},
        }
        if bare_eval:
            return {**out, "verdict": "ssti-likely",
                    "why": f"{fam} evaluated, but the bare expression evaluated too: an expression "
                           f"evaluator (calculator, formula, or code eval), not template syntax"}
        if not tracked:
            return {**out, "verdict": "ssti-likely",
                    "why": f"{fam} evaluated once but the repeat with new operands did not: unstable, re-check by hand"}
        if fam in FINGERPRINT_FAMILIES:
            out["fingerprint"] = _fingerprint(send, url, param, fam)
        return {**out, "verdict": "confirmed",
                "why": f"{fam} syntax evaluated arithmetic twice with fresh operands "
                       f"({_SYNTAX[fam][1]}); the same operands without template syntax did not"}

    if out["errors"]:
        names = ", ".join(e["engine"] for e in out["errors"])
        return {**out, "verdict": "ssti-likely",
                "why": f"template-engine error ({names}) in an injected response, absent from the control"}
    untested = [f for f, (r, _, _) in results.items() if r == "unresolved"]
    if untested:
        return {**out, "verdict": "inconclusive",
                "why": f"{len(untested)} of {len(results)} syntax families could not be tested "
                       f"(blocked or stripped): {', '.join(untested)}"}
    return {**out, "verdict": "negative",
            "why": "reflected; every syntax family came back unevaluated with no engine error"}


def main() -> int:
    ap = argparse.ArgumentParser(prog="ssti-confirm.py")
    ap.add_argument("--finding-id", required=True)
    ap.add_argument("--project-dir", required=True)
    ap.add_argument("--method", default="GET")
    ap.add_argument("--url", required=True, help="a concrete URL that carries (or accepts) the parameter")
    ap.add_argument("--param", required=True, help="the query parameter to inject")
    ap.add_argument("-H", "--header", action="append", default=[], dest="headers")
    ap.add_argument("--timeout", type=float, default=20.0)
    a = ap.parse_args()
    if a.method.upper() != "GET":
        print("ssti-confirm.py probes GET query parameters only (read-only)", file=sys.stderr)
        return 2
    _pace.init(a.project_dir)
    _egress.init(a.project_dir)   # roe.json's proxy applies to a CLI run, not just a lane's env

    def get(u):
        _pace.before(u)
        r = _params.fetch(u, a.headers, a.timeout)
        if r.get("status"):
            _pace.after(u, r["status"])
        return r

    res = probe_ssti(get, a.url, a.param)
    rec = {"schema": 1, "finding_id": a.finding_id, "vuln_class": "ssti",
           "ts": datetime.now(timezone.utc).isoformat(), "url": a.url, "param": a.param, **res,
           "negative_control": ("tagged arithmetic with fresh operands, a repeat that must track them, "
                                f"and a bare-expression control: {res['why']}")}
    d = os.path.join(a.project_dir, "evidence", a.finding_id)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "verdict.json"), "w") as fh:
        json.dump(rec, fh, indent=2)
    print(json.dumps({k: rec[k] for k in ("finding_id", "verdict", "why")}, indent=2))
    print(f"wrote {d}/verdict.json ({res['requests']} requests)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
