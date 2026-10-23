"""
Grimnir WAF arsenal — targeted payload engineering for Specter.

A WAF that blocks your payload is a reachability barrier to confirming a real bug,
not a reason to spray. This package makes payload evasion a scalpel:

    fingerprint the WAF  ->  analyse where input reflects  ->  encode for that
    context AND that WAF product, cheapest/highest-signal variants first.

Modules
-------
fingerprint   Detect the WAF product (Cloudflare, AWS WAF, Akamai, ModSecurity/CRS,
              Imperva, F5, Sucuri, FortiWeb, Barracuda, NAXSI ...) from headers,
              cookies, body and status, with a confidence score.
context       Reflection-context analyser: find WHERE a probe lands (HTML attr,
              JS string, tag body, SQL error ...) and the breakout prefix for it.
encodings     Tiered encoding catalogue (~24 techniques) tagged by WAF-effectiveness
              and applicable context; encode_payload() returns targeted variants.
arsenal       Orchestrator + CLI: fingerprint -> context probe -> ranked variants.

Design rules baked in (borrowed patterns, clean-room implementation):
- WET/DRY reuse first: the caller's own payload is variant rank 0, before we generate.
- Context gate: a technique only fires where it is meaningful (no SQL comments in an
  HTML-attribute context), so we never emit the spray that scales the wrong number.
- Deterministic: no learning table yet (deferred). Selection is fingerprint+context+
  priority, fully reproducible and offline-testable.

Stdlib only — no third-party deps.
"""

from .catalog import EncodingCatalog, EncodingTechnique, encode_payload
from .context import ReflectionContext, analyze_reflection, breakouts_for
from .fingerprint import passive_fingerprint, WAF_SIGNATURES, WAF_IDS

__all__ = [
    "EncodingCatalog",
    "EncodingTechnique",
    "encode_payload",
    "ReflectionContext",
    "analyze_reflection",
    "breakouts_for",
    "passive_fingerprint",
    "WAF_SIGNATURES",
    "WAF_IDS",
]
