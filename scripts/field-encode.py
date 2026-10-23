#!/usr/bin/env python3
"""
Make an arbitrary evidence field safe to store in a finding's JSON.

A captured request/response or a WAF-evasion payload can carry raw control bytes or
invalid UTF-8 (overlong encodings, null-adjacent bytes, binary bodies). Passed straight
into jq those either error out or store un-round-trippable text, so the finding fails to
write or writes corrupt evidence. This normalises a field:

  - clean text (valid UTF-8, no C0 controls except tab/newline/CR)  -> stored as-is
  - anything else                                                    -> base64, flagged

Usage (finding.sh pipes the raw field on stdin):

    printf '%s' "$REQUEST" | field-encode.py            # -> {"encoding":"utf8|base64","value":"..."}
    field-encode.py --decode --encoding base64 <<<"$VALUE"   # -> raw bytes on stdout

The `encoding` marker travels beside the value (finding schema: request_encoding /
response_encoding / evidence[].encoding). Readers decode base64 when the marker says so;
absent/utf8 means the value is literal. Stdlib only.
"""
from __future__ import annotations

import argparse
import base64
import json
import sys

# C0 controls that are legitimate in captured text; everything else in 0x00-0x1F is a
# red flag for "this is not really text".
_ALLOWED_CTRL = {0x09, 0x0A, 0x0D}


def is_clean_text(raw: bytes) -> bool:
    """True if raw is valid UTF-8 with no disallowed control bytes."""
    try:
        s = raw.decode("utf-8")
    except UnicodeDecodeError:
        return False
    for ch in s:
        o = ord(ch)
        if o < 0x20 and o not in _ALLOWED_CTRL:
            return False
        if o == 0x7F:  # DEL
            return False
    return True


def encode_field(raw: bytes, max_inline: int = 262144) -> dict:
    """Return {'encoding': 'utf8'|'base64', 'value': str}.

    base64 when the bytes are not clean text, or when they exceed max_inline (a very large
    inline blob bloats the finding JSON and is better carried opaque)."""
    if len(raw) <= max_inline and is_clean_text(raw):
        return {"encoding": "utf8", "value": raw.decode("utf-8")}
    return {"encoding": "base64", "value": base64.b64encode(raw).decode("ascii")}


def decode_field(value: str, encoding: str) -> bytes:
    if encoding == "base64":
        return base64.b64decode(value.encode("ascii"))
    return value.encode("utf-8")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Normalise an evidence field for safe JSON storage")
    p.add_argument("--decode", action="store_true", help="decode instead of encode")
    p.add_argument("--encoding", default="utf8", help="with --decode: utf8 or base64")
    p.add_argument("--max-inline", type=int, default=262144)
    a = p.parse_args(argv)

    raw = sys.stdin.buffer.read()
    if a.decode:
        sys.stdout.buffer.write(decode_field(raw.decode("utf-8", "replace"), a.encoding))
        return 0
    json.dump(encode_field(raw, a.max_inline), sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
