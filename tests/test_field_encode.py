"""field-encode normalises evidence fields so a finding's JSON keeps the exact bytes.

The silent failure it prevents: a captured request/response or a WAF-evasion payload with
control or invalid-UTF-8 bytes gets rewritten to U+FFFD on the way into JSON, so the
evidence no longer matches what was sent. base64 must kick in exactly then, and round-trip.
"""
import importlib.util
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("grimnir_field_encode", REPO / "scripts" / "field-encode.py")
fe = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fe)


class TestCleanText:
    def test_plain_ascii_is_utf8(self):
        r = fe.encode_field(b"GET /x?q=1 HTTP/1.1")
        assert r["encoding"] == "utf8" and r["value"] == "GET /x?q=1 HTTP/1.1"

    def test_tab_newline_cr_are_allowed(self):
        r = fe.encode_field(b"a\tb\r\nc")
        assert r["encoding"] == "utf8"

    def test_valid_multibyte_utf8_is_utf8(self):
        r = fe.encode_field("héllo→".encode("utf-8"))
        assert r["encoding"] == "utf8" and r["value"] == "héllo→"


class TestNeedsBase64:
    def test_invalid_utf8_goes_base64(self):
        r = fe.encode_field(b"\xc0\xaf\xff<script>")
        assert r["encoding"] == "base64"

    def test_control_bytes_go_base64(self):
        r = fe.encode_field(b"abc\x07\x1bdef")  # bell, ESC
        assert r["encoding"] == "base64"

    def test_del_byte_goes_base64(self):
        assert fe.encode_field(b"x\x7fy")["encoding"] == "base64"

    def test_oversize_clean_text_goes_base64(self):
        r = fe.encode_field(b"A" * 100, max_inline=10)
        assert r["encoding"] == "base64"


class TestRoundTrip:
    def test_binary_round_trips_exactly(self):
        raw = b"GET /x?q=\xc0\xaf\xff\x07 HTTP/1.1"
        enc = fe.encode_field(raw)
        assert fe.decode_field(enc["value"], enc["encoding"]) == raw

    def test_clean_round_trips(self):
        raw = b"plain request"
        enc = fe.encode_field(raw)
        assert fe.decode_field(enc["value"], enc["encoding"]) == raw

    def test_is_clean_text(self):
        assert fe.is_clean_text(b"hello world")
        assert not fe.is_clean_text(b"\xff\xfe")
        assert not fe.is_clean_text(b"bell\x07")
