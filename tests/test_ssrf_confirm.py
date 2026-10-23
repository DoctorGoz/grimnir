"""ssrf-confirm.py is the OOB collaborator oracle: it plants a minted callback URL into the request
and a callback is the verdict. The failures that would be silent: planting into the wrong place (no
callback ever fires), or — the dangerous one — recording a no-callback as a confident `negative` when
the listener was simply down (a silence that closes a live lane, hunting Rule 27). The live loop
needs a listener, so these assert the pure surface: placement, mint parsing, and the injection guard."""


class TestPlant:
    def test_placeholder_in_url_is_replaced(self, ssrf_confirm_mod):
        url, body = ssrf_confirm_mod.plant_oob("https://t/fetch?target={oob}", None, "http://c/h/n1")
        assert url == "https://t/fetch?target=http://c/h/n1" and body is None

    def test_placeholder_in_body_is_replaced(self, ssrf_confirm_mod):
        url, body = ssrf_confirm_mod.plant_oob("https://t/webhook", '{"url":"{oob}"}', "http://c/h/n1")
        assert body == '{"url":"http://c/h/n1"}' and url == "https://t/webhook"

    def test_every_occurrence_is_replaced(self, ssrf_confirm_mod):
        url, _ = ssrf_confirm_mod.plant_oob("https://t?a={oob}&b={oob}", None, "X")
        assert url == "https://t?a=X&b=X"

    def test_has_placeholder_detects_url_or_body(self, ssrf_confirm_mod):
        m = ssrf_confirm_mod
        assert m.has_placeholder("https://t?u={oob}", None)
        assert m.has_placeholder("https://t", '{"u":"{oob}"}')
        assert not m.has_placeholder("https://t?u=1", '{"u":"2"}')


class TestParseMint:
    def test_parses_nonce_and_single_hop_url(self, ssrf_confirm_mod):
        out = ("nonce: gnDEADBEEF   label: FINDING-1 t.io\n"
               "  http single-hop  : http://203.0.113.10:8080/h/gnDEADBEEF\n"
               "  http 2-hop bypass: http://203.0.113.10:8080/r/gnDEADBEEF?to=x\n")
        nonce, url = ssrf_confirm_mod.parse_mint(out)
        assert nonce == "gnDEADBEEF" and url == "http://203.0.113.10:8080/h/gnDEADBEEF"

    def test_unparseable_output_returns_none(self, ssrf_confirm_mod):
        assert ssrf_confirm_mod.parse_mint("garbage, no nonce here") == (None, None)
        assert ssrf_confirm_mod.parse_mint("") == (None, None)

    def test_prefers_single_hop_over_two_hop(self, ssrf_confirm_mod):
        # the 2-hop redirect URL is for the operator's rung climb, not the plain probe
        out = ("nonce: gnAAA\n  http single-hop  : http://c/h/gnAAA\n"
               "  http 2-hop bypass: http://c/r/gnAAA?to=http://c/h/gnAAA\n")
        _nonce, url = ssrf_confirm_mod.parse_mint(out)
        assert url == "http://c/h/gnAAA" and "/r/" not in url


class TestPreflightGate:
    def test_no_placeholder_writes_inconclusive_not_a_crash(self, ssrf_confirm_mod, tmp_path, monkeypatch):
        # A lane with no {oob} injection point must degrade to inconclusive, never fire, never crash.
        import sys
        monkeypatch.setattr(sys, "argv", [
            "ssrf-confirm.py", "--finding-id", "F-1", "--project-dir", str(tmp_path),
            "--url", "https://t/fetch?u=1"])   # no {oob}
        rc = ssrf_confirm_mod.main()
        rec = _load_verdict(tmp_path, "F-1")
        assert rc == 0 and rec["verdict"] == "inconclusive" and rec["vuln_class"] == "ssrf"


def _load_verdict(project_dir, finding_id):
    import json
    with open(project_dir / "evidence" / finding_id / "verdict.json") as fh:
        return json.load(fh)
