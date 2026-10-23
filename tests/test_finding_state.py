"""The canonical finding-state predicate must hold system-wide, independent of any
operator preference: only an independently `confirmed`, un-dispositioned finding ships."""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import finding_state as fs  # noqa: E402


def test_only_confirmed_ships():
    assert fs.is_ship_ready({"id": "X", "validation_state": "confirmed"})
    # 'validated' = reproduced once, not independently confirmed -> must NOT ship.
    assert not fs.is_ship_ready({"id": "X", "validation_state": "validated"})
    assert not fs.is_ship_ready({"id": "X", "validation_state": "theoretical"})
    assert not fs.is_ship_ready({"id": "X"})  # missing -> theoretical
    assert not fs.is_ship_ready({"id": "X", "validation_state": "refuted"})


def test_status_field_never_gates_ship():
    # Analyst triage status of 'confirmed' does NOT make a theoretical finding shippable.
    assert not fs.is_ship_ready({"id": "X", "status": "confirmed", "validation_state": "theoretical"})


def test_nested_validation_shape():
    assert fs.validation_state({"validation": {"state": "confirmed"}}) == "confirmed"
    assert fs.is_ship_ready({"validation": {"state": "confirmed"}})


def test_disposition_is_terminal():
    assert not fs.is_ship_ready({"validation_state": "confirmed", "disposition": "submitted"})
    assert not fs.is_ship_ready({"validation_state": "confirmed", "disposition": "duplicate"})
    assert not fs.is_ship_ready(
        {"validation_state": "confirmed", "submission": {"status": "not-applicable"}}
    )


def test_validation_block_carries_proof():
    vb = fs.validation_block(
        {"validation": {"state": "confirmed", "method": ["manual-repro"], "checked_at": "2026-09-09T11:38:37Z"}}
    )
    assert vb["state"] == "confirmed"
    assert vb["method"] == ["manual-repro"]
    assert vb["checked_at"].startswith("2026-09-09")


def test_load_findings_reads_agent_dir_and_ships_only_confirmed(tmp_path):
    (tmp_path / "specter" / "findings").mkdir(parents=True)
    (tmp_path / "findings").mkdir()
    (tmp_path / "specter" / "findings" / "SPE-001.json").write_text(
        json.dumps({"id": "SPE-001", "validation": {"state": "confirmed"}})
    )
    (tmp_path / "findings" / "OLD.json").write_text(
        json.dumps({"id": "OLD", "validation_state": "theoretical"})
    )
    findings = fs.load_findings(str(tmp_path))
    assert {f["id"] for f in findings} == {"SPE-001", "OLD"}
    assert all("_path" in f for f in findings)
    assert [f["id"] for f in fs.ship_ready_findings(str(tmp_path))] == ["SPE-001"]


def test_set_disposition_writes_and_suppresses_ship(tmp_path):
    """F2: stamping a terminal disposition is the write-back that makes a filed finding
    drop out of the deliver set the executor gate reads (ship_ready_findings), so it never
    re-emits as a fresh 'confirmed finding ready' task."""
    fp = tmp_path / "specter" / "findings" / "SPE-001.json"
    fp.parent.mkdir(parents=True)
    fp.write_text(json.dumps(
        {"id": "SPE-001", "title": "x", "severity": "high", "validation": {"state": "confirmed"}}))
    assert fs.is_ship_ready(json.loads(fp.read_text()))          # ship-ready before
    assert [f["id"] for f in fs.ship_ready_findings(str(tmp_path))] == ["SPE-001"]

    d = fs.set_disposition(str(fp), "submitted", ref="H1 #123", reason="filed")
    assert d["disposition"] == "submitted"
    assert d["disposition_detail"]["ref"] == "H1 #123"
    assert d["disposition_detail"]["decided_by"] == "operator"

    on_disk = json.loads(fp.read_text())                        # persisted, atomically
    assert on_disk["disposition"] == "submitted" and on_disk["title"] == "x"
    assert not fs.is_ship_ready(on_disk)
    assert fs.ship_ready_findings(str(tmp_path)) == []          # deliver gate sees nothing


def test_held_is_non_terminal_but_off_ship():
    """`held` parks a confirmed finding: it is NOT ship-ready (no gate auto-delivers it),
    but it is NOT terminal either — is_held is true and it stays reviewable."""
    f = {"id": "X", "validation_state": "confirmed", "disposition": "held"}
    assert fs.is_held(f)
    assert not fs.is_ship_ready(f)          # parked -> off the ship set
    assert "held" not in fs.TERMINAL_DISPOSITIONS  # but not a terminal marker


def test_held_findings_lists_parked_confirmed(tmp_path):
    (tmp_path / "specter" / "findings").mkdir(parents=True)
    (tmp_path / "specter" / "findings" / "SPE-001.json").write_text(
        json.dumps({"id": "SPE-001", "validation": {"state": "confirmed"}, "disposition": "held"}))
    (tmp_path / "specter" / "findings" / "SPE-002.json").write_text(
        json.dumps({"id": "SPE-002", "validation": {"state": "confirmed"}}))  # shippable, not held
    (tmp_path / "specter" / "findings" / "SPE-003.json").write_text(
        json.dumps({"id": "SPE-003", "validation": {"state": "validated"}, "disposition": "held"}))  # not confirmed
    assert [f["id"] for f in fs.held_findings(str(tmp_path))] == ["SPE-001"]
    assert [f["id"] for f in fs.ship_ready_findings(str(tmp_path))] == ["SPE-002"]


def test_set_disposition_accepts_held(tmp_path):
    fp = tmp_path / "findings" / "F.json"
    fp.parent.mkdir(parents=True)
    fp.write_text(json.dumps({"id": "F", "validation_state": "confirmed"}))
    d = fs.set_disposition(str(fp), "held", reason="BC operational freeze")
    assert d["disposition"] == "held"
    on_disk = json.loads(fp.read_text())
    assert fs.is_held(on_disk) and not fs.is_ship_ready(on_disk)


def test_set_disposition_rejects_non_terminal(tmp_path):
    """Only a TERMINAL marker suppresses shipping; a non-terminal string is a silent
    no-op the caller would think worked, so it must raise and leave the file untouched."""
    import pytest
    fp = tmp_path / "findings" / "F.json"
    fp.parent.mkdir(parents=True)
    fp.write_text(json.dumps({"id": "F", "validation_state": "confirmed"}))
    with pytest.raises(ValueError):
        fs.set_disposition(str(fp), "in-progress")
    assert fs.is_ship_ready(json.loads(fp.read_text()))         # untouched -> still ships


def test_set_disposition_normalizes_case_and_find_finding(tmp_path):
    fp = tmp_path / "artemis" / "findings" / "ART-001.json"
    fp.parent.mkdir(parents=True)
    fp.write_text(json.dumps({"id": "ART-001", "validation_state": "confirmed"}))
    rec = fs.find_finding(str(tmp_path), "ART-001")
    assert rec and rec["_path"].endswith("ART-001.json")
    fs.set_disposition(rec["_path"], "Duplicate")               # mixed case tolerated
    assert fs.disposition(json.loads(fp.read_text())) == "duplicate"
