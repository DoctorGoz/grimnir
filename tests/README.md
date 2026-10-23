# Unit tests

Running a CLI and checking its exit status catches a broken command; it cannot catch a
command that succeeds while computing the wrong answer.

These tests cover the code where a wrong answer is the failure mode and nothing crashes:

| File | Covers | Why it matters |
|------|--------|----------------|
| `test_coverage_resolution.py` | scope parsing, host normalization, boundary matching, app-id vs domain | Silent inflation — an item counted TESTED that nobody touched turns "22 of 811" into "airtight" |
| `test_export_gate.py` | validation gate, impact shapes, SARIF | Decides what leaves the engagement; drifting wide leaks theoretical findings into a deliverable |
| `test_playbook_matching.py` | prereq matching, reachability verdicts, ordering | Decides which lanes the test plan leads with |

```bash
python3 -m pytest tests/ -q
```

Both suites run in CI. Writing these found a live bug: `app.<domain>` — one of the most
common hostnames in any scope — was classified as a mobile bundle id, because the
hostname's own `app` label supplied "app context" while a bare scope bullet supplied no
domain context. Audited against a real corpus it affected multiple scope items across
several engagements, including targets' primary web applications.
