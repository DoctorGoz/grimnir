# Changelog

Public releases are snapshots of the development tree, cut and leak-scanned by a release builder.
Each release is one commit; development history is not published.

## v0.6.0

The first snapshot release after a period of private development.

- **Claim-split verification.** A finding lists its claims (one base claim plus escalations), and each
  claim is tested on its own. Refuting one escalation lowers the filed severity to the highest claim
  that survived, so the finding isn't thrown out whole. The floor is written at confirmation, and the
  report hygiene check warns when a draft claims more than the floor.
- **Fresh-eyes review.** `scripts/fresh-eyes.py` packs a finding, its evidence and its repro script into
  an isolated packet for a reviewer with no engagement context.
- **Rules of engagement.** Per-program `roe.json` (rate, daily budget, required headers, scanning ban,
  AI-tool ban) enforced by `scripts/roe.py`, with egress through the program's proxy.
- **Attack playbooks.** The playbook engine (`scripts/playbook.py match`) ranks lanes against the
  asset map and reachability labels. Ships with example playbooks for cross-tenant BOLA, mass
  assignment, missing-auth replay, in-band SQL injection and reflected XSS, plus a Salesforce
  Experience Cloud pack (methodology, playbooks and a read-only guest-access mapper).
- **MCP testing.** Enumeration, tool-poisoning and cross-server shadowing scans, rug-pull diffing, a
  confirmation harness, and an opt-in schema-driven fuzzer that respects the program's rules of
  engagement.
- **Credential intake.** `scripts/creds-normalize.py` turns freeform credential notes into the
  structured per-engagement vault.
- **Labs.** Walkthroughs for crAPI, OWASP Juice Shop, DVGA and a deliberately vulnerable MCP server.
- **CI** runs the test suite, the repository hygiene check and shellcheck.

Earlier releases (v0.1.0 to v0.5.0) were published from the previous repository history.
