# Bug bounty submission guide

This is the standing methodology for any external-facing security report Grimnir produces (HackerOne, Bugcrowd, direct disclosure to a program).

## Pairing

Every High or Critical external submission produces **two** artifacts:

1. **Main report** — based on `templates/bb-report.md`. Self-contained, carries the full CVSS justification and pre-emption of dismissals.
2. **Pushback rebuttal playbook** — based on `templates/pushback-playbook.md`. Stays internal until needed. Surgical, pattern-keyed responses for after the analyst pushes back.

For Medium and below, the playbook is optional. The main report still applies.

## Gap closure — run this loop before drafting, and again before filing

**A report is finished when its gaps are closed, not when its prose is good.** The most expensive
failure mode is a fluent, well-structured report that argues around a hole instead of testing it: it
reads as complete, survives a skim, and dies on contact with an analyst who asks the one question the
draft was written to deflect.

Run this as an explicit loop:

1. **Enumerate the gaps in writing, before drafting.** List every claim the report will make and mark
   each one *demonstrated* or *asserted*. Anything asserted is a gap. Do this as a written list, not
   in your head; the point is to make gaps countable.
2. **Test to close each gap.** Go get the evidence. Reaching for the wrong client, egress or tooling is
   a common reason a gap looks unclosable when it is not.
3. **Re-enumerate.** Closing one gap routinely opens another, or invalidates a claim you had already
   accepted. New evidence can also reframe the asset entirely (see Rule 31), which changes which gaps
   matter.
4. **Repeat until every gap is closed, or provably cannot be closed.**
5. **Then write, to what survived.** Severity, title and impact follow the evidence you actually hold.

**The rule that matters most: a pre-emption paragraph is not a substitute for a test.** If you find
yourself drafting a rebuttal to an objection you could have gone and tested, stop drafting and test it.
Pre-emption is for objections about *judgement* (severity, business impact, design intent). It is not
for objections about *facts* — those get closed with evidence or conceded. A pushback playbook entry
answering "you never demonstrated X" with an argument, rather than a capture of X, is the tell that
this loop was skipped.

Gap checks that repeatedly catch real problems:

- **Whose data is in the evidence?** Access to a resource you created yourself is not access to a
  victim's. This is the single most common gap and it is usually invisible to the author. See Rule 28
  and Rule 31.
- **Can a third party reproduce it?** Walk the reproduction steps as written, from a clean environment,
  with the tools the steps name. If it only works from your browser, your egress, your geo or your
  session, the steps are wrong and the report will be closed as unreproducible.
- **Is the bypassed control real for the attacker's starting state?** For any bypass, missing
  step-up or missing re-auth claim, the baseline row needs a capture of the first-party client,
  holding the same credential the attacker holds, being challenged. A challenge captured on another
  path (signed-out page, other client, other role) does not count. See Rule 34.
- **Does every claim have a matching artifact on disk?** Including phrases like "full captures
  retained". Diff each number, ID and status code in the report against the evidence directory.
- **Is the asset what the report says it is?** Load it in a real browser and read its own UI copy,
  title and bundle before describing it.
- **Is the claimed impact in scope?** Volunteering an out-of-scope impact (DoS, spam, self-XSS) invites
  a partial-scope flag and taints the rest.
- **Does the severity rest on something demonstrated?** If a CVSS metric is carrying weight that the
  evidence does not support, lower it before an analyst does.

### Claims and the floor

Split what the finding asserts into claims: exactly one **base** claim (the bug itself) and any
number of **escalation** claims (what it reaches or enables), each with the severity it would carry
if true and the control that tests it. Seed them with `finding.sh --claim "kind|severity|text|control"`,
settle them with `validate-finding.sh --claim-verdict C2=refuted`, and read the result with
`python3 scripts/finding_state.py show`. The **floor** is the highest severity whose claims all
survived; a refuted escalation is simply dropped and an untested one stops the climb.

File at the floor. An escalation that fails its control does not take the base finding down with it,
and an escalation still untested does not hold the report: file, then add it as a comment when it
survives. Before filing, run `scripts/fresh-eyes.py` for an independent attempt to refute each claim
from the packet alone, and run the `--repro` script yourself. See Rule 35.

Anything genuinely unclosable is stated plainly as a limitation in the report, with its denominator.
A known, disclosed limitation costs far less than one the analyst discovers.

## Pre-discovery: program intelligence

Before drafting, look up the program's past report dismissals. The pre-emption section of the main report is *only* useful if it addresses the dismissal patterns this specific program has used before.

- Search the program's H1 hacktivity, public Bugcrowd disclosures, and any internal notes from prior engagements for closed/N/A reports adjacent to your finding.
- Note the exact language the analyst used to dismiss. Treat it as the next analyst's likely opening move.
- Pre-empt those patterns explicitly in the main report. Do not name them as dismissals; frame as "structural facts about this finding."

**Comparative precedent (severity anchor + dup check).** Search the program's disclosed reports and public writeups for the same weakness class on similar assets. A disclosed report with a payout anchors severity, and a recent parent report is the duplicate risk to date before you file.

## Discovery techniques worth running on every engagement

- **Version-sprawl sweep.** When you find a finding on `/v5/foo`, sweep `/v1/foo`, `/v2/foo`, ..., `/v6/foo` and any sibling namespaces (`/csa-foo`, `/admin-foo`, `/internal-foo`). Older versions often have weaker auth than the current one. Newer (unannounced) versions sometimes ship without function-level checks.
- **Cross-region replay as default.** If the target has regional backends (per-country APIs, geo-routed paths, locale-prefixed routes), replay any access-control finding against every reachable region in a single session. Single-region findings on multi-region targets understate impact.
- **Lifecycle exhaustion.** For stateful resources (chat rooms, tickets, orders, sessions), drive the full state machine: create → modify → terminate → resume. Resume-from-terminal often re-opens write capability that's assumed gated.
- **Confirmation-oracle hunting.** When AC:H pushback is foreseeable ("you can't guess UUIDs"), don't argue the spec. Find a deterministic endpoint that confirms an ID (200 vs 404/500 differential on a single request) and submit that as appeal evidence.
- **Differential auth testing.** Same request with consumer JWT, agent JWT, no JWT, expired JWT, foreign-tenant JWT. The differential reveals which check is actually present.
- **Schema fishing.** Send wrong types (arrays where strings are expected) to provoke validation errors that disclose backend field names, then probe those fields for mass-assignment.

## Hygiene rules

- **No em-dashes anywhere in external output.** Use commas or colons. Enforced by `scripts/check-report-hygiene.sh` (also flags en-dashes, smart quotes, and ellipsis chars).
- **No internal codenames in submitted reports.** F-numbers, Specter/ARTEMIS finding IDs, and project tags stay in the workspace. External reports reference past submissions by H1/Bugcrowd report number, never by internal tag. `check-report-hygiene.sh` greps for the agent codenames as a backstop.
- **Verify CVSS via FIRST calculator before locking the score.** Score and vector must match exactly. A self-downgraded score invites a further downgrade by the analyst.
- **For High/Critical: in-depth CVSS + dismissal pre-emption belong in the main report**, not deferred to a follow-up. Anchoring on a low score happens fast; the main report is the only chance to prevent it.
- **Lead the summary with concrete data impact.** Not technical mechanics. The first paragraph must make dismissal harder, not easier.

## Evidence directory layout

```
$GRIMNIR_WORKSPACE/$PROGRAM/evidence/$FINDING-TAG-YYYY-MM-DD/   (default ~/workspace/...)
├── baseline/                 # Same-tenant / same-region captures
├── cross-tenant/             # Cross-tenant replay (if applicable)
├── cross-market/             # Cross-region replay (if applicable)
├── canaries.txt              # Canary tags + message-IDs
└── broader-sweep.txt         # Bulk-replay summary
```

All correlation IDs from the report must appear in the evidence directory. If the report cites a correlation ID that has no captured response, the evidence is incomplete.

## Pre-submission checklist

Before sending any external report, run through:

- [ ] **Gap loop closed** (see Gap closure above): gaps were enumerated in writing, tested, and re-enumerated until closed or provably unclosable. No pre-emption paragraph stands in for a test that could have been run.
- [ ] **Evidence contains a party other than us** — or, if it cannot, that limitation is stated explicitly in the report rather than argued around
- [ ] **Reproduction steps walked from a clean environment** with the tools the steps name (no dependence on our browser session, egress, geo, or cookies unless the report says so)
- [ ] **Asset identified from the app itself** (UI copy, title, bundle), not inferred from the hostname
- [ ] **No out-of-scope impact claimed** (check the program's exclusions: DoS, spam, self-XSS, etc.)
- [ ] Finding is `validation.state == confirmed` (negative control recorded for authz bugs; screenshot/vision confirm for UI/DOM bugs; out-of-band proof for SSRF). Theoretical findings do not get submitted.
- [ ] CVSS vector matches score (verified via FIRST calculator)
- [ ] Typography + codename hygiene passes: `scripts/check-report-hygiene.sh <report.md>` exits clean (no em-dashes, en-dashes, smart quotes, ellipsis chars, or internal codenames; resolve the NNNNNNN submission-id warning). Mandatory for any draft written by a delegated model (e.g. a cheaper model), which does not inherit this house style.
- [ ] Prior program dismissals reviewed and addressed in pre-emption section
- [ ] All correlation IDs in report present in evidence directory
- [ ] Title leads with weakness + scope of impact
- [ ] Architecture context names the specific JWT claim / scope / role boundary failing
- [ ] Pushback playbook drafted (High/Critical only)
- [ ] Single-account engagements: degraded-mode caveat noted

## Pairing with internal Grimnir state

- The internal finding tag (e.g. an F-number or finding ID) lives in `$GRIMNIR_WORKSPACE/$PROGRAM/findings/` and in memory. It never appears in the external report.
- The submitted report number (assigned by the platform after submission) is captured in memory and used for cross-referencing in subsequent reports against the same program ("distinct from but adjacent to report #NNNNNNN").
- The pushback playbook stays in `$GRIMNIR_WORKSPACE/$PROGRAM/reports/` and is only sent (in part) after specific pushback arrives.
