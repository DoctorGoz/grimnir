# [Descriptive title: weakness + scope of impact]

[Title rules: Lead with the weakness class and the breadth of impact in human terms. No internal codenames (no F-numbers, no Specter/ARTEMIS finding IDs). No em-dashes. Aim to make dismissal hard from the title alone.]

**Program:** [Program name]
**Asset:** [Domain or service, e.g. `app.example.com` (`assistant_bff` service)]
**Weakness:** [Class + framework codes, e.g. Broken Function Level Authorization (OWASP API5:2023, CWE-863). Note compounding factors here.]
**Severity (proposed):** [Rating], CVSS 3.1 base **[X.X]** (`AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_`)
**Confirmed:** [YYYY-MM-DD], [auth context], against [scope of reach]. Full request and response captures with correlation IDs retained.
**Related:** [Distinct from but adjacent to report #NNNNNNN, OR Standalone — first report on this surface.]

---

## Summary

[2-4 sentences. Lead with concrete data or business impact, not technical mechanics. Make it clear what the affected resources are, who they belong to, and what role boundary has failed. The reviewer should be unable to dismiss this paragraph without engaging with the evidence below.]

## Impact

[Bullet list of concrete, quantified impact. What gets read, written, or driven. Include scale numbers (markets, accounts, records). Frame in terms of the program's data classes and compliance posture, not abstract CVSS metrics.]

- [Operational data class exposed across N jurisdictions / tenants]
- [State write capability on resources owned by [party], not the bearer]
- [Lifecycle iteration / repeatability properties]
- [Compliance / audit-trail implications]
- [Adjacent attack chains gated only by [missing primitive]]

## Architecture context

[1-2 paragraphs. Establish how the system *should* enforce the boundary that's failing, using the program's own JWT claims, scopes, route naming, or product surfaces. Cite the claim or scope that *would* have enforced this if checked. This proves the vuln is "the server fails to check," not "the design lacks a control."]

[If relevant, separate identity from role explicitly. A consumer is not their own [admin/agent/operator] in any market, regardless of how identity is modeled across regions.]

## Reproduction

**Prerequisites:**
- [Auth artifact, e.g. one consumer JWT obtained via normal login flow]
- [Any required headers, e.g. `x-program-app-locale: en-US`]
- [No additional setup needed]

**Step 1 — [Action].**
```http
[Verb] [Path] HTTP/1.1
Host: [host]
Authorization: Bearer [TOKEN]
[Other required headers]

[Body]
```

Response:
```http
HTTP/1.1 [Status]
[Relevant headers including correlation ID]

[Body excerpt with the fields that prove the boundary failure highlighted]
```

[Continue for each step of the reproduction, including any state-machine ordering quirks that reviewers will hit if they replay out of order. Document those quirks explicitly so they don't get treated as a non-repro.]

**Cross-tenant / cross-market replay (if applicable):**

[Show the same request against N additional backends/tenants. Tabulate correlation IDs and response indicators. If you tested the full visible footprint, say so.]

| Region | Endpoint suffix | Status | Correlation ID | Notable response field |
|--------|-----------------|--------|----------------|------------------------|
| [..]   | [..]            | [..]   | [..]           | [..]                   |

## Pre-empting prior dismissal patterns

[Look up the program's past report dismissals. Identify the dismissal patterns the analyst has used to N/A or downgrade similar findings. Address each in advance, before they can be raised.]

**[Past pattern 1, e.g. "same identity across regions = self-access"]:** [One-paragraph counter, anchored on the structural difference between the prior report and this one. If this report's boundary is *role* and the prior was *identity*, say so directly.]

**[Past pattern 2]:** [Counter.]

**[Past pattern 3]:** [Counter.]

## CVSS 3.1 vector and per-metric justification

`CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_` = **Base [X.X] [Rating]**

[Verify the score via the FIRST calculator (https://www.first.org/cvss/calculator/3.1) before submitting. Score and vector must match exactly.]

- **AV:_ ([Network / Adjacent / Local / Physical]).** [Justification.]
- **AC:_ ([Low / High]).** [Justification. If the program has historically pushed AC:H, address it here with concrete evidence: deterministic primitive, single request, repeatability, etc.]
- **PR:_ ([None / Low / High]).** [Justification.]
- **UI:_ ([None / Required]).** [Justification.]
- **S:_ ([Unchanged / Changed]).** [If Changed: cite the CVSS spec language ("affect resources beyond the security scope managed by the security authority of the vulnerable component") and identify the two authority boundaries crossed.]
- **C:_ ([None / Low / High]).** [Justification framed in data-class terms, not "did the caller create the row."]
- **I:_ ([None / Low / High]).** [Justification framed in resource-ownership terms.]
- **A:_ ([None / Low / High]).** [Justification.]

## Remediation

1. [Specific control, e.g. enforce CSA-scope claim on all `/v5/csa-chat-room*` handlers, reject consumer JWTs with 403]
2. [Market isolation / tenant isolation control]
3. [Defense in depth: object-level checks remain as a backstop]
4. [Audit-trail / monitoring recommendation]
5. [Lifecycle constraint, e.g. forbid resume-from-resolved]
6. [Inventory hygiene: deprecate or auth-gate the older API versions]

## Evidence package

- `$GRIMNIR_WORKSPACE/[program]/evidence/[finding-tag]-YYYY-MM-DD/` — same-tenant baseline captures
- `[same path]/cross-tenant/` or `/cross-market/` — replay captures
- All correlation IDs retained inline in this report
- Canary tags (if applicable): [list]

## Disclosure timeline

- YYYY-MM-DD — Discovery
- YYYY-MM-DD — Validation across [scope]
- YYYY-MM-DD — Submission (this report)

---

## Pre-submission checklist

[Internal — strip this section before submission.]

- [ ] **Gap loop closed** — every claim below marked demonstrated or asserted, each asserted one tested, then re-enumerated until closed or provably unclosable. **No pre-emption paragraph substitutes for a test that could have been run.** (See "Gap closure" in `templates/bb-submission-guide.md`.)
- [ ] **Evidence contains a party other than us** (access to a resource we created ourselves is not access to a victim's) — or the limitation is stated plainly in the report
- [ ] **Repro steps walked from a clean environment**, with the tools the steps name — they do not silently depend on our browser session, cookies, egress or geo
- [ ] **Asset identified from the app itself** (UI copy, page title, JS bundle), not inferred from its hostname
- [ ] **No out-of-scope impact claimed** (DoS, spam, self-XSS, or whatever this program excludes)
- [ ] **Every claim matches an artifact on disk** — including any "captures retained" phrasing; numbers, IDs and status codes diffed against the evidence directory
- [ ] CVSS vector run through FIRST calculator; score matches vector, and no metric carries weight the evidence does not support
- [ ] No em-dashes anywhere in the body
- [ ] No internal codenames (F-numbers, Specter/ARTEMIS finding IDs, internal project tags)
- [ ] Prior reports in this program reviewed; their dismissal patterns are addressed in the pre-emption section
- [ ] All correlation IDs in the report are present in the evidence directory
- [ ] If cross-tenant or cross-market: differential between owned vs foreign documented
- [ ] Architecture context names the specific JWT claim / scope / role boundary that's failing
- [ ] Title leads with weakness + scope of impact, not jargon
- [ ] Severity-only and triage-out-of-scope rebuttals drafted in paired pushback playbook
- [ ] Single-account engagements: degraded-mode caveat noted (or escalate to user for second account)
