# [Finding tag] pushback rebuttal playbook

The main report (`[path to draft]`) carries the full per-metric CVSS justification and the pre-emption section. This document is for **after** specific pushback arrives, with short focused responses keyed to each likely dismissal pattern. Pick the matching block, send as a comment.

[Replace each pattern below with the dismissal arguments you actually expect for *this specific finding* in *this specific program*. Look up the program's past dismissals before drafting. Aim for 8-12 patterns. Each block should be 1-2 short paragraphs and stand alone.]

---

## Pattern 1: [Most likely dismissal, verbatim quote of the analyst's expected language]

[Counter-argument. Anchor on structural facts (role vs identity, scope vs object, data class vs ownership), not appeals to spec authority. Keep it tight: the reviewer is skimming.]

---

## Pattern 2: ["This requires compromised credentials" or equivalent self-access framing]

[Counter. Note that authenticated-BFLA findings by definition involve an authenticated caller exceeding their authority; otherwise every BFLA gets N/A'd on these grounds. CVSS PR:L already accounts for the authentication requirement.]

---

## Pattern 3: ["Scope should be Unchanged"]

[Counter. Cite CVSS 3.1 spec language: "affect resources beyond the security scope managed by the security authority of the vulnerable component." Identify the two distinct authority boundaries crossed.]

---

## Pattern 4: ["Confidentiality should be Low or None"]

[Counter framed on data class, not row ownership. Enumerate the specific fields exposed and the operational/compliance role they play.]

---

## Pattern 5: ["Integrity is bounded — user only manipulates their own resources"]

[Counter. Identify what the writes go *into* (workflow data store, audit pipeline, KPI/SLA feed). Note any unbounded-iteration property if present.]

---

## Pattern 6: ["This is by design"]

[Counter. Frontend bundle, route naming, response schema, JWT claim model — all establish the intended boundary. "By design" must reconcile with those artifacts to be coherent.]

---

## Pattern 7: ["Bounded write impact / target already in terminal state"]

[Counter, if applicable. Lifecycle reset / resume-from-resolved / re-entry properties that defeat this argument.]

---

## Pattern 8: ["Severity is Medium because no PII is exposed"]

[Counter. PII is not the only data class CVSS measures. Internal operational metadata, safety-pipeline flags, queue health, etc., all have impact independent of PII content.]

---

## Pattern 9: ["Show us a real-world attack chain"]

[Counter. The chain in the main report is the real chain. Enumerate downstream operational impact: queue inflation, audit pollution, premature closure, opportunistic targeting based on regional health leak. Each is one or two requests with normal credentials.]

---

## Pattern 10: ["Already patched"]

[Counter. The appeal stands on captured state at submission time. Correlation IDs and timestamps are reproducible from the program's side. A silent patch is a confirmation, not a defense.]

---

## When to send what

- **Single-pattern pushback:** send the matching block alone. Do not overload the response.
- **Multi-pattern pushback:** combine 2-3 blocks max, lead with the strongest, drop the weakest.
- **Severity-only pushback ("we're scoring this Medium"):** combine the Scope, Confidentiality, Integrity blocks.
- **Triage-out-of-scope pushback:** combine the identity / credentials blocks.
- **Vague "limited impact" pushback:** combine the by-design, no-PII, real-world-chain blocks.

Each block is intentionally short. The main report carries the long-form argument; these are surgical follow-ups.
