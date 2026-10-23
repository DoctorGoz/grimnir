# Reachability Pre-Check — $PROJECT

Canonical format for the intelligence-layer LANE gate. `scripts/reachability.sh init`
generates a pre-filled copy of this in the engagement dir; this template documents the
shape and lets you fill it by hand if needed.

**The rule:** do not plan or dispatch a *primary* lane you cannot reach. A gated
high-value lane discovered after the testing is the #1 documented source of fruitless
effort. Run this gate after classification, before the test plan and any dispatch.

## Gate taxonomy

`kyc` · `funded-balance` · `second-account` · `device` · `paid-tier` · `geo-egress` ·
`browser-interactive` · `otp-2fa` · `approval-role`

## Gates held (from project.md -> Account Capabilities)

| Gate | Held |
|------|------|
| second-account | [yes/no] |
| kyc | [none / level-0 / verified] |
| funded-balance | [yes/no] |
| device | [yes/no] |
| paid-tier | [free / paid] |
| geo-egress | [regions / unknown] |
| otp-2fa | [yes/no] |
| approval-role | [yes/no] |

## Stack-known gates (prior programs on this stack hit these)

- [fill from your own notes]

## Lane matrix

One row per high-value lane from classification.md. Verdict =
REACHABLE / GATED(gate) / UNKNOWN(needs-check). Lead the test plan with REACHABLE lanes
plus the program focus areas; deprioritize GATED ones (and do not re-test them as if
they were negatives — a gated lane is gated, not disproven).

| Lane / surface | Class | Gate(s) | Verdict | Note |
|----------------|-------|---------|---------|------|
| cross-account / cross-tenant authz (BOLA/BFLA) | AUTHZ | second-account | REACHABLE / GATED | need a 2nd account |
| (add lanes from classification.md) |  |  | UNKNOWN |  |
