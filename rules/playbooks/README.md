# Attack Playbooks

Declarative, reachability-aware attack chains. A playbook fuses four things Grimnir
already tracks separately into one unit:

1. **HUGINN recon signals** — what the asset map and intel feed found (`prerequisites`).
2. **The reachability gate taxonomy** — which lanes the operator can actually reach (`reachability.gates`).
3. **The confirm harness + evidence gate** — how each step is proven (`chain[].confirm`, `chain[].evidence_class`).
4. **The never-submit list** — the dismissal traps each lane risks (`never_submit`).

The point is *not* to fire tooling (Grimnir never tests directly). It is to answer, at
`/engage` time: **given what HUGINN found and what the operator holds, which lanes are worth
dispatching, to whom, and how will we prove them?** This is the design idea borrowed from
Kittysploit's playbook engine, re-cast for an orchestrator that delegates instead of executes.

## Format

One YAML file per playbook, validated against `schemas/playbook.schema.json`. See that
schema for the full field reference. Skeleton:

```yaml
id: bola-cross-tenant
name: Cross-tenant object authorization bypass (BOLA/IDOR)
domain: api
lead_agent: specter
prerequisites:
  signals_any: [rest_api, multi_tenant, object_id]
  tech_any: [openapi, swagger]
  auth: two isolated tenant accounts, both write-capable
reachability:
  gates: [second-account]          # BLOCKED if the operator holds only one account
chain:
  - id: enumerate_objects
    capability: recon
    agent: specter
    action: Map object-scoped endpoints (/orders/{id}, /users/{id}) from the API surface.
  - id: cross_read
    capability: authz_bypass
    agent: specter
    action: Request account B's object id with account A's credentials.
    confirm: authz-confirm.py        # 4-way differential; records the negative control
    evidence_class: authz
never_submit:
  - path id in URL is not by itself a BOLA signal (run the 4-way discriminator first)
severity_ceiling: high
references:
  - hunting Rule 3 (negative control required)
```

## How the matcher uses it

`scripts/playbook.py match --project-dir DIR` reads:

- `asset-map.json` -> `technologies[].name` and `ai_indicators` (for `tech_any` / `signals_any`)
- `intel.jsonl` -> each entry's `discovery_type` and `tags` (for `signals_any`)
- `reachability.json` -> `gates_held` (to annotate each matched playbook REACHABLE / BLOCKED(gate) / UNKNOWN)

It prints matched playbooks ranked **REACHABLE first**, so the test plan leads with lanes
the operator can actually reach and defers or flags the gated ones (hunting Rules 1, 20-23).

## Authoring rules

- **Public-repo hygiene.** These files are tracked and world-visible. Never name a real
  program, target domain, company, report number, or operator artifact. Encode the *method*,
  not the war story — generic vendor names (WordPress, Apollo) are fine; a real customer is not.
- **Delegate, don't execute.** Every `chain[].agent` names a specialist; steps describe a test
  to delegate, never a command Grimnir runs itself.
- **Tie the terminal step to proof.** The step that establishes impact should carry a `confirm`
  primitive and an `evidence_class` so the finding can clear the High/Critical evidence gate.
- **Be honest about the ceiling.** If the realistic outcome is blind/Medium, say so in
  `severity_ceiling` and list the never-submit trap — a playbook that oversells wastes spend.

---

# The playbook operating model

Playbooks are not just a lane library — they are how Grimnir's strategy is meant to grow. A lane
that has a playbook is a lane the tool will *surface and rank at `/engage`*; a lane that doesn't is
a lane you only test when you happen to remember it. So the standing job is: keep finding gaps, and
add playbooks in a disciplined way. This section is the repeatable process.

## 1. Finding gaps (do this periodically, and after a run teaches you something)

Five lenses, in priority order:

1. **Domain coverage.** Map current playbooks against the seven domains (web / api / genai / mcp /
   network / cloud / mobile) and the classification table in `CLAUDE.md`. An empty or one-thin-file
   domain is a *structural* gap — the highest-priority kind, because the tool is blind there.
2. **Portfolio frequency.** Which bug classes recur across your actual engagements (operator memory,
   the negative-lane log)? A high-frequency lane with no playbook is the
   highest-*value* gap. Frequency beats novelty.
3. **Precondition lanes.** Some lanes gate others (`auth-token-privilege` decides whether the authz
   lanes are even viable). A missing precondition is high-leverage — it makes several other
   playbooks sharper at once.
4. **Confirm-harness coverage.** A confirm primitive (`authz-confirm`, `oob-listener`,
   `render-confirm`, `mcp-confirm`) with no playbook that exercises it is either a dead capability
   or a missing lane. Cross-check both directions.
5. **Never-submit boundary lanes.** A class on `rules/never-submit.md` (CORS, self-XSS, blind SSRF)
   benefits from a playbook precisely because it encodes *where the submittable line is* — turning a
   dupe magnet into a disciplined, occasionally-real lane.

## 2. Scoping: one playbook or a small family

- **One playbook** when the lane has a single dominant mechanism and one confirm path.
- **A small family** when the class fans out into distinct mechanisms that do NOT share a confirm
  path (OAuth ATO split into `oauth-redirect-token-theft` / `sso-trust-takeover` / `account-prehijack`
  because intercepting a token, abusing IdP trust, and pre-seeding an account are three different
  proofs). Cloud split into `cloud-storage-exposure` / `cloud-iam-privesc` for the same reason.
- **Heuristic:** if a single `chain` would need more than ~8 steps or mutually-exclusive branches,
  split it. Guard against both failure modes — one sprawling playbook (thin and unfocused) and a
  pile of near-duplicate stubs.

## 3. Design (fit it to what we already have — never invent tooling)

- Map every `chain[].agent` to an existing specialist; steps describe a test to *delegate*.
- Tie the impact step to a `confirm` primitive + `evidence_class` so the finding clears the
  High/Critical evidence gate. If the class isn't `authz`/`xss`/`ssrf`, leave `evidence_class` off
  the non-terminal steps and confirm the terminal finding with the closest primitive.
- Name the reachability `gates` honestly (from the taxonomy) so `match` ranks it correctly.
- Prereqs must key off signals HUGINN actually emits — `asset-map.json` `technologies` /
  `auth_mechanisms` / `ai_indicators` / `endpoints[].tags`, and `intel.jsonl` `discovery_type` /
  `tags`. **If a needed signal isn't collected, extend `collect_target` in `scripts/playbook.py`**
  (as was done for `auth_mechanisms`) — the playbook is only as good as the signals that trigger it.
- List `never_submit` traps and a realistic `severity_ceiling`. Generic content only (public repo).

## 4. Encode now vs research first

The decision gate before writing:

- **Encode now** when: the methodology is mature, it maps to an existing confirm primitive, and
  you've run the lane enough to know its real gates and traps. (Cloud, OAuth, mobile, authz all
  qualified — no external research needed, just fitting.)
- **Research first** when: the class is genuinely emerging (a new agentic/MCP attack), OR you don't
  yet know its reachability profile, OR the proof path is unclear. Do a focused study, decide the
  confirm primitive (add one if none fits), then encode. Log what you learned so the next lane is
  cheaper.

## 5. Playbooks as strategy — growing into new areas

The point of encoding a lane *before* it's routine is that the tool then pulls you toward it. This
is how Grimnir evolves with the operator into areas of substantial value we don't hit regularly yet.
Candidate next areas (add each when it clears the encode-now bar, not before): network/Hunter chains
(pair with a pentest/red-team engagement mode), prompt-injection → cross-privilege breach (ARTEMIS,
non-MCP), gRPC/protobuf services, CI/CD and secrets-in-pipeline, and business-logic/payment-capture
manipulation. Re-run the gap sweep (section 1) after notable engagements — the negative-lane log is
the best source of the next gap.
