# Grimnir architecture

This is the design-level map of Grimnir: what each piece is, how an engagement flows through
it, and where everything lives. It leads with the organizing principle rather than an
exhaustive file list, because the principle is stable while the file list churns. When the two
disagree, **the filesystem is authoritative.**

## The shape

Grimnir is an orchestrator (the always-resident brief in `CLAUDE.md`) plus six specialist
agents. The orchestrator never tests. It classifies a target, scopes it, delegates to the
right specialists, tracks state, and compiles one report.

```
                      GRIMNIR  (orchestrator / PM)
                      classify - scope - delegate - track - report
                                     |
                      HUGINN  (Phase 0 recon, always first)
                      subdomains - ports - fingerprint - asset map - intel feed
                                     |
        +-----------+-----------+-----------+-----------+-----------+
     Specter     ARTEMIS      Hunter       Nimbus      Nomad    report-compiler
     API/Web     GenAI/LLM    Network      Cloud       Mobile   (unified report)
                 & MCP        & Infra      & IaaS
```

Every specialist reads the shared hunting rules at startup, writes findings in one structured
format, and shares discoveries through a single cross-agent intel feed. That uniformity is
what lets the orchestrator treat the team as one pipeline instead of six tools.

## Two questions decide where anything lives

1. **Shared, or specialist-specific?** Cross-agent capability lives at the repo root
   (`scripts/`, `rules/`, `templates/`, `schemas/`, `.claude/`). Anything specific to one
   specialist lives under that specialist's own directory (`huginn/`, `specter/`, `artemis/`,
   `hunter/`, `nimbus/`, `nomad/`).

2. **Executable, or knowledge?** Executables are `scripts/`. Static knowledge (methodology,
   references, wordlists) lives under `docs/` / `references/` / `wordlists/` under whoever
   owns it.

That is the whole model. A new capability slots in by answering those two questions.

## The four kinds of artifact

| Kind | Where | What it is | Invoked how |
|------|-------|-----------|-------------|
| **Agent** | `.claude/agents/<id>.md` | A specialist persona: system prompt, methodology, allowed tools. Its scripts live in `<id>/`. | Spawned as a subagent |
| **Skill** | `.claude/skills/<name>/` | A procedure the orchestrator drives interactively. | Skill tool |
| **Command** | `.claude/commands/<name>.md` | A slash-command entry point that kicks off a workflow or delegates. | `/name` |
| **Script** | `scripts/` or `<agent>/scripts/` | An executable that does one mechanical job: scan, extract, confirm. | Bash |

Rule of thumb: interactive workflow becomes a skill; one mechanical job becomes a script.

## How an engagement flows

```
/engage target
   classify -> scope -> reachability gate -> engagement brief -> test plan
       |
/recon target
   HUGINN Phase 0 -> asset-map.json + intel.jsonl
       |
playbook.py match
   rank the applicable attack playbooks REACHABLE-first against the fresh asset map
       |
specialists test the ranked lanes
   each candidate finding is confirmed by scripts/confirm/ before it is promoted
       |
/report
   merge, dedup, cross-domain chaining, framework mapping -> report.md
```

## The engagement directory contract

An engagement is a directory, not a database. Everything about one target lives under
`$GRIMNIR_WORKSPACE/<project>/`, and the tools agree on these files:

| File | Written by | What it holds |
|------|-----------|---------------|
| `scope.md`, `classification.md`, `test-plan.md` | `/engage` | authorization, target type, the plan |
| `state.json` | `scripts/state.sh` | per-agent phase, status, progress, checkpoints |
| `asset-map.json` | HUGINN | the attack surface: hosts, endpoints, tech, auth, WAF |
| `intel.jsonl` | any agent | append-only cross-agent feed, items routing-tagged |
| `decisions.jsonl` | `scripts/decision-log.sh` | append-only trail of why a lane was engaged, skipped, or not filed |
| `activity.jsonl` | `scripts/activity.py` | append-only ledger of every lane fire, finding, validation, negative |
| `roe.json` | `scripts/roe.py` | the program's rules of engagement: rate, budget, required headers, scanning ban |
| `<agent>/findings/` | `scripts/finding.sh` | structured findings (`AGT-NNN.json` plus markdown) |
| `report.md` | report-compiler | the unified engagement report |

Because the contract is files, a later session resumes an engagement by reading them, and a
coverage claim can be reconciled against them rather than asserted. Schemas for the structured
files live in `schemas/`.

## Confirmation harness and the evidence gate

`scripts/confirm/` holds non-interactive primitives that promote a `theoretical` finding to
`confirmed` with reproducible proof, each emitting the same `{vuln_class, verdict}` record:
differential authz/authn/tier oracles, an out-of-band listener for blind SSRF and injection, a
DNS-rebinder, headless-render proof for XSS/DOM, SSTI/SQLi/JWT/race oracles, and an MCP-native
primitive. `scripts/validate-finding.sh` is the only promoter: it reads that record, carries
across the class, negative control, screenshot, and method, and an **evidence gate** blocks a
High or Critical promotion that lacks the class-appropriate artifact. A promotion therefore
cannot claim more than its evidence does, and "confirmed" means a triager can reproduce it.
Details and per-primitive flags: `scripts/confirm/README.md`.

## Playbooks: schema and matcher

A playbook (`rules/playbooks/*.yaml`, `schemas/playbook.schema.json`) is one declarative
attack chain that fuses HUGINN's recon signals, the reachability taxonomy, the confirmation
harness, and the never-submit list into a single decision unit. `scripts/playbook.py match`
ranks the applicable chains REACHABLE / BLOCKED(gate) / UNKNOWN against the asset map, so the
test plan leads with lanes you can actually reach. `scripts/playbook.py plan <id>` renders a
matched chain as runnable commands: the confirm primitive with `--finding-id` filled, then
`finding.sh`, then `validate-finding.sh --from-evidence`, with target-specific values surfaced
as explicit `{PLACEHOLDER}` fields. Playbooks whose severity depends on what comes back carry a
`response_channel` block, so a critical claim cannot rest on a blind channel.

## Intelligence layer

Before the expensive testing, Grimnir decides where to spend effort and, more valuably, where
to skip. `scripts/reachability.sh` labels each high-value lane REACHABLE / GATED / UNKNOWN at
`/engage`. `scripts/brief.sh` fuses reachability, fertility, and focus areas into one spend /
skip / gated prior. `scripts/fertility.sh` asks whether the surface is actually yielding bugs,
so a hot surface raises the threshold to keep digging and an unknown one never lowers it.
`scripts/coverage.py` closes the loop at the end, reconciling scope against what was tested and
refusing to let an engagement close on the assets that happened to get attention.

## The private backend (design level)

The public toolkit is driven by hand or by an interactive agent: a human or the orchestrator
runs the confirm primitives and promotes findings. Behind it, the authors run an optional
backend that is not part of this repo. At a design level it is a daemon that schedules
deterministic, read-mostly test lanes against an engagement under a rules-of-engagement gate
(rate, budget, quiet hours, scanning ban, an auto-fire switch), writing the same findings and
evidence this toolkit produces. Anything a lane cannot prove without a human, and every
state-changing or account-level action, is parked for a person to confirm before it goes
anywhere. The public tools expose the seams this backend plugs into (the `roe.py` lane check,
the activity ledger, the evidence records) but carry none of its scheduling, tuning, or
target-selection logic.

## Repo vs runtime vs operator (what is not in here)

The repo is the generic "core build." Two whole tiers live outside it and are never committed
(see Public Repository Hygiene in `CLAUDE.md`):

- **Engagement data**: `$GRIMNIR_WORKSPACE/<project>/` (default `~/workspace/<project>/`),
  per-program scope, findings, evidence, state, intel. One directory per engagement.
- **Operator-local knowledge**: `$GRIMNIR_HOME/` (default `~/.grimnir/`, cross-engagement) and
  `TEAM.md` (a gitignored infrastructure roster).

The three roots are separate variables on purpose. `$GRIMNIR_REPO_DIR` (default
`~/workspace/grimnir`) is this checkout: replaceable, public, safe to delete and re-clone.
`$GRIMNIR_WORKSPACE` is engagement data: irreplaceable and target-specific. `$GRIMNIR_HOME` is
cross-engagement knowledge: irreplaceable and operator-specific. They default to
overlapping-looking paths, which is exactly why code must never derive one from another.
