# Grimnir

[![CI](https://github.com/DoctorGoz/grimnir/actions/workflows/ci.yml/badge.svg)](https://github.com/DoctorGoz/grimnir/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Grimnir is an orchestrator for running authorized penetration tests and bug-bounty
engagements with Claude Code.** It classifies a target, scopes it, delegates the work to six
specialist agents, and compiles one report. Its defining rule is that a finding cannot reach
that report until a confirmation harness has reproduced it: findings are born `theoretical`
and stay there until proven. The orchestrator and every agent are prompt and methodology
definitions, so cloning the repo gives you the whole team immediately, with the heavier
toolchains installed only when you want them.

Grimnir is a methodology layer, not a scanner. It decides where to spend effort, keeps testing
inside scope and inside the program's rules, turns "I think this is a bug" into something a
triager can reproduce, and reports coverage with its denominator instead of a vibe.

## The team

HUGINN always runs first (recon and the asset map); the orchestrator then routes to the
specialists the target needs.

| Agent | Domain |
|-------|--------|
| **HUGINN** | Recon: subdomains, ports, tech fingerprint, JS analysis, asset map and intel feed (always first) |
| **Specter** | REST, GraphQL, gRPC and traditional web apps (OWASP API Top 10, WSTG) |
| **ARTEMIS** | LLM apps, RAG, agents and MCP servers (OWASP LLM / Agentic / MCP, MITRE ATLAS) |
| **Hunter** | Hosts, services and networks (PTES, MITRE ATT&CK) |
| **Nimbus** | AWS, Azure, GCP, serverless and Kubernetes (ATT&CK Cloud, CIS) |
| **Nomad** | Android and iOS apps (OWASP MASVS / MASTG) |

See **[ARCHITECTURE.md](ARCHITECTURE.md)** for how the pieces fit together.

## The differentiator: findings are born theoretical

Most of the cost of a finding is not discovery, it is proving it to someone else. Grimnir
makes that proof a property of the data, not a habit you have to remember.

Every finding carries a `validation.state` that is separate from its triage status:

- `theoretical` (believed real, no reproducible proof) is the default for a new finding,
- `validated` (reproduced),
- `confirmed` (reproducible proof plus an independent check), or
- `refuted`.

`scripts/validate-finding.sh` is the only thing that promotes a finding, and it reads the
evidence produced by the confirmation harness in `scripts/confirm/`. Each primitive writes a
machine-readable `verdict.json`, and a promotion cannot claim more than that verdict says: it
carries across the vulnerability class, the negative control, any screenshot, and the method.
An **evidence gate** hard-blocks promotion of a High or Critical finding that lacks the
class-appropriate artifact. The report compiler and the external-submission flow enforce the
other end: only `confirmed` or `validated` findings reach a report body, and `theoretical`
ones sit in an "unvalidated" appendix and are never submitted.

The confirmation primitives (differential authz, authn, tier, SSRF out-of-band, SSTI, SQLi,
XSS, JWT, race, MCP) run on stdlib `python3`; only the headless-render and DNS-rebind oracles
need extras. Full list and flags: `scripts/confirm/README.md`.

## 90-second demo

```bash
claude                              # launch Claude Code in the repo, then:

/engage acme-corp                   # classify the target, scope it, write the test plan
                                    #   also runs the reachability gate: which lanes are
                                    #   actually reachable before you spend effort on them
/recon acme-corp                    # HUGINN Phase 0 -> asset-map.json + intel.jsonl

python3 scripts/playbook.py match --project-dir ~/workspace/acme-corp
                                    # rank the applicable attack playbooks REACHABLE-first
python3 scripts/playbook.py plan bola-cross-tenant --project-dir ~/workspace/acme-corp
                                    # render the chosen chain as runnable commands:
                                    #   the confirm primitive, finding.sh, validate-finding.sh
```

Run the rendered commands and you finish with a `confirmed` finding whose evidence a triager
can replay, plus a coverage figure that names its denominator ("22 of 811 endpoints tested",
never "airtight"). For a full start-to-confirmed walkthrough against a real lab, see
**[labs/crapi.md](labs/crapi.md)**.

## Install

> **Run this on a machine you are willing to lose.** The tracked `.claude/settings.json`
> grants the agent an allow-list broad enough to run code without prompting, because
> specialists have to run unattended to be useful. A pentest orchestrator also ingests
> attacker-controlled input by design. Use a dedicated VM, container, or disposable VPS, not
> your daily workstation. Read **[SECURITY.md](SECURITY.md)** first.

Grimnir is a Claude Code orchestrator, not compiled software, so there are two independent
axes: what you can do right after cloning, and which external toolchains you install.

**Tier 0, zero install.** Clone and launch Claude Code. You get the orchestrator and all six
agents as a methodology layer: classify, scope, plan, delegate, the intel feed, structured
findings, the validation gate, and the stdlib-only confirmation primitives.

```bash
git clone https://github.com/DoctorGoz/grimnir.git ~/workspace/grimnir
cd ~/workspace/grimnir && claude
```

**Install profiles.** Run `setup/setup.sh` when you want the external toolchains. It suggests
a profile for your host; pick one explicitly with `--profile`.

```bash
./setup/setup.sh                            # interactive, suggests a profile
./setup/setup.sh --profile full --yes       # non-interactive, all agents
./setup/setup.sh --dry-run --profile lite   # preview without installing
```

| Profile | Specialist toolchains | Adds | Target host |
|---------|----------------------|------|-------------|
| **lite** | Hunter (recon) | nmap, nuclei, httpx, subfinder, naabu | Pi / drop box (2-4GB) |
| **standard** | Hunter + Specter | + ffuf, sqlmap, katana, dalfox, gau | Pi 5 / VPS (4-8GB) |
| **full** | Hunter + Specter + ARTEMIS + Nimbus + Nomad | + cloud, mobile, AI, proxies | Workstation (8GB+) |

HUGINN and the orchestrator are present in every profile. For the test gate and the
optional headless-render oracle:

```bash
python3 -m pip install -r requirements-dev.txt
python3 -m pytest -q                        # the test gate
playwright install chromium                 # only for the headless XSS/DOM oracle
```

## Lab demos

Each lab is a deliberately vulnerable app plus a walkthrough that drives Grimnir end to end,
from `/engage` to a `confirmed` finding. Run them on the same isolated host as Grimnir.

| Lab | Exercises | Guide |
|-----|-----------|-------|
| OWASP crAPI | BOLA, mass assignment, missing-auth replay | [labs/crapi.md](labs/crapi.md) |
| OWASP Juice Shop | SQL injection, reflected XSS | [labs/juice-shop.md](labs/juice-shop.md) |
| DVGA | GraphQL introspection and authz | [labs/dvga.md](labs/dvga.md) |
| Vulnerable MCP server | MCP tool poisoning, shadowing, tool-call authz | [labs/mcp.md](labs/mcp.md) |

Start at **[labs/README.md](labs/README.md)**.

## What else is in the box

- `rules/hunting.md` and `rules/never-submit.md`: the shared hunting rules every agent reads
  at startup, each written from a measured failure.
- `rules/playbooks/`: declarative, reachability-aware attack chains. `scripts/playbook.py match`
  ranks them against the asset map; `plan` renders one as runnable commands. Schema:
  `schemas/playbook.schema.json`.
- `scripts/scope.py`, `scripts/roe.py`, `scripts/session.py`: keep testing in scope, inside
  the program's rate and quiet-hour limits, and authenticated as your own test accounts.
- `scripts/reachability.sh`, `brief.sh`, `fertility.sh`: the intelligence layer that sets a
  spend / skip / gated prior before the expensive testing.
- `scripts/coverage.py`: reconciles scope against what was tested (TESTED / SKIPPED / GATED /
  UNTOUCHED) and refuses to let an engagement close on the assets that happened to get
  attention.
- `scripts/export-findings.py`: emits the gate-passing findings as SARIF 2.1.0 or a merged
  JSON bundle for external vulnerability managers.
- `templates/`: the report, submission-guide, and pushback-playbook templates;
  `scripts/check-report-hygiene.sh` lints an outbound report.
- The `caido-mode` skill drives traffic through the Caido proxy so replayed requests keep
  their original auth intact and stay visible in Caido's UI.

## Engagement data lives outside the repo

The repo is the generic toolkit. Everything about a target lives under
`$GRIMNIR_WORKSPACE/<project>/` (default `~/workspace/<project>/`): scope, findings, evidence,
state, and the intel feed, one directory per engagement. Cross-engagement operator data lives
in `$GRIMNIR_HOME` (default `~/.grimnir/`). Nothing operator-specific is ever written into this
tree. The three roots are independent variables on purpose; see ARCHITECTURE.md.

```bash
export GRIMNIR_WORKSPACE="/srv/engagements"    # engagement data (default ~/workspace)
export GRIMNIR_HOME="/srv/grimnir-state"        # cross-engagement store (default ~/.grimnir)
export GRIMNIR_REPO_DIR="/opt/grimnir"          # this checkout (default ~/workspace/grimnir)
```

## Framework coverage

| Framework | Agent |
|-----------|-------|
| PTES, MITRE ATT&CK | Hunter |
| OWASP API Top 10 (2023), WSTG v5.0 | Specter |
| OWASP LLM Top 10, Agentic Top 10, MCP Top 10, MITRE ATLAS | ARTEMIS |
| MITRE ATT&CK Cloud, CIS Benchmarks | Nimbus |
| OWASP MASVS / MASTG | Nomad |

## Contributing

Grimnir's tracked files are generic by policy: no target names, credentials, or operator
data. See **[CONTRIBUTING.md](CONTRIBUTING.md)** before opening a pull request.

## License and use

MIT, see **[LICENSE](LICENSE)**. Built for authorized security testing, bug-bounty, and
research use only. **Only test systems you have written authorization to test.**
