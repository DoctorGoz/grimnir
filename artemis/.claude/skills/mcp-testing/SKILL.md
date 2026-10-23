---
name: mcp-testing
description: OWASP MCP Top 10 testing playbook for Model Context Protocol servers. Enumerate a remote MCP server, then route each of the ten risks to the right ARTEMIS/Specter technique. Use when a target exposes an MCP endpoint (tools/resources/prompts over JSON-RPC).
allowed-tools: Read, Grep, Glob, Bash
---

# MCP Server Testing Skill (OWASP MCP Top 10)

## When to Use
- A target exposes an MCP endpoint (streamable-HTTP or HTTP+SSE) — often surfaced by HUGINN
  recon, a JS bundle referencing an MCP client, or an "agent/tools" feature in a SaaS product.
- You see JSON-RPC 2.0 with `tools/list`, `resources/list`, `prompts/list`, or `Mcp-Session-Id`.
- Assessing MCP01-MCP10 against a discovered server.

The MCP server is usually a thin wrapper over a backend API. **Route discovered tools, endpoints,
and secrets to Specter (API) and Nimbus (cloud).**

## Step 1 — Always Enumerate First

    # Authenticated enumeration (recommended: pass the engagement's auth + proxy)
    bash scripts/mcp-enum.sh https://target/mcp \
      --auth "Authorization: Bearer <token>" \
      --project-dir "$PROJECT_DIR" --proxy "$PROXY"

    # Unauthenticated (tests MCP07/MCP09 exposure)
    bash scripts/mcp-enum.sh https://target/mcp --project-dir "$PROJECT_DIR"

Outputs (`$PROJECT_DIR/artemis/recon/mcp-enum-<ts>/`):
- `mcp-inventory.md` — server info, tools (+poisoning flags), resources, prompts, Top-10 hints
- `mcp-assets.json` — machine-readable asset-map fragment (route to other agents)
- `mcp-raw.jsonl` — raw JSON-RPC responses

If `initialize` fails, retry with/without `--auth` and try alternate paths (`/mcp`, `/sse`,
`/message`, `/.well-known/mcp`) — a reachable undeclared server is MCP09.

## Step 2 — Route Each Risk (read `references/owasp-mcp-top10.md` for procedures)

| Risk | Do this | Tool / skill |
|------|---------|--------------|
| MCP05 Command Injection **(lead here)** | Fuzz string tool params with shell metachars + OOB triggers | `mcp-probe.sh`, `scripts/confirm/mcp-confirm.py`, `oob-listener.py`, `dns-rebind.py` |
| MCP02 Privilege Escalation / Scope Creep | 4-way BOLA/BFLA on id/account/org/path tool params (incl. `atz` server-injected params from enum); call privileged-looking tools as low-priv | `scripts/confirm/mcp-confirm.py authz` |
| MCP10 Context Injection & Over-Sharing | Two identities: can B read A's context/resources? | `mcp-confirm.py authz`, `data-exfiltration` |
| MCP01 Secret Exposure | Grep inventory + read resources + malformed calls for secrets | `mcp-call.sh`, `data-exfiltration` |
| MCP03 Tool Poisoning | Score descriptions, decode invisible chars, diff two enums for rug pulls; prove attacker can introduce/alter | `mcp-poison-scan.py` |
| MCP06 Intent Flow Subversion | Plant injection in tool results/resources the agent reads | `prompt-injection` |
| MCP07 Insufficient AuthN/AuthZ | Enumerate + call with no/forged/expired token | `mcp-enum.sh` (no `--auth`) |
| MCP09 Shadow Servers | Probe subdomains/paths for undeclared MCP endpoints; grep JS for MCP client URLs | `mcp-shadow-scan.sh` + HUGINN recon |
| MCP04 Supply Chain | Note referenced packages/registries for takeover | HUGINN |
| MCP08 Audit/Telemetry | Advisory only — NOT a standalone submittable finding | — |

## Step 3 — Active Testing Loop (MCP05 / MCP02 — the paying lanes)

Enumeration is read-only; findings come from exercising tools. Keep it bounded
(the harm-check + "no exploitation beyond confirmation" rules apply).

**MCP05 — command / SSRF injection (top lane).** Run the OOB listener, then let the
probe walk every string param with the payload sets, weaving in a callback nonce so
BLIND execution is caught (not just reflected output):

```bash
python3 scripts/confirm/oob-listener.py &        # or the always-on systemd service
ASSETS=$(ls -dt "$PROJECT_DIR"/artemis/recon/mcp-enum-*/mcp-assets.json | head -1)
bash artemis/scripts/mcp-probe.sh https://target/mcp --assets "$ASSETS" \
  --auth "Authorization: Bearer <t>" --oob-base http://<listener-ip>:18080 \
  --project-dir "$PROJECT_DIR" --proxy "$PROXY"
# review probe-report.md: SIGNAL (reflected exfil), OOB fires (poll to confirm), anomalies
```

Confirm a hit into an evidence-gate artifact:

```bash
GRIMNIR_OOB_BASE=http://<listener-ip>:18080 \
python3 scripts/confirm/mcp-confirm.py ssrf --finding-id ART-NNN \
  --project-dir "$PROJECT_DIR" --base-url https://target/mcp \
  --auth "Authorization: Bearer <t>" --tool fetch --param url   # -> evidence/<id>/verdict.json
```

**MCP02 / MCP10 — cross-object / cross-tenant tool call.** 4-way differential over a
tool call with the attacker's creds; `confirmed` requires the victim's distinguishable data:

```bash
python3 scripts/confirm/mcp-confirm.py authz --finding-id ART-NNN \
  --project-dir "$PROJECT_DIR" --base-url https://target/mcp \
  --auth "Authorization: Bearer <attacker>" --tool get_record --id-param recordId \
  --own-id 1001 --victim-id 1002 --nonexistent-id 999999 --victim-marker 'Lucinda'
# -> evidence/<id>/authz.json  (the negative control the gate consumes)
```

For any `atz` param the enum flagged (server-injected authz), run the same authz check
with that param as `--id-param`: if the client value is honored, it is a privilege bypass.

**Schema-driven fuzz (opt-in).** `mcp-fuzz.py` sends a fixed payload set (traversal, command and
template injection, SSRF callback, oversized and type-confusion values) to every string parameter,
capped per tool. It CALLS the server's tools, so it refuses without
`--i-understand-this-calls-tools` and skips tools that look destructive or outbound. With
`--project-dir` it refuses when the program's `roe.json` bans automated scanning, paces every
request through `roe.py`, and rides the egress proxy. Signals are leads: confirm each with
`mcp-confirm.py` and a negative control.

```bash
python3 artemis/scripts/mcp-fuzz.py https://target/mcp --i-understand-this-calls-tools \
  --project-dir "$PROJECT_DIR" --auth "Authorization: Bearer <t>" --oob-base http://<listener-ip>:18080
```

## Standalone build (one-way flow)

The MCP scripts above, `mcp-confirm.py`, the wordlists and the offline fixture-server tests
(`tests/test_mcp_kit.py`) are the upstream of the standalone `mcptester` kit. The kit is generated
from this repo with `python3 release/build.py --target mcptester --out DIR` (manifest
`release/mcptester.toml`, standalone-only files in `release/overlay/mcptester/`) and is never
edited by hand: fix the script here, rebuild. Keep the egress and project-dir layers optional
(`egress-layer` / `project-dir-layer` marker comments in the scripts) because the build strips them.
Client-config discovery and per-scan SARIF output exist only in the standalone build.

## Success Criteria
An MCP finding is real only when it crosses a **privilege or tenancy boundary** with effect:
- A tool call executes a command / reaches internal resources (MCP05)
- A client reads/writes another tenant's or user's data via a tool/resource (MCP02/MCP10)
- An attacker-controllable poisoned tool description is consumed by another party's agent (MCP03)

An injection that merely "fires" against your own context, or context change with no security
effect, is a NEGATIVE — log it (`scripts/event-emitter.sh record-negative`), do not report it
(see `rules/never-submit.md` and `rules/hunting.md`).

## Output
Document: the tool/method called, exact params, request/response, the boundary crossed, and the
negative control. Route backend endpoints/secrets to Specter/Nimbus via intel (`--tag needs-specter`).

## Validate & Promote

Findings are born `theoretical` and follow the repo-root validation gate. Class-specific checks:
- **MCP02/MCP10 (authz):** negative control via `authz-confirm.py` — cross returns the victim's
  distinguishable data.
- **MCP05 (command/SSRF):** out-of-band proof via `oob-listener.py` (+ `dns-rebind.py`).
- **MCP03 (poisoning):** raw hidden bytes + a path by which another party consumes the description.

```bash
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent artemis \
  --id ART-NNN --state confirmed --method <oob|authz-differential|manual-repro> \
  --negative-control "<what you proved, and the control result>" --by artemis
```

Only `confirmed` findings ship. The evidence gate hard-blocks High/Critical without the artifact.
