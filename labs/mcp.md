# Lab: a vulnerable MCP server (tool poisoning, shadowing, tool-call authz)

Model Context Protocol (MCP) servers expose tools and resources to AI agents over JSON-RPC.
Grimnir's ARTEMIS agent ships an MCP toolchain that enumerates a server read-only, scores
tool-description poisoning and cross-server shadowing, and confirms a finding through an actual
tool call. This lab drives that chain against a deliberately vulnerable MCP server.

## 1. Start the lab

Point the tools at any MCP endpoint you are authorized to test. For a self-contained local
target, a deliberately vulnerable server such as the
[Damn Vulnerable MCP Server](https://github.com/harishsg993010/damn-vulnerable-MCP-server)
works well; follow its README to run it on your isolated host. Note the endpoint URL it serves
(for example `http://localhost:9000/mcp`); the commands below use `$MCP_URL` for it.

```bash
export MCP_URL=http://localhost:9000/mcp     # your lab's actual MCP endpoint
```

The transport is streamable HTTP by default; the tools fall back to the legacy HTTP+SSE
transport automatically.

## 2. Engage

```bash
cd ~/workspace/grimnir && claude
```

```
/engage mcp-lab
```

Describe it as "an MCP server at $MCP_URL, authorized local lab." A JSON-RPC `/mcp` endpoint
classifies as an MCP target (ARTEMIS lead). For a local lab, leave `GRIMNIR_PROXY` unset.

## 3. Enumerate read-only

`mcp-enum.sh` runs the read-only handshake (`initialize` ->
`notifications/initialized` -> `tools/list` -> `resources/list` -> `prompts/list`), dumps every
tool description and input schema, and writes an `mcp-assets.json` asset fragment with per-item
OWASP MCP Top 10 hints.

```bash
PROJECT_DIR=~/workspace/mcp-lab
bash artemis/scripts/mcp-enum.sh "$MCP_URL" --project-dir "$PROJECT_DIR"
```

## 4. Score poisoning and shadowing

`mcp-poison-scan.py` turns the boolean poisoning flags into a weighted risk score, decodes
invisible characters to their codepoints, and detects cross-server tool shadowing when given
more than one enumeration. `mcp-shadow-scan.sh` is the dedicated shadowing check across a set
of servers.

```bash
python3 artemis/scripts/mcp-poison-scan.py scan \
  "$PROJECT_DIR/artemis/recon/"*/mcp-assets.json --project-dir "$PROJECT_DIR"
```

> **Reality check (and why this matters for what you submit).** On a first-party target, a
> poisoned tool description is usually vendor-by-design and not a reportable vulnerability on
> its own. It pays only when an attacker can **introduce or alter** a description that another
> party's agent will consume, or when a **rug pull** changes a tool after a user approved it
> (`mcp-poison-scan.py diff --baseline ... --current ...`). The score prioritizes review; you
> still have to show the consumption path. This is the never-submit discipline doing its job.

## 5. Confirm a tool-call authz bug

The bug that does stand on its own is broken authorization on a tool call: a tool that returns
another tenant's object when you change an id argument (OWASP MCP02 / MCP10). `mcp-confirm.py`
runs the same 4-way differential the REST BOLA lane uses, but the trigger is a JSON-RPC
`tools/call`, and it writes the same `authz.json` the evidence gate consumes.

```bash
python3 scripts/confirm/mcp-confirm.py authz --finding-id ART-001 --project-dir "$PROJECT_DIR" \
  --base-url "$MCP_URL" --auth "Authorization: Bearer {ATTACKER_TOKEN}" \
  --tool get_record --id-param recordId \
  --own-id 1001 --victim-id 1002 --nonexistent-id 999999 \
  --victim-marker '{VICTIM_ONLY_STRING}'
```

Then record and promote, exactly as in the REST labs:

```bash
bash scripts/finding.sh --project-dir "$PROJECT_DIR" --agent artemis --class bola \
  --title "MCP tool get_record returns another tenant's object" --severity high
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent artemis \
  --id ART-001 --from-evidence
```

For a tool that fetches a URL, `mcp-confirm.py ssrf` fires a unique out-of-band nonce *through*
the tool call and polls the listener, proving blind SSRF through the MCP layer. Start
`scripts/confirm/oob-listener.py` first; see `scripts/confirm/README.md`.

## What you should see

- `mcp-enum.sh` prints the tool catalog and writes `mcp-assets.json`. A server that does not
  complete the handshake is not MCP at this path; try `--transport sse` or a fallback host.
- `mcp-poison-scan.py` ranks the tools by risk and names the signals (invisible characters,
  imperative instructions aimed at the agent, overbroad scopes).
- `mcp-confirm.py authz` writes `evidence/ART-001/authz.json` with `verdict: confirmed` only
  when the cross-tenant call returns the victim's marked data; a uniform response is `negative`.

## Tear down

Stop the vulnerable MCP server per its own instructions.
