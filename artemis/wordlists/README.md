# ARTEMIS Wordlists Reference

All wordlists use **one payload per line** format. Lines starting with `#` are comments. Blank lines are skipped. Scripts parse with `grep -cv '^#\|^$'`.

## Core Testing Wordlists

| File | Entries | Category | Primary Script |
|------|---------|----------|---------------|
| `prompt-injection-payloads.txt` | ~120 | LLM01 — Direct & indirect prompt injection | `prompt-injection-spray.sh` |
| `jailbreak-prefixes.txt` | ~80 | LLM01 — Jailbreak prefixes and role-play personas | `prompt-injection-spray.sh` |
| `system-prompt-extractors.txt` | 35 | LLM07 — System prompt extraction | `system-prompt-extract.sh` |
| `encoding-bypasses.txt` | 16 | LLM01 — Encoding-based injection bypass templates | `prompt-injection-spray.sh` |
| `role-play-personas.txt` | 20 | LLM01 — Persona-based jailbreak identities | `prompt-injection-spray.sh` |
| `guardrail-test-topics.txt` | 40 | Guardrails — Content filter boundary testing | `guardrail-probe.sh` |
| `sensitive-data-probes.txt` | 35 | LLM02 — Sensitive data extraction probes | `system-prompt-extract.sh` |

## RAG-Specific Wordlists (added 2026-06-13)

| File | Entries | Category | Primary Script |
|------|---------|----------|---------------|
| `rag-poisoning-payloads.txt` | ~65 | LLM04/LLM08 — Document injection, hidden text, instruction override | `rag-poisoning-spray.sh` |
| `embedding-manipulation.txt` | ~45 | LLM08 — Retrieval optimization, embedding probes, similarity bypass | `rag-poisoning-spray.sh` |
| `chunk-boundary-exploits.txt` | ~30 | LLM04/LLM08 — Cross-chunk chains, sliding window exploits | `rag-poisoning-spray.sh` |
| `rag-document-leakage.txt` | ~70 | LLM02/LLM07 — Document enumeration, extraction, metadata, cross-tenant | `rag-document-extract.sh` |

## Agent & API Wordlists

| File | Entries | Category | Primary Script |
|------|---------|----------|---------------|
| `agent-tool-names.txt` | 65 | ASI02 — Common agent tool/function names | `agent-tool-enum.sh` |
| `llm-api-endpoints.txt` | 67 | Recon — LLM API endpoint paths | `llm-recon.sh` |

## MCP (Model Context Protocol) Wordlists (added 2026-07-09)

| File | Category | Primary Script |
|------|----------|---------------|
| `mcp-command-injection.txt` | MCP05 — OS command injection into tool params (OOB + reflected) | `mcp-probe.sh` (mode cmdinj) |
| `mcp-ssrf.txt` | MCP05 — SSRF / IMDS / URL-fetch targets | `mcp-probe.sh` (mode ssrf) |
| `mcp-path-traversal.txt` | MCP05 — path traversal / arbitrary file read | `mcp-probe.sh` (mode traversal) |
| `mcp-tool-poisoning.txt` | MCP03 — poisoning payloads / detection signatures | `mcp-poison-scan.py`, injection when a tool is attacker-registerable |
| `mcp-shadow-paths.txt` | MCP09 — shadow MCP endpoint discovery paths | `mcp-shadow-scan.sh` |

MCP05 payloads use placeholders substituted at fire time: `{{OOB}}` (full callback
URL), `{{OOBHOST}}` (host:port), `{{NONCE}}` (correlation id). Without `--oob-base`
the probe skips the blind OOB payloads and runs only reflected/target ones.

## Format

```
# Section comment
payload one
payload two
payload three

# Another section
payload four
```

Scripts skip `#` lines and blank lines. Each non-comment line is one payload sent to the target.

## Adding New Wordlists

1. Create `<name>.txt` in this directory
2. Follow the one-per-line format with `#` section headers
3. Add an entry to this README
4. If you create a corresponding script, follow the pattern in `scripts/`
