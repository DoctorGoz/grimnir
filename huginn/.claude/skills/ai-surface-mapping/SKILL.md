---
name: ai-surface-mapping
description: Detect and classify AI/LLM surface — chat widgets, AI APIs, RAG, agents — and (critically) identify the vendor before routing to ARTEMIS. HUGINN Phase 5.
allowed-tools: Read, Grep, Glob, Bash
---

# AI Surface Mapping Skill (HUGINN Phase 5)

Find the AI/LLM attack surface and classify it so ARTEMIS is dispatched only at
*in-scope, first-party* AI. The expensive mistake is firing ARTEMIS at a
third-party widget that is out of scope or isn't even an LLM.

## Methodology

### Step 1: Detect AI indicators
Chat widgets, "Ask AI"/copilot buttons, `/ai/`, `/chat`, `/assistant`,
`/completions`, `/v1/chat`, streaming (SSE) endpoints, generative triggers
(summaries, recommendations), RAG/citation features, file-upload-then-answer.

### Step 2: Identify the VENDOR (decisive)
Inspect the widget's network calls and JS. Is it first-party, or a third-party
SaaS (Intercom/Drift/Sierra/DigitalCX/Zendesk/etc.)? Many "chatbots" are scripted
FAQ bots, not LLMs, and many SaaS widgets are out of scope.

### Step 3: Classify behaviour
Real LLM (free-form generation) vs scripted/intent bot? Does it have data access /
tools / memory (agentic)? Note model hints (headers, error strings).

### Step 4: Scope check
Confirm the AI endpoint/host is in the program scope before recommending ARTEMIS.

### Step 5: MCP shadow-server discovery (MCP09)
Agentic/"tools" features often expose a Model Context Protocol server. Look for MCP
client references in JS bundles (`js-secret-patterns.txt` now flags `modelcontextprotocol`,
`McpClient`, `/mcp`, `/sse`, `.well-known/mcp`, `mcpServers`) and fuzz for undeclared
MCP endpoints across in-scope hosts:

```bash
bash artemis/scripts/mcp-shadow-scan.sh https://target.example \
  --js-dir "$PROJECT_DIR/recon/js" --project-dir "$PROJECT_DIR"
```

Any candidate endpoint → enumerate with `artemis/scripts/mcp-enum.sh` and route
`needs-artemis` (an unauth/default-cred reachable MCP server with usable tools is
MCP09 High/Critical). A reachable-but-fully-authed server is Low/Info.

## Output to record
ai_indicators[]: type, vendor, first_party (bool), in_scope (bool), is_llm (bool),
has_tools, endpoint → `asset-map.json` `ai_indicators`.

## Log & Route
HUGINN produces **intel and an asset map**, not findings. Route to ARTEMIS ONLY first-party, in-scope, actual LLMs.

```bash
bash scripts/intel.sh add --project-dir "$PROJECT_DIR" --agent huginn \
  --type technology --confidence confirmed --name "First-party RAG assistant" \
  --tech-category ai --tag needs-artemis --tag high-value
```
First-party in-scope LLM → `needs-artemis`. Third-party/OOS/non-LLM widget → record with `first_party:false`/`in_scope:false` and do NOT route (see the operator rule on embedded chatbots). The API layer behind an AI feature → also `needs-specter`.
