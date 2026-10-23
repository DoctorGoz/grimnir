---
name: resource-exhaustion
description: LLM resource exhaustion and denial-of-service testing. Covers token flooding, recursive generation, context window abuse, and cost amplification attacks.
allowed-tools: Read, Grep, Glob, Bash
---

# Resource Exhaustion Testing Skill

## When to Use
- OWASP LLM10 (Unbounded Consumption) assessment; MITRE ATLAS: Denial of ML Service / Cost Harvesting
- Testing rate limits and resource controls
- Evaluating cost management and abuse prevention

## Attack Vectors

### Token Flooding
- Send maximum-length inputs to consume token quota
- Generate maximum-length outputs: "Write a 10000 word essay on..."
- Test if input/output token limits are enforced
- Calculate cost per request and estimate abuse potential

### Recursive Generation
- "Generate a prompt that generates a prompt that generates..."
- Request self-referential content that causes processing loops
- Test if recursion depth limits exist

### Context Window Abuse
- Fill context window with junk to push out system prompt
- Test behavior when context is exactly at the limit
- Send inputs that cause maximum internal expansion (e.g., "expand each word into a paragraph")

### Concurrent Request Flooding
- Test rate limits with parallel requests
- Identify per-user vs per-IP vs global limits
- Test if rate limit bypasses exist (header manipulation, API key rotation)

### Cost Amplification
- Identify the most expensive operations (embeddings, fine-tuning, tool calls)
- Calculate amplification factor: cost-to-attacker vs cost-to-target
- Test if billing alerts and spending caps are configured

### Embedding/Vector Abuse
- Flood vector database with junk embeddings
- Test storage limits on vector DB
- Submit inputs that generate maximum embedding dimensions

## Testing Ethics
- NEVER cause actual denial of service without explicit authorization
- Start with low-volume tests and scale gradually
- Monitor target system health during testing
- Stop immediately if degradation is observed

## Output
Attack vector, resource consumed, rate limit findings, cost analysis, severity.

## Validate & Promote

Findings from this skill are born `theoretical` (see the validation layer in the repo-root `CLAUDE.md`). They do NOT enter a report or external submission until promoted to `confirmed` with `scripts/validate-finding.sh`, after the independent check below.

- **Independent check for this class:** Show measurable cost/latency/quota impact vs a baseline request, not a one-off slow response.
- **Automated confirm:** for the concurrent-flood / rate-limit lane, `scripts/confirm/race-confirm.py` proves the limiter was exceeded (successes above the expected max vs a sequential control); cost/latency is measured attack-vs-baseline.
- Only `confirmed` findings ship. `validated` = reproduced but not independently confirmed.

```bash
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent artemis \
  --id ART-NNN --state confirmed --method manual-repro \
  --negative-control "<what you proved, and the control result>" --by artemis
```
