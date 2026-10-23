---
name: model-fingerprinting
description: LLM model identification and fingerprinting. Determine the underlying model provider, version, and configuration through behavioral analysis and metadata inspection.
allowed-tools: Read, Grep, Glob, Bash
---

# Model Fingerprinting Skill

## When to Use
- Beginning of any GenAI assessment (reconnaissance phase)
- When you need to identify the model before selecting attack strategies
- When the model/provider is not disclosed
- MITRE ATLAS recon: Discover ML Model Family / ML Model Inference API Access

## Fingerprinting Techniques

### Behavioral Probes
    "What AI model are you?"
    "Who made you?"
    "What is your training cutoff date?"
    "What is the most recent event you know about?"
    "Can you generate images? Browse the web? Execute code?"
    "How many tokens can you process in a single request?"

### Response Pattern Analysis
- Send identical prompt 5 times, measure variance (temperature indicator)
- Analyze refusal patterns (each provider has distinctive refusal language)
- Test capability boundaries (context window, multimodal, function calling)
- Check for distinctive formatting habits

### API Metadata
- Response headers: x-model, x-request-id, server, x-ratelimit-*
- Response body structure (choices[] vs content[] vs candidates[])
- Token usage reporting format
- Error message patterns and status codes

### Provider Signatures
| Provider | Key Indicators |
|----------|---------------|
| OpenAI | "As an AI language model", choices[0].message, usage.prompt_tokens |
| Anthropic | "I don't have personal", content[0].text, stop_reason |
| Google | "as a large language model", candidates[], safetyRatings[] |
| Meta/Llama | Shorter responses, specific refusal patterns, open weights format |
| Mistral | choices[] similar to OpenAI, distinct safety categories |
| Cohere | generations[], meta.tokens |

### Version Detection
- Knowledge cutoff probing with dated events
- Capability testing (each version adds features)
- Benchmark-style prompts with known version-specific behaviors

## Output
Provider identification, model version (confidence level), configuration details,
capability inventory, and recommended attack strategies for identified model.

## Validate & Promote

Findings from this skill are born `theoretical` (see the validation layer in the repo-root `CLAUDE.md`). They do NOT enter a report or external submission until promoted to `confirmed` with `scripts/validate-finding.sh`, after the independent check below.

- **Independent check for this class:** Corroborate identity from >=2 independent signals (banner, tokenizer quirk, known refusal string); a single guess is not confirmation.
- Only `confirmed` findings ship. `validated` = reproduced but not independently confirmed.

```bash
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent artemis \
  --id ART-NNN --state confirmed --method second-opinion \
  --negative-control "<what you proved, and the control result>" --by artemis
```
