Run complete GenAI security audit against $ARGUMENTS

Orchestrates all subagents through the full ARTEMIS methodology.

## Phase 1: Reconnaissance (recon-agent)
Model fingerprinting, API mapping, guardrail identification, tool enumeration

## Phase 2: System Prompt Extraction (data-extraction-tester)
LLM07 — Extract and document system prompt and configuration

## Phase 3: Prompt Injection Testing (prompt-injection-tester)
LLM01 — Direct, indirect, encoding, multi-turn injection attacks

## Phase 4: Guardrail Assessment (jailbreak-tester)
Safety filter effectiveness across all content categories

## Phase 5: Data Extraction Testing (data-extraction-tester)
LLM02 — Training data, PII, RAG documents, credentials, conversation history

## Phase 6: Output Handling Testing (output-handling-tester)
LLM05 — XSS, injection, SSRF through model-generated output

## Phase 7: Agentic Testing (agent-abuse-tester) — if applicable
ASI01-ASI10 — Goal hijacking, tool misuse, privilege escalation, memory attacks

## Phase 8: Resource & Abuse Testing (main agent)
LLM10 — Rate limits, token flooding, cost amplification

## Phase 9: Reporting (report-generator)
Compile findings, deduplicate, severity classification, generate report

Save to engagement directory. Run: bash scripts/full-genai-audit.sh $ARGUMENTS
