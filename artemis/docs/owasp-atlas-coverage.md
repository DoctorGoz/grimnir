# ARTEMIS coverage matrix — OWASP LLM / Agentic + MITRE ATLAS

A living traceability map: each framework category -> the ARTEMIS skill that tests it -> the tool ->
the confirm harness that proves it. Re-check when the frameworks move (they do — the Agentic list was
renumbered for 2026). `GAP` = no skill; `partial` = covered but shallow or unlabeled.

- Frameworks verified live: **OWASP Top 10 for LLM Applications (2025)**, **OWASP Top 10 for Agentic
  Applications (2026)** (published 2025-12-09), **MITRE ATLAS**.
- Last verified / updated: 2026-09-29.

## OWASP LLM Top 10 (2025)

| Cat | Name | Skill(s) | Tool | Confirm harness | Status |
|-----|------|----------|------|-----------------|--------|
| LLM01 | Prompt Injection | prompt-injection, multi-turn-attack | prompt-injection-spray.sh | llm-confirm.py `--mode injection` | solid |
| LLM02 | Sensitive Information Disclosure | data-exfiltration | — | llm-confirm.py `--mode extraction` | solid |
| LLM03 | Supply Chain | — | — | — | **GAP** (mostly SDLC/deps; low live-BB yield) |
| LLM04 | Data & Model Poisoning | rag-poisoning | rag-poisoning-spray.sh | llm-confirm.py `--mode injection` | partial (black-box limits) |
| LLM05 | Improper Output Handling | output-handling | output-xss-test.sh | render-confirm.py (+ llm-confirm injection) | solid |
| LLM06 | Excessive Agency | agent-abuse | agent-tool-enum.sh | mcp-confirm.py | solid (via Agentic) |
| LLM07 | System Prompt Leakage | system-prompt-extraction | system-prompt-extract.sh | llm-confirm.py `--mode extraction` | solid |
| LLM08 | Vector & Embedding Weaknesses | rag-poisoning | — | — | **partial** — embedding-inversion / cross-context depth still thin |
| LLM09 | Misinformation | — | — | — | **GAP** (hallucination-as-vuln, package hallucination) |
| LLM10 | Unbounded Consumption | resource-exhaustion | — | race-confirm.py (concurrent lane) | partial — labeled, cost/quota proof still manual |

## OWASP Top 10 for Agentic Applications (2026)

All in the `agent-abuse` skill (rewritten to the 2026 taxonomy 2026-09-29).

| Cat | Name | Status |
|-----|------|--------|
| ASI01 | Agent Goal Hijack | solid |
| ASI02 | Tool Misuse and Exploitation | solid (+ mcp-testing) |
| ASI03 | Identity and Privilege Abuse | solid |
| ASI04 | Agentic Supply Chain Vulnerabilities | added (was mislabeled "Uncontrolled Actions") |
| ASI05 | Unexpected Code Execution (RCE) | added (was mislabeled "Multi-Agent Attacks") — high value |
| ASI06 | Memory & Context Poisoning | solid |
| ASI07 | Insecure Inter-Agent Communication | added |
| ASI08 | Cascading Failures | added |
| ASI09 | Human-Agent Trust Exploitation | added (low automated testability — document the mechanism) |
| ASI10 | Rogue Agents | relabeled to 2026 meaning |

## MCP

`mcp-testing` (OWASP MCP Top 10) is the best-shaped skill and already wires `scripts/confirm/mcp-confirm.py`.
See also the `mcp-tool-authz` playbook.

## MITRE ATLAS

Skills now carry ATLAS technique **names** where they map (LLM Prompt Injection, LLM Jailbreak, LLM Data
Leakage, Denial of ML Service, Cost Harvesting, Discover ML Model Family). `report-generator` maps
findings to ATLAS tactics. **Deferred:** stamping exact `AML.Txxxx` IDs — verify each against the live
ATLAS matrix before asserting an ID (names are stable, IDs were not confirmed this pass).

## Done this pass (2026-09-29)

- `agent-abuse` rewritten to Agentic 2026 (closed ASI04/05/07/08/09, relabeled ASI04/05/10).
- Wired `llm-confirm.py` into prompt-injection, system-prompt-extraction, guardrail-bypass,
  data-exfiltration, output-handling, rag-poisoning; noted the multi-turn final-turn use.
- Added framework anchoring to the previously unlabeled skills (guardrail-bypass, jailbreak-testing,
  multi-turn-attack, resource-exhaustion, model-fingerprinting).

## Deferred / revisit (next skills-depth session)

- **Sub-agent defs still on the OLD ASI taxonomy** — `artemis/.claude/agents/agent-abuse-tester.md`
  (and check the other tester defs) mirror the pre-2026 ASI list; remap them the same way the skill was.
- **LLM08 embedding depth** — a dedicated embedding-inversion / cross-context-leakage procedure beyond
  the current rag-poisoning bullets.
- **LLM10 cost proof** — a small quota/cost-amplification measurement harness (vs manual measurement).
- **LLM03 / LLM09 / ASI09** — real categories, low live-BB yield; add lightweight procedures only if a
  target warrants them.
- **MITRE ATLAS exact IDs** — stamp verified `AML.Txxxx` per skill.
- **PyRIT adoption decision** — only if automated multi-turn attack generation proves a gap our
  `multi-turn-attack` skill + promptfoo/garak don't cover.
