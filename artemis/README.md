# ARTEMIS — GenAI Red Teaming & Penetration Testing Agent

**AI Red Team Engagement, Methodology, and Intelligence System**

A Claude Code agent for conducting professional-grade penetration tests against GenAI/LLM systems, grounded in industry-standard frameworks.

---

## Frameworks & Standards

- **OWASP GenAI Red Teaming Guide** (v1.0, January 2025)
- **OWASP Top 10 for LLM Applications** (2025) — LLM01 through LLM10
- **OWASP Top 10 for Agentic Applications** (2026) — ASI01 through ASI10
- **MITRE ATLAS** — Adversarial Threat Landscape for AI Systems
- **NIST AI RMF** — AI Risk Management Framework
- **EU AI Act** — Regulatory compliance considerations

---

## Quick Start

### As a Claude Code Agent
1. `cd` into the `genai-redteam-agent/` directory
2. Run `claude` — it reads `CLAUDE.md` as the agent system prompt
3. Start with `/scope` to begin an engagement

### Slash Commands
```
/scope <target>              — Define engagement scope and test plan
/recon <target>              — GenAI system reconnaissance
/assess [category]           — Vulnerability assessment (LLM01-10, ASI01-10, or all)
/test-prompt-injection <url> — Prompt injection testing (LLM01)
/test-jailbreak <url>        — Guardrail bypass testing
/test-data-extraction <url>  — Data extraction testing (LLM02, LLM07)
/test-agent-abuse <url>      — Agentic abuse testing (ASI01-10)
/test-system-prompt <url>    — System prompt extraction (LLM07)
/test-guardrails <url>       — Content filter assessment
/full-audit <url>            — Complete security audit (all phases)
/report                      — Generate findings report
```

### Standalone Scripts
```bash
bash scripts/llm-recon.sh https://api.target.com/v1 [API_KEY]
bash scripts/prompt-injection-spray.sh https://api.target.com/v1/chat/completions
bash scripts/system-prompt-extract.sh https://api.target.com/v1/chat/completions
bash scripts/guardrail-probe.sh https://api.target.com/v1/chat/completions
bash scripts/agent-tool-enum.sh https://api.target.com/v1/chat/completions
bash scripts/full-genai-audit.sh https://api.target.com/v1/chat/completions [API_KEY] [ENG_ID]
```

---

## Architecture

```
genai-redteam-agent/
├── CLAUDE.md                              # Agent identity, rules, methodology
├── SKILL.md                               # Skill metadata and triggering
├── README.md                              # This file
│
├── .claude/                               # Claude Code integration
│   ├── settings.json                      # Permissions, hooks, safety guards
│   ├── agents/                            # 7 specialized subagents
│   │   ├── recon-agent.md                 #   Model fingerprinting, API mapping
│   │   ├── prompt-injection-tester.md     #   LLM01 — injection attacks
│   │   ├── jailbreak-tester.md            #   Guardrail bypass testing
│   │   ├── data-extraction-tester.md      #   LLM02/LLM07 — data leakage
│   │   ├── agent-abuse-tester.md          #   ASI01-10 — agentic attacks
│   │   ├── output-handling-tester.md      #   LLM05 — output injection
│   │   └── report-generator.md            #   Report compilation
│   ├── commands/                          # 11 slash commands
│   │   ├── scope.md                       #   /scope
│   │   ├── recon.md                       #   /recon
│   │   ├── assess.md                      #   /assess [category]
│   │   ├── test-prompt-injection.md       #   /test-prompt-injection
│   │   ├── test-jailbreak.md              #   /test-jailbreak
│   │   ├── test-data-extraction.md        #   /test-data-extraction
│   │   ├── test-agent-abuse.md            #   /test-agent-abuse
│   │   ├── test-system-prompt.md          #   /test-system-prompt
│   │   ├── test-guardrails.md             #   /test-guardrails
│   │   ├── full-audit.md                  #   /full-audit
│   │   └── report.md                      #   /report
│   └── skills/                            # 11 tactical playbooks
│       ├── prompt-injection/              #   Core injection testing
│       ├── jailbreak-testing/             #   Guardrail bypass methods
│       ├── system-prompt-extraction/      #   System prompt leak testing
│       ├── data-exfiltration/             #   Sensitive data extraction
│       ├── agent-abuse/                   #   Agentic system attacks
│       ├── output-handling/               #   Output injection testing
│       ├── rag-poisoning/                 #   RAG/retrieval attacks
│       ├── model-fingerprinting/          #   Model identification
│       ├── guardrail-bypass/              #   Filter bypass techniques
│       ├── multi-turn-attack/             #   Multi-turn escalation
│       └── resource-exhaustion/           #   DoS/resource abuse
│
├── references/                            # Assessment procedure references
│   ├── owasp-llm-top10.md                #   LLM01-LLM10 test procedures
│   ├── owasp-agentic-top10.md            #   ASI01-ASI10 test procedures
│   ├── redteam-methodology.md            #   Overall methodology
│   ├── payload-library.md                #   Categorized test payloads
│   └── threat-modeling.md                #   AI threat modeling guide
│
├── templates/                             # Document templates
│   ├── scope-template.md                 #   Engagement scoping
│   ├── finding-template.md               #   Individual finding report
│   ├── report-template.md                #   Full pentest report
│   └── test-plan-template.md             #   Test plan / checklist
│
├── scripts/                               # Automation scripts
│   ├── llm-recon.sh                      #   GenAI recon pipeline
│   ├── prompt-injection-spray.sh         #   Spray injection payloads
│   ├── system-prompt-extract.sh          #   Extract system prompts
│   ├── guardrail-probe.sh               #   Test guardrail effectiveness
│   ├── agent-tool-enum.sh               #   Enumerate agent tools
│   ├── output-xss-test.sh               #   Test XSS in LLM output
│   ├── full-genai-audit.sh              #   Orchestrate full audit
│   ├── init-engagement.sh               #   Initialize engagement workspace
│   └── new-finding.sh                    #   Create finding from template
│
├── wordlists/                             # Curated test wordlists
│   ├── prompt-injection-payloads.txt     #   28 core injection payloads
│   ├── jailbreak-prefixes.txt            #   29 jailbreak prompt prefixes
│   ├── system-prompt-extractors.txt      #   35 extraction prompts
│   ├── encoding-bypasses.txt             #   Encoded payload variants
│   ├── role-play-personas.txt            #   20 personas for role-play attacks
│   ├── sensitive-data-probes.txt         #   35 data extraction probes
│   ├── agent-tool-names.txt              #   60+ common tool/function names
│   ├── guardrail-test-topics.txt         #   40 content filter test topics
│   └── llm-api-endpoints.txt             #   65+ common LLM API paths
│
├── docs/                                  # Reference documentation
│   ├── tool-quick-reference.md           #   Tool command cheat sheet
│   ├── attack-decision-tree.md           #   Attack strategy by target type
│   └── llm-provider-fingerprints.md      #   Model identification signatures
│
└── prompts/                               # Integration prompts
    └── pm-agent-integration.md           #   PM orchestrator protocol
```

---

## Coverage

### OWASP LLM Top 10 (2025)
| ID | Risk | Subagent | Tests |
|----|------|----------|-------|
| LLM01 | Prompt Injection | prompt-injection-tester | 6 test procedures, 20+ payload variants |
| LLM02 | Sensitive Information Disclosure | data-extraction-tester | 5 test procedures |
| LLM03 | Supply Chain | Main agent + semgrep | 4 test procedures |
| LLM04 | Data and Model Poisoning | Main agent | 3 test procedures |
| LLM05 | Improper Output Handling | output-handling-tester | 3 test procedures |
| LLM06 | Excessive Agency | agent-abuse-tester | 3 test procedures |
| LLM07 | System Prompt Leakage | data-extraction-tester | 3 test procedures |
| LLM08 | Vector and Embedding Weaknesses | Main agent | 4 test procedures |
| LLM09 | Misinformation | Main agent | 3 test procedures |
| LLM10 | Unbounded Consumption | Main agent | 3 test procedures |

### OWASP Agentic Top 10 (2026)
| ID | Risk | Subagent | Tests |
|----|------|----------|-------|
| ASI01 | Agent Goal Hijacking | agent-abuse-tester | 3 test procedures |
| ASI02 | Tool Misuse and Exploitation | agent-abuse-tester | 4 test procedures |
| ASI03 | Identity and Privilege Abuse | agent-abuse-tester | 3 test procedures |
| ASI04 | Uncontrolled Agentic Actions | agent-abuse-tester | 3 test procedures |
| ASI05 | Improper Multi-Agent Orchestration | agent-abuse-tester | 3 test procedures |
| ASI06 | Compromised Agentic Memory | agent-abuse-tester | 3 test procedures |
| ASI07 | Insecure Agentic Communication | agent-abuse-tester | 2 test procedures |
| ASI08 | Cascading Failures | agent-abuse-tester | 2 test procedures |
| ASI09 | Human-Agent Trust Exploitation | agent-abuse-tester | 2 test procedures |
| ASI10 | Rogue Agents | agent-abuse-tester | 3 test procedures |

---

## Important Notes

- **Authorization Required**: This agent ONLY operates against systems with explicit written authorization
- **Ethical Use**: Designed for legitimate security testing by authorized professionals
- **Non-Determinism**: All tests account for LLM stochastic behavior with minimum 5 attempts per payload
- **Evidence-Based**: Every finding requires reproduction steps and supporting evidence
- **Framework-Mapped**: All findings map to OWASP, MITRE ATLAS, and NIST references

---

## License

This work is based on OWASP materials licensed under Creative Commons Attribution-ShareAlike v4.0.
