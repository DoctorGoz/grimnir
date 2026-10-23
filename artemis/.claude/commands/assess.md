Run vulnerability assessment against $ARGUMENTS

Accepts: category code (LLM01-LLM10, ASI01-ASI10) or "all"

## Category Routing
- LLM01 (Prompt Injection): Use prompt-injection-tester agent
- LLM02 (Sensitive Info Disclosure): Use data-extraction-tester agent
- LLM03 (Supply Chain): Manual review with references/owasp-llm-top10.md
- LLM04 (Data/Model Poisoning): Use rag-poisoning skill + manual review
- LLM05 (Improper Output Handling): Use output-handling-tester agent
- LLM06 (Excessive Agency): Use agent-abuse-tester agent
- LLM07 (System Prompt Leakage): Use data-extraction-tester agent
- LLM08 (Vector/Embedding Weakness): Use rag-poisoning skill
- LLM09 (Misinformation): Manual testing with references/owasp-llm-top10.md
- LLM10 (Unbounded Consumption): Use resource-exhaustion skill
- ASI01-ASI10: Use agent-abuse-tester agent
- "all": Orchestrate all categories in priority order from test plan

## For Each Category
1. Read test procedures from references/owasp-llm-top10.md or references/owasp-agentic-top10.md
2. Execute test cases with minimum 5 attempts per payload
3. Document findings immediately: bash scripts/new-finding.sh "TITLE" "CATEGORY" "SEVERITY"
4. Update test plan status

Save findings to engagement/findings/ directory.
