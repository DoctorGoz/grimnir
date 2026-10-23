Begin engagement scoping for GenAI/LLM security assessment of $ARGUMENTS

## Steps
1. Identify target type: LLM chatbot, RAG application, agentic system, multi-agent system, API endpoint, embedded AI feature
2. Determine technology stack: model provider, framework (LangChain, LlamaIndex, etc.), deployment (cloud API, self-hosted)
3. Define scope boundaries: in-scope endpoints, out-of-scope systems, testing categories
4. Assess applicable OWASP categories based on target type:
   - LLM chatbot: LLM01, LLM02, LLM05, LLM07, LLM09, LLM10
   - RAG application: LLM01, LLM02, LLM04, LLM05, LLM07, LLM08
   - Agentic system: LLM01, LLM02, LLM06, ASI01-ASI10
   - API endpoint: LLM01, LLM02, LLM05, LLM07, LLM10
5. Create threat model using references/threat-modeling.md
6. Generate scope.md from templates/scope-template.md
7. Generate test-plan.md from templates/test-plan-template.md
8. Initialize engagement workspace: bash scripts/init-engagement.sh ENGAGEMENT_ID TARGET_NAME
