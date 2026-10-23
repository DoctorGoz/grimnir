Run GenAI system reconnaissance against $ARGUMENTS

## Steps
1. Model fingerprinting: identify provider, model version, capabilities (use model-fingerprinting skill)
2. API surface mapping: discover all endpoints, input schemas, output formats
   - Test common LLM API paths from wordlists/llm-api-endpoints.txt
   - Map authentication mechanisms and rate limits
3. Guardrail identification: probe content filters and safety boundaries
   - Test categories from wordlists/guardrail-test-topics.txt
   - Document exact refusal messages and patterns
4. Tool/plugin enumeration (if agentic):
   - Probe for available tools from wordlists/agent-tool-names.txt
   - Map tool capabilities and permissions
5. RAG system detection: test for document retrieval capabilities
6. Run automated recon: bash scripts/llm-recon.sh $ARGUMENTS
7. Compile attack surface map to engagement/recon-notes.md

Report: model identification, endpoint inventory, guardrail map, tool inventory, and recommended attack priorities.
