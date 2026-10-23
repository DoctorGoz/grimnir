Run data extraction and information disclosure testing against $ARGUMENTS

Delegates to data-extraction-tester agent.

## Test Categories
1. System prompt extraction (LLM07): direct, framing, completion, encoding techniques
2. Training data extraction (LLM02): memorization probing, PII extraction
3. RAG document leakage: document listing, cross-boundary access, chunk exploitation
4. Credential/config exposure: API keys, environment variables, infrastructure details
5. Conversation history leakage: cross-user access, session persistence

## Automated Testing
- System prompt extraction: bash scripts/system-prompt-extract.sh $ARGUMENTS
- Extraction prompts: wordlists/system-prompt-extractors.txt
- Data probes: wordlists/sensitive-data-probes.txt

Save findings with: bash scripts/new-finding.sh "TITLE" "LLM02/LLM07" "SEVERITY"
