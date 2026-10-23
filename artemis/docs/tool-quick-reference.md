# GenAI Pentesting Tool Quick Reference

## HTTP & API Testing

| Tool | Command | Purpose |
|------|---------|---------|
| curl | `curl -X POST URL -H "Content-Type: application/json" -d '{"messages":[...]}'` | Send prompts to LLM APIs |
| curl (stream) | `curl -N URL -d '{"stream":true,...}'` | Test streaming responses |
| httpx | `httpx -l urls.txt -status-code -content-type -tech-detect` | Probe endpoints, detect tech |
| nuclei | `nuclei -u URL -t templates/` | Template-based scanning |

## Python Testing

| Purpose | Command |
|---------|---------|
| Token counting | `python3 -c "import tiktoken; enc=tiktoken.encoding_for_model('gpt-4'); print(len(enc.encode('text')))"` |
| Async spray | `python3 scripts/async-spray.py --target URL --wordlist payloads.txt` |
| Base64 encode | `python3 -c "import base64; print(base64.b64encode(b'payload').decode())"` |
| JSON escape | `echo 'payload' \| python3 -c "import sys,json; print(json.dumps(sys.stdin.read()))"` |

## Encoding & Obfuscation

| Encoding | Encode | Decode |
|----------|--------|--------|
| Base64 | `echo -n "text" \| base64` | `echo "dGV4dA==" \| base64 -d` |
| Hex | `echo -n "text" \| xxd -p` | `echo "74657874" \| xxd -r -p` |
| ROT13 | `echo "text" \| tr 'a-zA-Z' 'n-za-mN-ZA-M'` | Same command (symmetric) |
| URL | `python3 -c "import urllib.parse; print(urllib.parse.quote('text'))"` | `python3 -c "import urllib.parse; print(urllib.parse.unquote('text'))"` |

## SSRF & Callback Detection

| Tool | Command | Purpose |
|------|---------|---------|
| interactsh | `interactsh-client` | OOB callback detection for SSRF via agents |
| curl (metadata) | `curl http://169.254.169.254/latest/meta-data/` | AWS metadata endpoint |

## Secrets & Source Analysis

| Tool | Command | Purpose |
|------|---------|---------|
| semgrep | `semgrep --config=auto /path/to/source` | SAST for LLM integration code |
| gitleaks | `gitleaks detect --source /path/to/repo` | Find leaked secrets in code |
| trufflehog | `trufflehog git file:///path/to/repo` | Deep secret scanning |
| secretfinder | `secretfinder -i https://target.com/app.js -o cli` | JS secret extraction |

## JSON Processing

| Tool | Command | Purpose |
|------|---------|---------|
| jq | `jq '.choices[0].message.content'` | Extract chat completion text |
| jq | `jq '.content[0].text'` | Extract Anthropic response text |
| jq | `jq '.candidates[0].content.parts[0].text'` | Extract Google AI response |
| gron | `gron response.json \| grep -i key` | Grep-friendly JSON |

## Automated Baseline Scanning

| Tool | Command | Purpose |
|------|---------|---------|
| garak | `garak --model_type openai --model_name gpt-4 --probes promptinject,encoding` | Direct garak invocation |
| garak (list probes) | `garak --list_probes` | Show all available probe modules |
| garak (list generators) | `garak --list_generators` | Show all supported model types |
| garak (REST API) | `garak --model_type rest --model_name https://target/api --probes dan` | Test custom REST endpoint |
| garak-baseline.sh | `bash scripts/garak-baseline.sh openai gpt-4` | Wrapper with cost-controlled defaults |
| garak-baseline.sh | `bash scripts/garak-baseline.sh rest target --rate-limit 1.0` | Strict rate limiting |

**⚠️ Token/cost warning:** garak generates many API calls. Default baseline: ~300-1,000 calls. Full scan: 10,000+. Always use the wrapper script or `--probes` to limit scope.

## ARTEMIS Scripts

| Script | Usage | Purpose |
|--------|-------|---------|
| llm-recon.sh | `bash scripts/llm-recon.sh URL [KEY]` | Full recon pipeline |
| prompt-injection-spray.sh | `bash scripts/prompt-injection-spray.sh URL [WORDLIST] [KEY]` | Spray PI payloads |
| system-prompt-extract.sh | `bash scripts/system-prompt-extract.sh URL [KEY]` | Extract system prompt |
| guardrail-probe.sh | `bash scripts/guardrail-probe.sh URL [KEY]` | Test guardrail effectiveness |
| agent-tool-enum.sh | `bash scripts/agent-tool-enum.sh URL [KEY]` | Enumerate agent tools |
| output-xss-test.sh | `bash scripts/output-xss-test.sh URL [KEY]` | Test XSS in LLM output |
| full-genai-audit.sh | `bash scripts/full-genai-audit.sh URL [KEY] [ENG_ID]` | Run full audit pipeline |
| garak-baseline.sh | `bash scripts/garak-baseline.sh <model_type> <model_name> [OPTIONS]` | Automated LLM vuln baseline |
| init-engagement.sh | `bash scripts/init-engagement.sh ENG_ID TARGET` | Init workspace |
| new-finding.sh | `bash scripts/new-finding.sh "Title" "Category" "Severity"` | Create finding |

## RAG Testing Scripts (added 2026-06-13)

| Script | Usage | Purpose |
|--------|-------|---------|
| rag-poisoning-spray.sh | `bash scripts/rag-poisoning-spray.sh URL [WORDLIST] [KEY]` | Spray RAG document injection payloads |
| rag-document-extract.sh | `bash scripts/rag-document-extract.sh URL [KEY]` | Test document leakage from RAG systems |

## promptfoo Integration (added 2026-06-13)

| Command | Usage | Purpose |
|---------|-------|---------|
| promptfoo-wrapper.sh | `bash artemis/promptfoo/promptfoo-wrapper.sh URL [rag|chat] [KEY] [--project-dir DIR]` | Run promptfoo adversarial eval |
| promptfoo eval (RAG) | `cd artemis/promptfoo && npm run eval:rag` | RAG evaluation with structured assertions |
| promptfoo eval (Chat) | `cd artemis/promptfoo && npm run eval:chat` | Chatbot evaluation with guardrail tests |
| promptfoo view | `cd artemis/promptfoo && npm run view` | Interactive results viewer |
| npm install | `cd artemis/promptfoo && npm install` | Install promptfoo (first-time setup) |

## Key Python Libraries for GenAI Testing

| Library | Install | Purpose |
|---------|---------|---------|
| tiktoken | `pip install tiktoken` | OpenAI tokenizer (token counting, context window) |
| transformers | `pip install transformers` | HuggingFace tokenizers & models |
| openai | `pip install openai` | OpenAI API client |
| anthropic | `pip install anthropic` | Anthropic API client |
| langchain | `pip install langchain` | Test LangChain applications |
| httpx | `pip install httpx` | Async HTTP client |
| aiohttp | `pip install aiohttp` | Async HTTP for spray scripts |
| garak | `pip install garak` | NVIDIA LLM vulnerability scanner (baseline scanning) |
