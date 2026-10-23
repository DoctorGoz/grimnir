# LLM Provider Fingerprints

Reference guide for identifying LLM providers and models through behavioral and technical indicators.

## OpenAI (GPT-3.5, GPT-4, GPT-4o, o1, o3)

### API Response Structure
```json
{
  "id": "chatcmpl-...",
  "object": "chat.completion",
  "model": "gpt-4o-2024-08-06",
  "choices": [{"index": 0, "message": {"role": "assistant", "content": "..."}, "finish_reason": "stop"}],
  "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30}
}
```

### Behavioral Indicators
- Refusal phrase: "As an AI language model, I cannot..."
- Self-identifies as: "ChatGPT" or "GPT-4"
- Distinctive markdown formatting in responses
- Knowledge cutoff varies by model version
- Function calling uses `tools` / `tool_calls` format

### Technical Signatures
- API base: `https://api.openai.com/v1/`
- Headers: `openai-model`, `openai-organization`, `openai-processing-ms`
- Rate limit headers: `x-ratelimit-limit-requests`, `x-ratelimit-remaining-tokens`
- Error format: `{"error": {"message": "...", "type": "...", "code": "..."}}`

### Model Differentiation
| Probe | GPT-3.5 | GPT-4 | GPT-4o | o1/o3 |
|-------|---------|-------|--------|-------|
| Complex reasoning | Struggles | Strong | Strong | Strongest |
| Knowledge cutoff | ~2021-2023 | ~2023-2024 | ~2024 | ~2024-2025 |
| Image understanding | No | Yes (4V) | Yes | Yes |
| Response speed | Fast | Slow | Fast | Variable |

---

## Anthropic (Claude 3, 3.5, 4)

### API Response Structure
```json
{
  "id": "msg_...",
  "type": "message",
  "role": "assistant",
  "content": [{"type": "text", "text": "..."}],
  "model": "claude-sonnet-4-20250514",
  "stop_reason": "end_turn",
  "usage": {"input_tokens": 10, "output_tokens": 20}
}
```

### Behavioral Indicators
- Refusal phrase: "I don't think I should..." or "I'd prefer not to..."
- Less likely to say "As an AI" — more natural refusals
- Tends to be more verbose and thorough
- Often acknowledges limitations directly
- Uses "I" perspective frequently

### Technical Signatures
- API base: `https://api.anthropic.com/v1/`
- Required header: `x-api-key` and `anthropic-version`
- Headers: `request-id`
- Error format: `{"type": "error", "error": {"type": "...", "message": "..."}}`
- Content format uses `content[0].text` not `choices[0].message.content`

### Model Differentiation
| Probe | Haiku | Sonnet | Opus |
|-------|-------|--------|------|
| Response depth | Brief | Balanced | Very thorough |
| Reasoning | Good | Strong | Strongest |
| Speed | Fastest | Medium | Slowest |
| Context window | 200K | 200K | 200K |

---

## Google (Gemini 1.5, 2.0, 2.5)

### API Response Structure
```json
{
  "candidates": [{
    "content": {"parts": [{"text": "..."}], "role": "model"},
    "finishReason": "STOP",
    "safetyRatings": [{"category": "HARM_CATEGORY_...", "probability": "..."}]
  }],
  "usageMetadata": {"promptTokenCount": 10, "candidatesTokenCount": 20}
}
```

### Behavioral Indicators
- Refusal phrase: "As a large language model, I'm not able to..."
- Often includes safety caveats and disclaimers
- May reference Google services (Search, Maps)
- Distinctive `safetyRatings` in API responses
- Uses `candidates[]` array (can return multiple)

### Technical Signatures
- API base: `https://generativelanguage.googleapis.com/v1beta/`
- Auth: API key as query param `?key=` or OAuth2
- Response uses `candidates[0].content.parts[0].text`
- Safety ratings always present in response
- Error format: Google Cloud error schema

---

## Meta (Llama 3, 3.1, 3.2, 4)

### Behavioral Indicators (when self-hosted)
- Shorter, more direct responses
- Less likely to add safety disclaimers
- May not self-identify or claims to be a "helpful assistant"
- Specific refusal patterns differ from commercial APIs
- Open weights — behavior varies heavily by fine-tuning

### Technical Signatures (common serving frameworks)
- **Ollama**: API at `http://localhost:11434/api/chat`, response has `model`, `message`, `done`
- **vLLM**: OpenAI-compatible API, but model names reveal it's Llama
- **TGI**: `http://host/generate`, response has `generated_text`
- **llama.cpp**: Various API formats depending on server

### Detection
- Ask "What model are you?" — often reveals "Llama" or "Meta"
- Check `/v1/models` endpoint for model names
- Response style tends to be less polished than commercial APIs

---

## Mistral

### API Response Structure
```json
{
  "id": "cmpl-...",
  "object": "chat.completion",
  "model": "mistral-large-latest",
  "choices": [{"index": 0, "message": {"role": "assistant", "content": "..."}, "finish_reason": "stop"}],
  "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30}
}
```

### Behavioral Indicators
- Similar structure to OpenAI (intentionally compatible)
- May self-identify as Mistral
- Distinct safety categories and refusal patterns
- French company — may handle French queries distinctively

### Technical Signatures
- API base: `https://api.mistral.ai/v1/`
- Auth: Bearer token
- OpenAI-compatible format but different model names
- Error format similar to OpenAI

---

## Cohere

### API Response Structure
```json
{
  "response_id": "...",
  "text": "...",
  "generation_id": "...",
  "token_count": {"prompt_tokens": 10, "response_tokens": 20, "total_tokens": 30, "billed_tokens": 25},
  "meta": {"api_version": {"version": "2"}}
}
```

### Technical Signatures
- API base: `https://api.cohere.com/v2/`
- Auth: Bearer token
- Distinctive response format with `text` (not `choices[]`)
- Billed tokens separate from total tokens
- RAG built-in with `documents` parameter

---

## Detection Strategy

1. **Send "What model are you?"** — many models self-identify
2. **Check API response structure** — each provider has unique JSON schema
3. **Analyze response headers** — provider-specific headers
4. **Test knowledge cutoff** — ask about recent events
5. **Observe refusal language** — distinctive per provider
6. **Check error messages** — unique error formats per provider
7. **Test capabilities** — image understanding, function calling, streaming
8. **Try `/v1/models` endpoint** — often lists available models
