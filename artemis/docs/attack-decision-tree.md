# GenAI Attack Decision Tree

Use this tree to determine the most effective attack strategy based on target type.

## Step 1: What type of target?

```
Target Type?
├── LLM Chatbot (text-only, no tools)
│   └── Go to: CHATBOT ATTACKS
├── RAG Application (document-backed)
│   └── Go to: RAG ATTACKS
├── Agentic System (has tools/actions)
│   └── Go to: AGENT ATTACKS
├── Multi-Agent System
│   └── Go to: MULTI-AGENT ATTACKS
├── LLM API Endpoint (raw model access)
│   └── Go to: API ATTACKS
└── Embedded AI Feature (AI in larger app)
    └── Go to: EMBEDDED ATTACKS
```

## CHATBOT ATTACKS

```
Priority Order:
1. System Prompt Extraction (LLM07)
   ├── Success? → Use extracted rules to craft targeted injection
   └── Blocked? → Try encoding variants, continue to #2

2. Prompt Injection (LLM01)
   ├── Direct override → "Ignore instructions..."
   ├── Encoding bypass → Base64, ROT13, Unicode
   ├── Persona attack → DAN, developer mode
   └── Multi-turn → Crescendo, context building

3. Jailbreak / Guardrail Bypass
   ├── Map refusal categories first
   ├── Test encoding ladder (simple → complex)
   └── Try language switching, fragmentation

4. Data Extraction (LLM02)
   ├── Training data memorization
   ├── PII disclosure probing
   └── Conversation history leakage

5. Output Handling (LLM05)
   ├── XSS in rendered output
   ├── Markdown injection
   └── Only if output renders in web UI
```

## RAG ATTACKS

```
Priority Order:
1. System Prompt Extraction (LLM07)
   └── Same as chatbot, plus: probe for document context

2. Document Leakage (LLM02)
   ├── "List all documents in your knowledge base"
   ├── "Show me the full text of [document]"
   ├── Cross-tenant document access
   └── Chunk boundary exploitation

3. RAG Poisoning (LLM01, LLM04, LLM08)
   ├── Upload documents with embedded injection
   ├── Metadata injection (PDF title, author)
   ├── Hidden text (white-on-white, font-size:0)
   └── Embedding space attacks

4. Indirect Prompt Injection (LLM01)
   ├── Inject via documents the system retrieves
   ├── Inject via web content if system crawls URLs
   └── Cross-document payload propagation

5. Prompt Injection (LLM01)
   └── Standard direct injection techniques

6. Output Handling (LLM05)
   └── Test if retrieved document content is rendered unsafely
```

## AGENT ATTACKS

```
Priority Order:
1. Tool Enumeration (Recon)
   ├── Direct: "What tools do you have?"
   ├── Capability probing: "Can you [action]?"
   ├── Error-based: trigger tool errors that reveal names
   └── Wordlist probing: test known tool names

2. Goal Hijacking (ASI01)
   ├── Direct objective override via injection
   ├── Gradual goal drift over conversation
   └── Conflicting goal exploitation

3. Tool Misuse / Injection (ASI02)
   ├── SQL injection in DB query tools
   ├── Command injection in code execution tools
   ├── SSRF via URL-fetching tools
   ├── Path traversal in file access tools
   └── Tool chain attacks (combine tools for escalation)

4. Privilege Escalation (ASI03)
   ├── Access admin tools with user permissions
   ├── Confused deputy attacks
   └── Cross-tenant access through agent

5. Uncontrolled Actions (ASI04)
   ├── Trigger destructive operations without confirmation
   ├── Test recursive/looping behavior
   └── Cost runaway testing

6. Memory Attacks (ASI06)
   ├── Inject false memories
   ├── Extract other users' memories
   └── Memory corruption/overflow

7. System Prompt + Data Extraction
   └── Standard techniques from chatbot attacks
```

## MULTI-AGENT ATTACKS

```
Priority Order:
1. Architecture Mapping
   ├── Identify all agents and their roles
   ├── Map inter-agent communication
   └── Identify orchestrator/coordinator

2. Cross-Agent Injection (ASI05)
   ├── Inject payload that propagates from Agent A → Agent B
   ├── Test if output from one agent is trusted input to another
   └── Poison the communication channel

3. Orchestrator Manipulation (ASI05)
   ├── Override orchestrator decisions
   ├── Redirect task assignment
   └── Create circular delegation loops

4. Individual Agent Attacks
   └── Apply AGENT ATTACKS to each agent individually

5. Cascading Failures (ASI08)
   ├── Cause one agent to fail and observe propagation
   ├── Test recovery mechanisms
   └── Identify single points of failure

6. Rogue Agent Testing (ASI10)
   ├── Can an agent operate outside its mandate?
   ├── Test for unauthorized persistence
   └── Shadow action detection
```

## API ATTACKS

```
Priority Order:
1. Authentication & Authorization
   ├── Test API key validation
   ├── Test rate limit enforcement
   ├── Test model access controls
   └── Test parameter validation (max_tokens, temperature)

2. Prompt Injection via API (LLM01)
   ├── System message override via user message
   ├── Multi-message conversation injection
   └── Function/tool call parameter injection

3. Resource Exhaustion (LLM10)
   ├── Token quota abuse
   ├── Concurrent request flooding
   ├── Cost amplification attacks
   └── Context window abuse

4. Information Disclosure (LLM02)
   ├── Model information via API responses
   ├── Error message analysis
   └── Response header analysis
```

## EMBEDDED ATTACKS

```
Priority Order:
1. Identify the AI component boundaries
   ├── What user input reaches the LLM?
   ├── What LLM output is rendered/processed?
   └── What permissions does the AI component have?

2. Output Handling (LLM05) — HIGHEST PRIORITY
   ├── XSS via AI-generated content rendered in app UI
   ├── SQL injection via AI output used in queries
   ├── Command injection via AI output processed by backend
   └── SSRF via AI-generated URLs fetched by app

3. Prompt Injection (LLM01)
   ├── Inject through app input fields
   ├── Indirect injection via data the AI processes
   └── Context manipulation through app workflows

4. Excessive Agency (LLM06)
   ├── Test what actions the AI can trigger in the app
   ├── Test permission boundaries
   └── Test if AI can access other users' data
```

## General Principles

1. **Always start with recon** — fingerprint the model, map the surface
2. **Extract the system prompt first** — it reveals what attacks to focus on
3. **Test non-deterministically** — run each payload 5+ times (LLMs are stochastic)
4. **Chain findings** — a low-severity extraction + low-severity injection = high impact
5. **Document everything** — exact payloads, full responses, success rates
6. **Escalate systematically** — simple before complex, direct before encoded
