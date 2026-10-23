# GenAI Penetration Test — Engagement Scope

## Engagement Information
| Field | Value |
|-------|-------|
| **Engagement ID** | ENG-YYYY-NNN |
| **Client** | [Organization Name] |
| **Tester(s)** | [Names / Team] |
| **Start Date** | YYYY-MM-DD |
| **End Date** | YYYY-MM-DD |
| **Authorization Ref** | [Link to signed authorization document] |

---

## Target System Description

**System Name**: [Name]
**System Type**: [ ] Foundation Model  [ ] Fine-Tuned Model  [ ] RAG Application  [ ] Chatbot/Assistant  [ ] Tool-Using Agent  [ ] Multi-Agent System  [ ] Autonomous Agent  [ ] MCP-Connected System

**Description**: [Brief description of the system's purpose and functionality]

**Technology Stack**:
- Model Provider/Version: [e.g., GPT-4o, Claude Sonnet 4.5, Llama 3]
- Framework: [e.g., LangChain, CrewAI, AutoGen, custom]
- Vector Database: [e.g., Pinecone, Weaviate, ChromaDB]
- Deployment: [e.g., AWS, Azure, GCP, on-prem]
- User Interface: [e.g., Web chat, API, Slack bot, mobile app]

**Access Points**:
- Endpoint(s): [URLs, API endpoints]
- Authentication: [How testers will authenticate]
- Test Account(s): [Provided credentials/roles]

---

## Scope Definition

### In Scope
- [ ] [Specific system/endpoint 1]
- [ ] [Specific system/endpoint 2]
- [ ] [Specific functionality]

### Out of Scope
- [ ] [Systems/endpoints NOT to be tested]
- [ ] [Specific actions NOT authorized]
- [ ] [Third-party services not included]

### Testing Categories (check all that apply)

#### OWASP LLM Top 10 (2025)
- [ ] LLM01: Prompt Injection
- [ ] LLM02: Sensitive Information Disclosure
- [ ] LLM03: Supply Chain
- [ ] LLM04: Data and Model Poisoning
- [ ] LLM05: Improper Output Handling
- [ ] LLM06: Excessive Agency
- [ ] LLM07: System Prompt Leakage
- [ ] LLM08: Vector and Embedding Weaknesses
- [ ] LLM09: Misinformation
- [ ] LLM10: Unbounded Consumption

#### OWASP Agentic Top 10 (2026)
- [ ] ASI01: Agent Goal Hijacking
- [ ] ASI02: Tool Misuse and Exploitation
- [ ] ASI03: Identity and Privilege Abuse
- [ ] ASI04: Uncontrolled Agentic Actions
- [ ] ASI05: Improper Multi-Agent Orchestration
- [ ] ASI06: Compromised Agentic Memory
- [ ] ASI07: Insecure Agentic Communication
- [ ] ASI08: Cascading Failures
- [ ] ASI09: Human-Agent Trust Exploitation
- [ ] ASI10: Rogue Agents

---

## Rules of Engagement

### Authorized Actions
- [ ] Prompt injection testing
- [ ] System prompt extraction attempts
- [ ] Data exfiltration testing (with data redaction)
- [ ] Tool/plugin security testing
- [ ] Rate limiting / DoS testing (at specified levels)
- [ ] Agent behavior manipulation testing
- [ ] Multi-agent trust boundary testing

### Prohibited Actions
- [ ] Testing against production with real user data impact
- [ ] Exfiltrating actual sensitive data (demonstrate path only)
- [ ] Exceeding [N] requests per minute
- [ ] Testing outside of [time window]
- [ ] [Other restrictions]

### Escalation Procedures
- **Critical finding during testing**: Contact [name] at [phone/email]
- **Evidence of active compromise**: Contact [name] at [phone/email]
- **System availability concern**: Contact [name] at [phone/email]
- **Legal/compliance question**: Contact [name] at [phone/email]

---

## Success Criteria

### Quantitative Metrics
- Coverage of [N]% of in-scope OWASP categories
- Minimum [N] test payloads per category
- [N] attempts per payload (for statistical validity)

### Qualitative Criteria
- Comprehensive threat model produced
- All critical/high findings include remediation guidance
- Executive summary suitable for non-technical stakeholders
- Findings mapped to framework references

---

## Deliverables
- [ ] Engagement scope document (this document)
- [ ] Test plan with prioritized categories
- [ ] Reconnaissance report
- [ ] Individual finding reports
- [ ] Final penetration test report with executive summary
- [ ] Remediation roadmap
- [ ] Monitoring recommendations

---

## Signatures

| Role | Name | Signature | Date |
|------|------|-----------|------|
| System Owner | | | |
| Test Lead | | | |
| Legal/Compliance | | | |
