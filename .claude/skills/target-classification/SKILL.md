---
name: target-classification
description: Classify penetration testing targets to determine which specialist agents to deploy. Determines if target needs network testing (Hunter), API testing (Specter), GenAI testing (ARTEMIS), cloud testing (Nimbus), mobile testing (Nomad), or a combination.
allowed-tools: Read, Grep, Glob, Bash
---

# Target Classification Skill

## When to Use
- Start of every new engagement
- When a new target or scope change is introduced
- When unsure which agent should handle a target

## Classification Indicators

### Network/Infrastructure → Hunter
- IP address, CIDR range, or hostname as target
- Non-HTTP services (SSH, SMB, RDP, databases, DNS, SNMP)
- Multiple open ports across various protocols
- Active Directory / domain environment
- Server or VM requiring OS-level assessment
- Cloud *instance* with exposed network services (the host; cloud *account/config* → Nimbus)

### Cloud / IaaS → Nimbus
- Cloud credentials / console / API access in scope (AWS keys, Azure/GCP service accounts)
- Object storage (S3 / Azure Blob / GCS buckets)
- IAM / roles / policies, serverless (Lambda/Functions), managed Kubernetes (EKS/GKE/AKS)
- Cloud account id / subscription / project as the engagement target
- Metadata/SSRF credential-theft surface (pairs with Specter's SSRF)

### Mobile → Nomad
- Android APK / iOS IPA, or an app-store listing in scope
- Custom URL schemes / deeplinks, `assetlinks.json` / `apple-app-site-association`
- A mobile app fronting a backend API (test the app AND route the API to Specter)

### API/Web → Specter
- OpenAPI/Swagger/AsyncAPI specification available
- REST endpoints returning JSON/XML
- GraphQL endpoint (/graphql, /gql)
- gRPC service (HTTP/2, protobuf content-type)
- Traditional web app with forms, sessions, cookies
- CRUD operations on resources
- OAuth/OIDC flows
- API key or JWT authentication

### Salesforce / Experience Cloud → Specter (with the Salesforce pack)
Route to Specter, tag the engagement `salesforce`, and lead the test plan with the three `salesforce-*` playbooks (`rules/playbooks/`). Methodology: `specter/docs/salesforce-experience-cloud.md`. Map the guest surface first with `specter/scripts/sf-guest-map.py` (read-only, rate-limited).
- Paths: `/s/`, `/s/topic`, `/s/article`, `/s/contactsupport`
- Domains: `*.force.com`, `*.secure.force.com`, `*.live.siteforce.com`, `*.my.site.com`
- Aura endpoint: POST to `/s/sfsites/aura`, `/aura` or `/sfsites/aura`; LWC Apex at `/webruntime/api/apex/execute`
- Cookies: `BrowserId`, `renderCtx`, `sfdc-stream`
- Response tells: `"actions":[`, `aura:clientOutOfSync`, `aura:invalidSession`
- Download servlets: `/servlet/servlet.FileDownload`, `/sfc/servlet.shepherd/...`
- Authorization: the vendor requires approval for production testing; prefer a sandbox or developer org and confirm program rules before any fuzzing or writes
- Realistic severity ceiling is Critical, but the modal result on a hardened org is Low; state it per target

### GenAI/LLM → ARTEMIS
- Chat interface accepting natural language
- AI-generated responses (conversational, non-deterministic)
- Document upload for AI processing (RAG)
- AI assistant, copilot, or chatbot branding
- Prompt/message input field
- Model name or provider mentioned (GPT, Claude, Gemini, Llama)
- Tool use / function calling capabilities
- Agent or autonomous action features

### Both/Multiple → Combined Agents
- API that processes natural language → Specter + ARTEMIS
- Web app with embedded chatbot or AI assistant → Specter + ARTEMIS
- Agentic system with API-accessible tools → ARTEMIS + Specter
- RAG application with both document API and chat interface → ARTEMIS + Specter
- AI product with admin API, user API, and AI endpoints → Specter + ARTEMIS
- Server hosting web apps → Hunter + Specter
- Infrastructure with AI services → Hunter + Specter + ARTEMIS
- Cloud account hosting apps/APIs → Nimbus + Specter
- Mobile app + its backend → Nomad + Specter (+ Nimbus if cloud-hosted)
- Cloud-hosted serverless/container backend → Nimbus (+ Specter for the API)

## Quick Classification Flow

    # Check for network services (non-HTTP)
    nmap --top-ports 20 -T4 TARGET 2>/dev/null | grep open
    # If non-HTTP services found → Hunter (at minimum)

    curl -s TARGET/v1/chat/completions -d '{"messages":[{"role":"user","content":"test"}]}' -H "Content-Type: application/json"
    # If returns AI response → ARTEMIS (at minimum)

    curl -s TARGET/api/ -H "Content-Type: application/json"
    # If returns structured API data → Specter

    curl -s TARGET/ | grep -iE "chat|ai|assistant|copilot|prompt"
    # If matches → likely needs ARTEMIS

    curl -s TARGET/swagger.json TARGET/openapi.json TARGET/api-docs 2>/dev/null
    # If any returns spec → Specter

## Output
Save classification to `$PROJECT_DIR/classification.md` (absolute path) with:
- Target type
- Assigned agents (primary + secondary)
- Justification
- Recommended testing categories to prioritize (OWASP, PTES, MITRE ATT&CK)
