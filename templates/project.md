# [Project Name]

[Brief description of the target — what it is, what it does, who runs it.]

## Target

Primary URL: https://target.example.com
Type: [web app / API / AI chatbot / network / infrastructure / mixed]
Program handle: [bug-bounty platform slug, e.g. acme-corp-bbp — the canonical id for the program;
                 often differs from the short dir name.
                 LEAVE BLANK for a pentest or directly-supplied target.]
Platform: [h1 / intigriti / bugcrowd / ywh — bug-bounty only; blank for direct targets]

## Credentials

| Purpose | Username | Password/Token | Notes |
|---------|----------|----------------|-------|
| Admin | admin@example.com | ... | Main test account |
| User | user@example.com | ... | Low-privilege account |
| API Key | — | ... | Used for API auth |

### Account Capabilities (reachability pre-check)

Declare what you hold, for `scripts/reachability.sh` (the LANE gate). Used to label
high-value lanes REACHABLE vs GATED before any specialist is dispatched.

- Accounts held: [1 / 2 / more]
- KYC level: [none / level-0 / verified]
- Funded balance: [no / yes — amount + currency]
- Mobile device / app: [no / yes — platform]
- Plan tier: [free / paid — which plan]
- Geo-egress available: [regions, e.g. us, eu / none]
- OTP/2FA enrolled: [no / yes]
- Elevated role/approval: [no / yes — which]

## Scope

Authorization: [Bug bounty program / Pentest contract / Internal assessment]
Platform: [HackerOne / Bugcrowd / Intigriti / Direct contract / Internal]

### In Scope

- *.target.com
- API endpoints at api.target.com
- [List all in-scope targets, URLs, IPs, CIDR ranges]

### Out of Scope

- production-database.target.com
- Third-party integrations
- [List all exclusions]

## Testing Priorities

[What the client/program cares about most. AI features? API security? Infrastructure?]

## AI Features (if applicable)

[Describe any AI/LLM features — chatbots, copilots, AI agents, RAG systems]
- AI Chat URL: https://...
- AI API endpoint: https://...
- Model info: [if known]

## Constraints

- Rate limit: [e.g., 10 req/sec, none specified]
- Testing window: [e.g., 24/7, business hours only]
- Notification required: [yes/no, who to contact]
- Destructive testing: [allowed/not allowed]

## Notes

[Any additional context — program rules, known issues, previous findings, tips]
