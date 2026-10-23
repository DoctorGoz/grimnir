Run complete OWASP API Top 10 audit against $ARGUMENTS

Orchestrates all subagents through the full methodology:

## Phase 1: Reconnaissance (recon-agent)
Full attack surface mapping, WAF detection, endpoint discovery, tech fingerprinting

## Phase 2: Authentication Testing (auth-tester)
JWT analysis/attacks, OAuth flow testing, session management, credential testing

## Phase 3: Authorization Testing (auth-tester)
BOLA/IDOR on all endpoints, BFLA on admin endpoints, BOPLA/mass assignment, RBAC bypass

## Phase 4: Injection Testing (injection-tester)
SQLi, NoSQLi, command injection, SSRF, SSTI, XXE on all parameters

## Phase 5: Business Logic (main agent)
Rate limit testing/bypass, race conditions, workflow bypass, resource exhaustion

## Phase 6: Configuration Review (main agent)
CORS policy, security headers, TLS config, error handling, API versioning/inventory

## Phase 7: Reporting (report-generator)
Compile findings, deduplicate, classify severity, generate executive summary

Save to reports/TARGET-YYYYMMDD-full-audit.md
