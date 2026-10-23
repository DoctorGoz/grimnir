# Specter - API & Web Security Pentesting Agent

A Claude Code CLI agent specialized in API and web application security
testing, designed for penetration testing engagements and bug bounty hunting.

## Overview

Specter is an AI-powered pentesting agent built on Claude Code that
systematically tests APIs and web applications against the OWASP API
Security Top 10 (2023) and OWASP WSTG v5.0 methodologies.

It operates standalone or accepts delegated tasks from a Project Manager
orchestrator agent as part of a larger pentesting workflow.

## Quick Start

1. Clone this repo into your working directory
2. Install required tools (see Prerequisites below)
3. Run Claude Code from the project root:
   claude
4. Use slash commands to start testing:
   /recon https://api.target.com
   /full-audit https://api.target.com

## Project Structure

    api-pentest-agent/
    |- CLAUDE.md                    # Agent identity and methodology
    |- .claude/
    |  |- agents/                   # 7 specialized subagents
    |  |  |- recon-agent.md
    |  |  |- auth-tester.md
    |  |  |- injection-tester.md
    |  |  |- rest-api-tester.md
    |  |  |- graphql-tester.md
    |  |  |- grpc-tester.md
    |  |  |- report-generator.md
    |  |- commands/                 # 10 slash commands
    |  |  |- recon.md, scan.md, test-auth.md, test-bola.md,
    |  |  |- test-rest-api.md, test-graphql.md, test-grpc.md,
    |  |  |- test-jwt.md, full-audit.md, waf-check.md
    |  |- skills/                   # 11 testing skills
    |  |  |- api-recon/, bola-testing/, jwt-analysis/,
    |  |  |- rest-api-testing/, graphql-audit/, grpc-testing/,
    |  |  |- waf-bypass/, injection-testing/, auth-testing/,
    |  |  |- business-logic/, rate-limit-testing/
    |  |- settings.json             # Permissions, MCP, hooks
    |- scripts/                     # Shell automation scripts
    |  |- recon-pipeline.sh, api-fuzz.sh, jwt-test.sh,
    |  |- graphql-enum.sh, waf-detect.sh, full-audit.sh,
    |  |- spec-analyzer.sh, rest-api-test.sh
    |- templates/
    |  |- nuclei/                   # Custom nuclei templates
    |  |- findings/                 # Finding report template
    |  |- checklists/               # OWASP testing checklists
    |- wordlists/                   # Fuzzing wordlists
    |- docs/                        # Reference documentation
    |- reports/                     # Output directory

## Prerequisites

### Required Tools
- ffuf: go install github.com/ffuf/ffuf/v2@latest
- katana: go install github.com/projectdiscovery/katana/cmd/katana@latest
- nuclei: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
- httpx: go install github.com/projectdiscovery/httpx/cmd/httpx@latest
- kiterunner: github.com/assetnote/kiterunner (build from source)
- arjun: pip install arjun
- sqlmap: apt install sqlmap / pip install sqlmap
- jwt_tool: git clone https://github.com/ticarpi/jwt_tool
- graphqlmap: git clone https://github.com/swisskyrepo/GraphQLmap
- grpcurl: go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest
- wafw00f: pip install wafw00f
- caido: https://caido.io/download
- linkfinder: git clone https://github.com/GerbenJavado/LinkFinder
- SecretFinder: git clone https://github.com/m4ll0k/SecretFinder

### Optional Tools
- graphw00f, CrackQL, InQL (schema recovery without introspection is built in: `scripts/graphql-probe.py`)
- wafninja, bypass-firewalls-by-DNS-history
- jwt-cracker, hashcat (for JWT secret cracking)
- Evans, grpcui (for interactive gRPC testing)
- Ghost Security Reaper: github.com/ghostsecurity/reaper

## Usage

### Standalone
    cd api-pentest-agent
    claude
    > /recon https://api.target.com
    > /full-audit https://api.target.com

### From Project Manager Agent
    The PM agent can invoke Specter with structured JSON:
    {
      "target": "https://api.target.com",
      "scope": ["*.target.com"],
      "phase": "full-audit",
      "auth": {"type": "bearer", "token": "..."}
    }

### REST API Testing 
Dedicated REST API security testing with schema-driven and manual methodology.

**Agent & Skill**:
- .claude/agents/rest-api-tester.md — REST API subagent with OpenAPI schema-driven test generation, content-type negotiation, HTTP method tampering, API versioning bypass, HATEOAS link following, REST-specific mass assignment (PUT/PATCH/JSON Patch RFC 6902/Merge Patch RFC 7396), pagination/filter/sort injection, and response differential analysis
- .claude/skills/rest-api-testing/SKILL.md — Hands-on playbook with ready-to-run command blocks for every REST testing phase
- .claude/commands/test-rest-api.md — `/test-rest-api <target>` with `--spec`, `--token`, `--token-b`, `--phase`, `--proxy`, `--rate` flags

**Scripts**:
- scripts/spec-analyzer.sh — Parses OpenAPI/Swagger specs and auto-generates test matrices for BOLA, BFLA, mass assignment, and input validation. Use `--generate-scripts` to output ready-to-execute test scripts populated from the spec.
- scripts/rest-api-test.sh — End-to-end REST testing pipeline: WAF detection → spec discovery → content-type negotiation → method enumeration → version enumeration → mass assignment → response differential analysis. Outputs timestamped findings and summary reports.

**Wordlists**:
- wordlists/openapi-paths.txt — 72 common OpenAPI/Swagger spec discovery paths
- wordlists/content-types.txt — 23 Content-Type variations for negotiation testing
- wordlists/api-versions.txt — 26 API version strings for enumeration
- wordlists/mass-assignment-fields.txt — 60 privilege escalation field names (role, admin, verified, credits, etc.)

### Individual Tests
    /test-bola https://api.target.com/api/v1/users/123
    /test-jwt eyJhbGciOiJIUzI1NiJ9...
    /test-graphql https://api.target.com/graphql
    /test-grpc api.target.com:50051
    /waf-check https://api.target.com

## Methodology

Specter follows a six-phase methodology:
1. RECON: Passive and active discovery
2. ENUMERATE: Route brute-forcing, parameter discovery
3. MAP: Auth mechanisms, API types, data models
4. TEST: Systematic OWASP API Top 10 + WSTG testing
5. EXPLOIT: PoC validation of findings
6. REPORT: Structured findings with remediation

## References

- OWASP API Security Top 10: https://owasp.org/API-Security/
- OWASP WSTG: https://owasp.org/www-project-web-security-testing-guide/
- Ghost Security: https://ghostsecurity.com/
- Nuclei Templates: https://github.com/projectdiscovery/nuclei-templates

## Disclaimer

This tool is intended for authorized security testing only. The authors 
are not responsible for misuse of this tool.
