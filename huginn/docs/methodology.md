# HUGINN Reconnaissance Methodology

## Overview

HUGINN performs Phase 0 reconnaissance before specialist agents begin testing. The goal is to produce a complete attack surface inventory (asset-map.json) and pre-populate the intel feed (intel.jsonl) so specialists can skip recon and start testing immediately.

## Phases

### Phase 1: Passive Recon
- **Subdomain enumeration**: subfinder, findomain, assetfinder, amass
- **DNS records**: dnsx (A, AAAA, CNAME, MX, TXT, NS)
- **Certificate transparency**: crt.sh, certspotter
- **URL archives**: gau, waybackurls (historical endpoints)
- **WHOIS/OSINT**: whois, theHarvester

### Phase 2: Active Discovery
- **Port scanning**: naabu (fast), nmap (thorough)
- **Service detection**: nmap -sV
- **HTTP probing**: httpx (live hosts, status codes, titles, technologies)
- **Host discovery**: nmap -sn (for CIDR ranges)

### Phase 3: Fingerprinting
- **Technology detection**: whatweb, httpx --tech-detect, wappalyzer
- **WAF detection**: wafw00f
- **Response headers**: server, x-powered-by, CSP, HSTS, etc.
- **TLS certificates**: openssl (SANs, issuer, expiry)

### Phase 4: Endpoint & Content Discovery
- **Crawling**: katana (modern, JS-aware), gospider
- **JavaScript analysis**: linkfinder (API endpoints), secretfinder (secrets), jshunter
- **Parameter mining**: paramspider, arjun
- **URL deduplication**: uro

### Phase 5: Classification
- Build structured asset-map.json from raw data
- Identify AI/LLM indicators (chat widgets, AI triggers, /ai/ endpoints)
- Determine auth mechanisms
- Generate routing recommendations for specialists

### Phase 6: Distribution
- Pre-populate intel.jsonl with classified discoveries
- Tag each discovery for the appropriate specialist (needs-specter, needs-artemis, needs-hunter)
- Update engagement state via state.sh

## Tools by Category

| Category | Tools | Output |
|----------|-------|--------|
| Subdomains | subfinder, findomain, assetfinder, amass | subdomains.txt |
| DNS | dnsx, dnsrecon | dns-resolved.txt |
| Ports | naabu, nmap, masscan | ports-*.txt |
| HTTP | httpx | httpx-results.json |
| Tech | whatweb, wafw00f | whatweb.json, waf-detection.txt |
| Crawl | katana, gospider | crawl-katana.txt |
| JS | linkfinder, secretfinder, jshunter | js-endpoints.txt, js-secrets.txt |
| URLs | gau, waybackurls | urls-gau.txt, urls-wayback.txt |
| TLS | openssl | certificate.txt |
| Headers | curl | response-headers.txt |

## AI Indicator Detection

HUGINN specifically looks for signs of AI/LLM features to route to ARTEMIS:

- Chat widget scripts (Zendesk, Intercom, Drift, custom)
- `/ai/`, `/bot/`, `/chat/`, `/assistant/` API paths
- AI-related response headers or cookies
- Generative AI triggers in CMS/platform configs
- LLM model references in JavaScript
- RAG/knowledge base endpoints
- OpenAI/Anthropic/other AI SDK references in JS

## Correlator Mode

When running as a background correlator alongside specialists:

1. Polls agent output directories every 30 seconds
2. Detects new recon files and findings
3. Auto-generates cross-agent intel entries
4. Routes high-severity findings to all other agents
5. Creates correlation notes for cross-domain attack chains
