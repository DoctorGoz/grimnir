---
name: request-smuggling
description: HTTP request smuggling / desync testing (CWE-444, WSTG-INPV-15). Use where a front-end proxy/CDN forwards to a back-end (most modern stacks).
allowed-tools: Read, Grep, Glob, Bash
---

# HTTP Request Smuggling Skill (CWE-444)

Front-end and back-end disagree on where a request ends, letting you prepend bytes
to the next user's request: cache poisoning, credential capture, auth bypass,
WAF bypass. High impact, but easy to get false positives and easy to cause
collateral — test carefully and non-destructively.

## Prerequisites
- A chain with a reverse proxy/CDN/load balancer in front of an origin (the norm).
- Ideally Burp/Caido + the HTTP Request Smuggler mindset; raw socket control helps.

## Methodology

### Step 1: Detect the desync class (timing-based, safe)
- **CL.TE:** front-end uses Content-Length, back-end uses Transfer-Encoding.
- **TE.CL:** the reverse.
- **TE.TE:** one side is fooled by an obfuscated `Transfer-Encoding` header.
Send a crafted request and measure a deliberate **time delay** on the socket — a
timeout differential indicates a desync without poisoning shared state.

### Step 2: Obfuscated TE variants
`Transfer-Encoding: chunked` with tab/space/`x:` prefixes, duplicate headers,
`Transfer-Encoding:\tchunked`, etc.

### Step 3: Confirm impact carefully
Only after timing detection, attempt a controlled self-poison (your own second
request) to prove prefixing — avoid poisoning real users' traffic.

## Payloads / wordlists
PortSwigger smuggling probes; HTTP Request Smuggler patterns.

## Validate (negative control)
- **Attack:** reproduce the desync deterministically — the timing differential AND a
  controlled prefix landing on a *follow-up request you control*.
- **Negative control:** a well-formed request shows no delay / no prefix. A one-off
  timing blip is NOT proof; require repeatability (e.g. 5/5).

## Evidence to capture
The raw smuggling request(s), timing measurements across repeats, and the
controlled-prefix proof. Note the front-end (Server/Via headers) and any CDN.

## Safety
Do not run mass or user-affecting poisoning on production. Prefer self-contained
proofs. This class can disrupt other users — keep it surgical and in-scope.

## False-positive traps
- Network jitter mistaken for a timing desync (repeat, take medians).
- A normalising proxy that actually rejects malformed TE/CL.
- "It looked weird once" — not reproducible, not a finding.

## Validate & Promote

Findings from this skill are born `theoretical` (see the repo-root `CLAUDE.md`). Promote via `scripts/validate-finding.sh` only after a repeatable desync with a controlled prefix.

```bash
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent specter \
  --id SPE-NNN --state confirmed --method manual-repro \
  --negative-control "CL.TE probe: 5/5 timeouts vs 0/5 for well-formed control; self-poison prefix observed on controlled follow-up" --by specter
```
