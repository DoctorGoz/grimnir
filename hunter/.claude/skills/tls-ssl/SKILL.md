---
name: tls-ssl
description: TLS/SSL weakness testing — expired certs, weak ciphers, protocol downgrade, known vulnerabilities. Maps to Hunter NET08.
allowed-tools: Read, Grep, Glob, Bash
---

# TLS/SSL Testing Skill

## When to Use
- When any TLS/SSL service is discovered (HTTPS, SMTPS, IMAPS, LDAPS, etc.)
- When assessing encryption configuration and certificate validity

## Tool Chain

### 1. Certificate Analysis
    openssl s_client -connect TARGET:PORT -servername HOSTNAME </dev/null 2>/dev/null | openssl x509 -noout -text
    # Check: expiry, issuer, SAN, key size, signature algorithm

### 2. Cipher Enumeration
    nmap --script ssl-enum-ciphers -p PORT TARGET
    # Flag: RC4, DES, 3DES, NULL ciphers, export-grade, <128-bit

### 3. Protocol Support
    # Test each protocol version
    openssl s_client -connect TARGET:PORT -tls1   </dev/null 2>&1 | head -5  # TLS 1.0
    openssl s_client -connect TARGET:PORT -tls1_1 </dev/null 2>&1 | head -5  # TLS 1.1
    openssl s_client -connect TARGET:PORT -tls1_2 </dev/null 2>&1 | head -5  # TLS 1.2
    openssl s_client -connect TARGET:PORT -tls1_3 </dev/null 2>&1 | head -5  # TLS 1.3

### 4. Known Vulnerabilities
    # Heartbleed (CVE-2014-0160)
    nmap --script ssl-heartbleed -p PORT TARGET

    # POODLE (CVE-2014-3566)
    nmap --script ssl-poodle -p PORT TARGET

    # DROWN
    nmap --script ssl-drown -p PORT TARGET

    # ROBOT
    nmap --script tls-robot -p PORT TARGET

### 5. Certificate Chain
    openssl s_client -connect TARGET:PORT -showcerts </dev/null 2>/dev/null
    # Check: self-signed, incomplete chain, untrusted CA

## Severity Guidelines
- **High**: Expired certificate, self-signed on public service, SSLv3/TLS 1.0 enabled, Heartbleed
- **Medium**: TLS 1.1 enabled, weak ciphers (RC4, 3DES), missing HSTS, incomplete chain
- **Low**: Certificate transparency issues, SHA-1 in chain, missing OCSP stapling
- **Info**: TLS 1.3 not supported, cipher preference order

## Output
Document: protocol versions, cipher suites, certificate details, vulnerabilities, and remediation.

## Validate & Promote

Findings from this skill are born `theoretical` (see the validation layer in the repo-root `CLAUDE.md`). They do NOT enter a report or external submission until promoted to `confirmed` with `scripts/validate-finding.sh`, after the independent check below.

- **Independent check for this class:** Confirm the weak cipher/protocol is actually negotiable (handshake) and tie to concrete impact; a scanner flag alone is Low/Info.
- Only `confirmed` findings ship. `validated` = reproduced but not independently confirmed.

```bash
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent hunter \
  --id HUN-NNN --state confirmed --method tool-output \
  --negative-control "<what you proved, and the control result>" --by hunter
```
