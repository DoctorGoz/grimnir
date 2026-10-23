Detect and analyze WAF protection on $ARGUMENTS

## Detection
1. Fingerprint: wafw00f -a $ARGUMENTS -o reports/raw/waf-results.json -f json
2. Identify vendor and version

## Bypass Analysis
1. URL encoding: double-encode, unicode encode
2. Case variation: mixed case SQL keywords
3. Method override: X-HTTP-Method-Override header
4. Content-Type manipulation: json, xml, form-urlencoded
5. Header injection: X-Forwarded-For rotation
6. Origin IP: bypass-firewalls-by-DNS-history.sh -d DOMAIN
7. Path normalization: /./api/endpoint, //api//endpoint
8. Payload encoding: base64, hex, unicode

## WAFNinja Testing
wafninja fuzz -u "$ARGUMENTS/search?q=FUZZ" -t xss
wafninja fuzz -u "$ARGUMENTS/search?q=FUZZ" -t sqli

Report WAF type, working bypasses, adjusted testing strategy.
Save to reports/waf-analysis.md
