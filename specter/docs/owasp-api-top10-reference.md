# OWASP API Security Top 10 (2023) Quick Reference

## API1:2023 - Broken Object Level Authorization (BOLA)
Most common API vuln (~40% of attacks). APIs fail to verify requesting user
owns the object referenced by ID. Test by swapping object IDs between users.
Exploitability: Easy. Automated detection: Low.

## API2:2023 - Broken Authentication
Weak auth mechanisms: credential stuffing, JWT manipulation, missing lockout,
password reset flaws. Test JWT attacks, OAuth flows, session management.
Exploitability: Easy. Automated detection: Medium-High.

## API3:2023 - Broken Object Property Level Authorization (BOPLA)
Merges Excessive Data Exposure + Mass Assignment. APIs return all properties
or accept unexpected fields. Test by adding role/isAdmin fields to requests
and checking for sensitive data in responses.
Exploitability: Easy. Automated detection: Low.

## API4:2023 - Unrestricted Resource Consumption
Missing rate limits, pagination bounds, resource caps. Test with rapid bursts,
large page_size, GraphQL batching, downstream cost triggers.
Exploitability: Easy. Automated detection: Low-Medium.

## API5:2023 - Broken Function Level Authorization (BFLA)
Admin functions accessible to regular users. Test by accessing admin endpoints
with user tokens, varying HTTP methods.
Exploitability: Easy. Automated detection: Medium.

## API6:2023 - Unrestricted Access to Sensitive Business Flows (NEW)
Business logic abused via automation: scalping, fake reviews, referral abuse.
Test if sensitive flows have bot protection.
Exploitability: Easy. Automated detection: Low.

## API7:2023 - Server Side Request Forgery (NEW)
API fetches user-supplied URLs without validation. Test with internal IPs,
cloud metadata URLs, protocol smuggling.
Exploitability: Easy. Automated detection: High.

## API8:2023 - Security Misconfiguration
Verbose errors, permissive CORS, missing TLS, unnecessary methods. Mostly
automatable with DAST tools.
Exploitability: Easy. Automated detection: High.

## API9:2023 - Improper Inventory Management
Shadow APIs, old versions, deprecated endpoints without security controls.
Test older API paths and undocumented endpoints.
Exploitability: Easy. Automated detection: Medium.

## API10:2023 - Unsafe Consumption of APIs (NEW)
Trusting third-party API data without validation. Test TLS enforcement,
redirect following, input validation on external data.
Exploitability: Medium. Automated detection: Medium.
