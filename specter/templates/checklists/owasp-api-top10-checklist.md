# OWASP API Security Top 10 (2023) Testing Checklist

## API1:2023 - Broken Object Level Authorization (BOLA)
- [ ] Identified all endpoints with object identifiers
- [ ] Tested horizontal BOLA (user A accessing user B objects)
- [ ] Tested vertical BOLA (lower privilege accessing higher)
- [ ] Tested across all HTTP methods per endpoint
- [ ] Tested ID enumeration (sequential, UUID, encoded)
- [ ] Tested GraphQL variable ID manipulation

## API2:2023 - Broken Authentication
- [ ] Tested default/weak credentials
- [ ] Tested brute-force lockout mechanisms
- [ ] Tested JWT implementation (alg none, key confusion, etc)
- [ ] Tested OAuth flows (redirect_uri, state, PKCE, scope)
- [ ] Tested password reset flow
- [ ] Tested MFA bypass techniques
- [ ] Tested session management (fixation, timeout, concurrent)

## API3:2023 - Broken Object Property Level Authorization (BOPLA)
- [ ] Tested mass assignment (adding role, isAdmin, etc to requests)
- [ ] Compared GET responses vs POST/PUT accepted fields
- [ ] Checked for excessive data exposure in responses
- [ ] Tested field-level access control

## API4:2023 - Unrestricted Resource Consumption
- [ ] Tested rate limiting on sensitive endpoints
- [ ] Tested rate limit bypass techniques (headers, path variation)
- [ ] Tested pagination abuse (large page_size values)
- [ ] Tested GraphQL batching/alias abuse
- [ ] Tested large payload handling
- [ ] Tested downstream cost attacks (SMS, email triggers)

## API5:2023 - Broken Function Level Authorization (BFLA)
- [ ] Mapped admin vs user endpoints
- [ ] Tested admin endpoints with user tokens
- [ ] Tested HTTP method variations (GET allowed, PUT blocked?)
- [ ] Tested admin path patterns (/admin/, /internal/, /debug/)

## API6:2023 - Unrestricted Access to Sensitive Business Flows
- [ ] Identified sensitive business flows
- [ ] Tested automation without CAPTCHA/fingerprinting
- [ ] Tested coupon/referral abuse at scale
- [ ] Tested inventory/ticket scalping scenarios

## API7:2023 - Server Side Request Forgery (SSRF)
- [ ] Tested URL-accepting parameters with internal IPs
- [ ] Tested cloud metadata access (169.254.169.254)
- [ ] Tested blind SSRF with out-of-band detection
- [ ] Tested protocol smuggling (gopher, file, dict)

## API8:2023 - Security Misconfiguration
- [ ] Reviewed CORS policy
- [ ] Checked security headers (HSTS, CSP, X-Frame-Options)
- [ ] Tested TLS configuration
- [ ] Checked for verbose error messages / stack traces
- [ ] Tested unnecessary HTTP methods
- [ ] Checked for debug/test endpoints

## API9:2023 - Improper Inventory Management
- [ ] Discovered shadow/zombie APIs
- [ ] Tested older API versions still accessible
- [ ] Checked for undocumented endpoints
- [ ] Verified deprecated endpoints removed

## API10:2023 - Unsafe Consumption of APIs
- [ ] Checked TLS on all external API calls
- [ ] Tested redirect-following behavior
- [ ] Verified input validation on external API data
