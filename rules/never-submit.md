# Never-Submit List

Findings matching these patterns are NEVER submittable to bug bounty platforms, regardless
of technical validity. This list encodes platform policy, industry consensus, and operational
experience. Read before reporting — a submitted never-submit finding wastes a report slot
and damages reputation.

## How to Use

When evaluating a finding for submission, check it against these patterns. If it matches,
the finding is KILLED (via the 7-Question Gate, Q5) unless the **uplift criteria** are met —
meaning the finding has additional properties that make it submittable despite matching
the pattern.

---

### CORS Without Sensitive Data Exposure

**Pattern:** A permissive CORS policy (`Access-Control-Allow-Origin: *` or origin reflection)
that does NOT expose authenticated/sensitive data.

**Why not submittable:** Most platforms classify CORS as "Not Applicable" or "Informational"
unless paired with actual data exfiltration. A misconfigured CORS header alone is not a
vulnerability — it's a misconfiguration that MAY enable exploitation.

**Uplift criteria:** Demonstrate cross-origin exfiltration of authenticated user data.
Show a PoC where a third-party origin reads a protected API response that includes PII,
tokens, or private content. CORS + data = finding. CORS alone = not submittable.

---

### Missing Security Headers Without Demonstrable Impact

**Pattern:** Missing `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`,
`Referrer-Policy`, or `Permissions-Policy` headers, without proof that their absence
enables a concrete attack.

**Why not submittable:** Missing headers are hardening recommendations, not vulnerabilities.
Platforms require proof that the missing header enables a specific, exploitable attack.

**Uplift criteria:** Demonstrate the attack that the missing header would prevent. Missing
CSP + demonstrated XSS = submittable (the XSS is the finding; missing CSP is a mitigation
gap). Missing X-Frame-Options + demonstrated clickjacking on a sensitive action = submittable.

---

### Deprecated TLS Without Exploitable Downgrade

**Pattern:** TLS 1.0/1.1 support, or weak cipher suites, without demonstrating a practical
downgrade attack that exposes sensitive data.

**Why not submittable:** Most platforms consider this a hardening issue. Modern browsers
have deprecated these protocols client-side. The attack requires an active MITM position.

**Uplift criteria:** Demonstrate a working downgrade attack (e.g., POODLE, BEAST, or
a protocol downgrade via MITM) that successfully decrypts sensitive traffic. Version
enumeration alone is not enough.

---

### Rate Limiting on Non-Sensitive Endpoints

**Pattern:** Missing rate limiting on endpoints that do not expose authentication,
sensitive data, or resource exhaustion risks.

**Why not submittable:** Rate limiting is a defense-in-depth measure. On non-sensitive
endpoints (public content, static assets, search without auth), the absence of rate
limiting has no security impact.

**Uplift criteria:** Demonstrate that missing rate limiting enables: account takeover
via brute force, OTP bypass, credential stuffing on the login endpoint, or resource
exhaustion that causes denial of service. Rate limit on login/signup/OTP = submittable.
Rate limit on public search = not submittable.

---

### Self-XSS

**Pattern:** XSS that requires the victim to manually paste or type JavaScript into
their own browser console or URL bar.

**Why not submittable:** Self-XSS relies on social engineering the victim to execute
code in their own context. It bypasses no security boundary. Every platform rejects
self-XSS as a submission category.

**Uplift criteria:** There is no uplift for self-XSS. If the XSS can be triggered
without victim interaction (reflected, stored, DOM-based via a crafted link), it
is no longer self-XSS — submit it as a regular XSS finding.

---

### Clickjacking Without Sensitive Action

**Pattern:** A page can be framed in an iframe, but the framed page contains no
sensitive actions (state changes, data modification, privilege escalation).

**Why not submittable:** Clickjacking requires a sensitive action to be meaningful.
Framing a static about page or a public blog post has no security impact.

**Uplift criteria:** Demonstrate that a sensitive action (password change, money transfer,
permission grant, data deletion) can be triggered via clickjacking through a crafted
transparent overlay. Framed sensitive action = submittable. Framed public page = not submittable.

---

### Information Disclosure That Is Publicly Available

**Pattern:** The application reveals information that is already publicly accessible
through normal means (e.g., email addresses on a public team page, version numbers
in public documentation, technology stack in public job postings).

**Why not submittable:** Public information is public. Revealing what anyone can already
find is not a vulnerability.

**Uplift criteria:** Demonstrate that the disclosed information is NOT publicly available
through legitimate means, AND that the disclosure enables a concrete attack (credential
access, privilege escalation, account takeover). Internal-only info leaked externally = submittable.

---

### Missing Cookie Flags Without Consequence

**Pattern:** Cookies missing `Secure`, `HttpOnly`, or `SameSite` flags, without
demonstrating that the missing flag enables a concrete attack (e.g., cookie theft
via active XSS, CSRF on a state-changing endpoint).

**Why not submittable:** Cookie flags are hardening measures. Without an active attack
that exploits their absence, missing flags are "best practice" findings.

**Uplift criteria:** `HttpOnly` missing + demonstrated XSS that steals the cookie = submittable
(the XSS is the finding). `Secure` missing + demonstrated MITM on a non-HTTPS connection
that captures the cookie = submittable. `SameSite` missing + demonstrated CSRF on a
state-changing endpoint = submittable.

---

### Rate-Limit Bypass via Header Manipulation (Submit the Bypass, Not the Limit)

**Pattern:** "Missing rate limit" finding when the actual discovery is that rate limiting
can be bypassed via `X-Forwarded-For`, `X-Real-IP`, or similar header manipulation.

**Why not submittable:** The finding is misclassified. The real vulnerability is the
header-based bypass, not the rate limit itself.

**Uplift criteria:** Reclassify as "Rate Limit Bypass via Header Manipulation." The
bypass IS the finding. Submit THAT, with the header manipulation as the attack vector.
Frame it as authentication abuse (if the bypass enables brute force) rather than a
rate-limit weakness.

---

### Blind SSRF With No Internal Reach

**Pattern:** A server-side request that fires but returns nothing and lands nowhere
interesting -- typically a callback proving only that the target fetched a public URL you
supplied, in a feature whose whole job is fetching URLs (webhook target, link preview,
avatar import, RSS/feed subscription).

**Why not submittable:** A webhook reaching the public internet is the product working as
designed. The callback proves reach, and reach is the floor of the class, not its impact
(hunting Rule 32). Programs dismiss these as informational at volume, and blind webhook
SSRF is among the most duplicated reports on any mature program.

**Uplift criteria:** Climb the response channel or defeat a control, and say which:
- **Internal reach** -- the request landed on link-local, RFC1918, loopback or a named
  internal service, not just the public internet.
- **A filter defeat** -- an allowlist, denylist or post-resolution IP check was bypassed
  (redirect chain, DNS rebinding, parser confusion, an alternate address encoding).
- **A response channel above blind** -- the internal response came back through a named
  oracle: reflected content, an error body, a delivery log, the rendered artifact, a
  measurable timing or length differential.
- **Credential or execution** -- instance metadata, a service-account token, or a raw-socket
  protocol chained into a command.

Record the rung with `--channel-rung` at creation; the evidence gate enforces it, so a
blind primitive filed honestly as a Medium is fine and a blind primitive dressed as a
Critical is refused.

---

### Impact Cannot Be Demonstrated

**Pattern:** Any finding where the impact statement is speculative ("could potentially,"
"might allow," "may result in") without a concrete, reproducible demonstration.

**Why not submittable:** Bug bounty platforms require demonstrated impact. Speculative
impact is a theoretical finding — it stays in the "unvalidated" appendix.

**Uplift criteria:** Reproduce the impact. Show the data you accessed, the privilege
you gained, or the action you performed. Replace "could potentially expose user data"
with "exposed user PII for 3 accounts: names, emails, and phone numbers." Concrete
impact = submittable. Speculative impact = not submittable.

---

## Gate Triggers (machine-readable)

The 7-Question Gate (`validate-finding.sh --gate`, Question 5) parses the table
below. Each line is `pattern-id | trigger-regex | uplift-regex`. If a finding's
title+description matches the **trigger** regex AND does NOT match the **uplift**
regex, Q5 returns KILL. An uplift of `-` means "no uplift — always kill on trigger"
(e.g. self-XSS). Regexes are matched case-insensitively (grep -iE). Keep this in
sync with the prose patterns above.

<!-- GATE-TRIGGERS
cors-no-data | \bcors\b|access-control-allow-origin | exfiltrat|steal|read.*(pii|private|authenticated|sensitive)|account takeover|csrf token
missing-headers | missing.*(header|csp|x-frame|hsts|content-security)|security header(s)? (are |is )?missing | demonstrated|chained|leads to (xss|clickjack)|proven
deprecated-tls | (tls|ssl).{0,12}(1\.0|1\.1|v3|deprecated|weak cipher|poodle|beast|sweet32) | downgrade.*(decrypt|captur)|mitm.*(decrypt|captur)|active.*decrypt
rate-limit-nonsensitive | (rate.?limit|throttl|too many requests) | login|sign.?in|otp|password reset|brute.?force|credential stuffing|account takeover|enumeration
self-xss | self.?xss | -
clickjacking | clickjack|x-frame-options|frameable|iframe.*embed | password change|fund|transfer|delete account|sensitive action|state.chang|grant permission
public-info-disclosure | (information disclosure|info(rmation)? leak).{0,40}(public|already available|publicly) | internal|credential|token|not publicly|private key
cookie-flags | (httponly|samesite|secure flag|cookie.{0,10}flag|cookie.{0,10}attribute) | demonstrated xss|active xss|csrf.*state.chang|mitm.*captur
ratelimit-bypass-misclass | rate.?limit.{0,20}(bypass|circumvent).{0,20}(via|using|with).{0,20}(header|x-forwarded|x-real-ip) | -
ssrf-no-internal-reach | \bssrf\b|server.?side request forgery | 169\.254|metadata|link.?local|rfc1918|127\.0\.0\.1|localhost|internal|credential|iam role|service account|filter bypass|allowlist bypass|denylist|rebind|port scan|gopher|10\.[0-9]|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.
speculative-impact | could potentially|might allow|may result|may expose|theoretically|in theory | demonstrated|reproduced|exposed (the|user|pii)|gained (access|admin|root)|exfiltrat
GATE-TRIGGERS -->

> Note on `self-xss` and `ratelimit-bypass-misclass` (uplift `-`): these are never
> submittable *as described*. The fix is to reclassify (a non-self XSS is a regular
> XSS finding; a rate-limit bypass is an auth-abuse finding) — submit the reclassified
> finding under its real class, not the never-submit framing.
