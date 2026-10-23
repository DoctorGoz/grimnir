---
name: ssrf
description: Server-Side Request Forgery discovery and escalation (API7:2023 / CWE-918). Find the fetch primitive, establish the response channel, defeat the filter, and climb from blind to credentials. Pairs with nimbus/metadata-ssrf for the cloud half.
allowed-tools: Read, Grep, Glob, Bash
---

# SSRF Testing Skill (API7:2023 / CWE-918)

**The one thing to internalize before starting.** SSRF is not scored by the request. It is
scored by **where the request lands and whether the response comes back**. The same primitive is
worth nothing and worth a critical depending on those two facts. Most SSRF reports never earn
anything because they are filed at the moment the request fires, which is the beginning of the
work rather than the end of it. Read hunting Rule 32 before you write anything up.

This skill owns **discovery, the response channel, and filter defeat**. The cloud escalation lives
in `nimbus/.claude/skills/metadata-ssrf/SKILL.md`; hand off rather than duplicating it.

## Prerequisites
- A mapped surface (`api-recon` run, or HUGINN's asset map plus crawled JS).
- The OOB listener reachable from the public internet (`scripts/confirm/oob-listener.py`).
  **Run `oob-client.py preflight` first** — it prints the vantage, tests each port, and fires a
  full journalled loop. Add `--external` to prove the *internet* reaches it: the plain loop never
  leaves the host, so it cannot see an inbound firewall rule, and that rule turns every probe into
  a false negative that closes the lane (see feedback-oob-listener-external-reachability).
  Config comes from the environment or `~/.grimnir/oob/config.env`; `mint` refuses to run at all
  while the base is still the placeholder.
- A DNS channel, if you have a delegated zone: `dns-rebind.py --domain <zone>` plus
  `GRIMNIR_OOB_DNS_DOMAIN`. Without it, a target that resolves your hostname but cannot connect
  out is indistinguishable from a target with no SSRF.

## The response-channel ladder

Everything below serves one goal: climbing this ladder. Record which rung you reached in the
finding itself.

| Rung | You have | Ceiling |
|---|---|---|
| `blind` | The request fires. Nothing returns. | Low/Medium, heavy dupe risk |
| `partial` | An `og:` field, an error string, a status code, a length or timing delta | Medium/High |
| `full` | The whole response body | High |
| `credential` | Cloud role credentials, tokens, keys in the body | Critical |
| `execution` | RCE, root, or account takeover on the reached host | Critical |

## Methodology

### Step 0: Read what HUGINN already tagged
Phase 0 runs `huginn/scripts/fetch-surface.py`, which records `fetch_surfaces[]` on the asset
map and merges the same tokens into `endpoints[].tags`. Start there rather than from scratch:

```bash
bash huginn/scripts/fetch-surface.sh --project-dir "$PROJECT_DIR"      # re-run/report
jq -r '.fetch_surfaces[] | "\(.confidence)\t\(.surface)\t\(.evidence[0])"' \
   "$PROJECT_DIR/asset-map.json"
```

Treat the `confidence` column honestly. `strong` means a parameter literally named like a URL
or a path segment that names a fetch feature. `weak` means a path merely *contains* a word like
`preview`. **None of it means the server dereferences anything** - that is what Step 3 proves.
If the map shows nothing, that is usually a crawl-depth problem rather than an absence of
surfaces; go to Step 1 and enumerate by hand.

### Step 1: Map the four surfaces
SSRF hides wherever the server fetches something for you. Work all four; most testers only work
the first.

1. **Fetch-by-URL features.** Import, attach-by-URL, avatar/logo by URL, link unfurl, RSS,
   "test this endpoint", image proxies. Playbook: `ssrf-fetch-by-url`.
2. **Processing pipelines.** Transcoders, thumbnailers, document converters. The parser inside
   follows references in the file you uploaded. Playbook: `ssrf-processing-pipeline`.
3. **Rendering bots.** Screenshot, preview, HTML-to-PDF, og-scrapers. A real browser executes
   your content from the server's network position. Playbook: `ssrf-rendering-bot`.
4. **Outbound callbacks.** Webhooks, integrations, OAuth metadata and dynamic client
   registration. Must reach external hosts by design, so the filter is bolted on.
   Playbook: `webhook-ssrf-deblind`.

Two shapes sit outside that map and are missed by a parameter-driven plan:

5. **No URL parameter at all.** A server-rendered framework rebuilds its own absolute base URL
   from the inbound `Host` / `X-Forwarded-Host` header in order to call itself. Every URL in the
   request stays legitimate while the attacker chooses the host the server dials.
   Playbook: `ssrf-host-header-framework`.
6. **Dereferenced later, by something else.** The value is stored by one component and fetched
   minutes or hours later by a worker, a scheduled sync, an export, or an admin view. Nothing
   happens on the request that plants it, so immediate-feedback testing calls the field inert.
   Plant a **distinct** nonce per field or the callback cannot be attributed to a sink.
   Playbook: `ssrf-second-order`.

### Step 2: Enumerate every URL-bearing input
Parameters, JSON fields, XML nodes, multipart fields, and headers. Grep crawled JS bundles for
both the parameter names and the client-side function names that build these calls.

Parameter names: `url uri src href link dest destination target source path file document image
imageUrl avatar logo icon banner feed rss webhook callback callbackUrl return returnUrl next
redirect redirect_uri endpoint host domain proxy fetch load import importUrl remote remote_url
remote_attachment_url upload_url download_url preview unfurl page site data resource`

Headers the server may trust and follow: `X-Forwarded-For X-Forwarded-Host X-Original-URL
X-Rewrite-URL X-Host Forwarded Referer`

JS symbols worth grepping: `fetchRemote loadExternal proxyRequest getPreview importFromUrl
unfurl fetchUrl downloadFrom`

Use `scripts/js-endpoints.py` over the crawled bundles, and Rule 24 memory-safe grep on minified
files.

### Step 2b: Mine captured traffic in Caido
Organic traffic is the best candidate list you will get, because it shows parameters the UI
actually populates. Three filter presets ship in Caido (`SSRF: URL-bearing params`,
`SSRF: fetch-surface paths`, `SSRF: server-side fetcher UAs (inbound)`) for clicking in the UI.

From the CLI they work too - `search` expands `preset:` client-side by alias, name or id and
reports the substituted query as `expandedFilter`. That expansion is a fix: Caido's server
silently returned the **unfiltered** set for a `preset:` clause (500 rows against 3 for the
equivalent inline regex), and an unknown preset now throws instead. Either form is fine:

```bash
npx tsx .claude/skills/caido-mode/caido-client.ts search 'preset:"ssrf-params"' --limit 100
```

```bash
C=.claude/skills/caido-mode/caido-client.ts
# URL-bearing parameters
npx tsx $C search 'req.query.regex:"(?i)(^|&)(url|uri|src|source|href|link|target|dest|endpoint|fetch|image_?url|avatar|logo|icon|feed|rss|callback|callback_?url|webhook|remote_?url|import_?url|attachment_?url|proxy|redirect_?uri|return_?url)="' --limit 100
# paths that name a fetch feature
npx tsx $C search 'req.path.regex:"(?i)/(unfurl|oembed|opengraph|link-?preview|screenshot|snapshot|thumbnail|thumb|transcode|imageproxy|_next/image|convert|to-?pdf|webhooks?|hooks|deliveries|import|fetch-?remote)(/|$|\\?)"' --limit 100
# host-header candidates (inline: Caido refused a 4th preset on this instance, cap ~3)
npx tsx $C search 'req.raw.regex:"(?i)(X-Forwarded-Host|X-Original-Host|X-Host|X-Forwarded-Server|Forwarded):"' --limit 50
```

Then use `edit` rather than a hand-built request, so cookies and auth headers survive intact:

```bash
npx tsx $C edit <request-id> --replace 'https://legit.example.com:::http://169.254.169.254/latest/meta-data/'
```

### Step 3: Confirm the fetch, and fingerprint the fetcher
Point each candidate at the OOB listener. When the callback arrives, **read it carefully** — it
carries more than a yes/no:

- **Source IP** — is this the target's infrastructure or your own browser? Loopback and RFC1918
  answers from your own scanner are not SSRF (hunting Rule 30).
- **User-Agent** — `python-requests/`, `Go-http-client/`, `Java/`, `Apache-HttpClient/`,
  `okhttp/`, `curl/`, or a headless Chrome string. This predicts scheme support, redirect
  behaviour, and which parser-confusion bypasses will work.
- **Timing** — synchronous with your request, or queued and delivered later? An async fetch means
  the response will never reach you directly and the channel must be found elsewhere.

```bash
python3 scripts/confirm/oob-client.py preflight                  # do this once, first
python3 scripts/confirm/oob-client.py mint --label 'url= on POST /import'
# plant it, then wait before judging:
python3 scripts/confirm/oob-client.py poll NONCE 120
PROJECT_DIR="$PROJECT_DIR" python3 scripts/confirm/oob-client.py verdict NONCE SPE-NNN ssrf full
```

The 2-hop URL is not decoration: a callback on the second hop proves the port allowlist was
bypassed, which is a separate claim from proving the fetch happened.

**A silent probe is two different results.** No callback means either the target never fetched, or
it fetched and could not reach you. Where a DNS channel is running, plant the `<nonce>.<zone>` host
instead: a logged DNS query with no connection separates "inert parameter" from "egress-blocked
fetch", and only the first is a real negative (hunting Rule 27). `verdict` records that case as
`dns_only` and holds it at the `blind` rung.

### Step 4: Find the oracle — do this before payload work
This is the step that decides the value of everything else, and it is the step most often
skipped. Fetch a target you control that returns a large, distinctive, easily-recognized body.
Then hunt the entire product for anywhere that content, or any property of it, surfaces:

- the rendered page or the API response (full read)
- a generated artifact: thumbnail, transcoded file, exported PDF, screenshot (full read)
- a single reflected metadata field from an unfurler, e.g. a title (partial read)
- a delivery or job log showing status, headers, or body (partial to full)
- an error message quoting the first bytes or naming the internal host (partial)
- a response-length or duration delta between a known-open and known-closed internal port (partial)
- nothing at all (blind — keep climbing before you write it up)

**Coerce a renderable shape.** Where the channel only returns rendered output, an internal
endpoint that answers `text/plain` may simply not be drawn. Request a JSON or HTML representation
of the same path so the response ends up inside the artifact. This single move is routinely the
difference between a blind report and a credential leak.

### Step 5: Establish internal reach
With the channel known, sweep. Loopback, RFC1918, link-local, CGNAT, the platform's own internal
service names, and `.cluster.local` style discovery names where containers are in play. Port
list and per-service chains: `wordlists/ssrf-internal-services.txt`.

### Step 6: Defeat the filter
Only if step 5 is blocked. The ladder, in order of cost:

1. **Alternate address forms** — `wordlists/ssrf-address-forms.txt`. Decimal, octal, hex, mixed
   and overflow encodings; IPv6 loopback and unspecified; IPv4-mapped IPv6; the NAT64 well-known
   prefixes; a trailing dot; a public hostname resolving inward.
2. **Parser disagreement** — `wordlists/ssrf-parser-confusion.txt`. Userinfo splitting, fragment
   and query placement against substring-anywhere validators, whitespace and control characters
   around the netloc, over-long schemes, IDNA normalization gaps, CRLF Host smuggling.
3. **Redirects** — serve a redirect from an allowed host. Test **301, 302, 303, 307 and 308
   separately**. A client documented as not following redirects frequently follows exactly one of
   them, and that exception is the finding. 307/308 preserve method and body.
4. **DNS rebinding** — where the validator resolves and the client resolves again.
   `dns-rebind.py --mode rebind --public <ip> --internal <target> --domain <zone>` behind a
   delegated domain; it alternates per hostname, so a parallel probe cannot desynchronise the
   flip. Also test the *unresolvable* case: some filters fail open when a name does not resolve
   cleanly.

Full lane: playbook `ssrf-parser-confusion-rebind`.

**Diagnose which layer is blocking before grinding.** A string-match validator, a
post-resolution IP check, and a network-layer egress block produce different rejection shapes.
Only the last is genuinely closed; the first two are open lanes. Grinding encodings against a
network egress block is pure spend.

### Step 7: Escalate
- **Cloud host** → hand to Nimbus, `nimbus/.claude/skills/metadata-ssrf/SKILL.md`, playbook
  `ssrf-cloud-metadata`. Do **not** write off token-required metadata (AWS IMDSv2) as closed
  until you have checked whether the primitive can express a method and a header — a webhook with
  custom headers or a JavaScript-executing renderer can run the handshake from the workload
  itself.
- **On-prem or self-hosted** → playbook `ssrf-gopher-internal-rce`. Probe scheme support first
  (`gopher dict file ftp sftp tftp ldap netdoc jar`); a raw-socket scheme turns the primitive into
  an arbitrary TCP client.
- **Blind and staying blind** → the canary chain. Find an internal service that will itself make
  an outbound request when asked and point it at the listener. Its callback proves reach through a
  channel the primary primitive never had, and often returns the body.

## Payloads / wordlists
- `wordlists/ssrf-address-forms.txt` — alternate representations of loopback and link-local
- `wordlists/ssrf-parser-confusion.txt` — URL grammar attacks against split-decision validators
- `wordlists/ssrf-internal-services.txt` — port sweep plus the per-service chain catalogue
- `nimbus/wordlists/cloud-metadata-endpoints.txt` — provider endpoints with header requirements
- `wordlists/payloads-index.md` — the indexed cross-class payload library

## Validate (negative control)

- **Attack:** the callback arrives at the OOB listener **from the target's infrastructure**,
  during the request, with the minted nonce. For an escalated finding, the response content is
  additionally shown coming back through the identified channel.
- **Negative control:** the same primitive with a non-existent or non-resolving host produces no
  callback, and a control host you did not plant produces none either. For a filter-bypass claim,
  show the *plain* internal value is rejected and the bypassed form is not — otherwise you have
  documented intended behaviour, not a bypass.
- A callback arriving minutes later or from an unrelated IP is not proof (hunting Rule 11).

## Evidence to capture
The request carrying the payload, the listener log line with source IP, User-Agent and timestamp,
and — for anything above the blind rung — the response content arriving through the named channel
(the rendered artifact, the delivery log entry, the reflected field). State the rung explicitly.
Redact credential material to a recognizable prefix; never paste a live key into a report
(hunting Rule 28).

## False-positive traps
- **Your own scanner's loopback answers.** `127.0.0.1`, `0.0.0.0` and RFC1918 responses observed
  from your own vantage are your infrastructure, not the target's (hunting Rule 30). Run
  `hostname` and confirm the vantage before writing a reachability verdict.
- **A feature that is supposed to fetch arbitrary URLs.** A webhook reaching the public internet
  is the product working. The claim must involve internal reach or a filter defeat.
- **DNS-only callbacks.** A DNS lookup without a connection can come from a security scanner, a
  resolver cache, or a link-preview safety check rather than the fetch you think you triggered.
- **A rejection that is not identity-sensitive.** Before recording a lane as filtered, prove the
  filter is actually reacting to the target and not to a malformed URL (hunting Rule 27).
- **Third-party infrastructure.** An embedded widget or vendor service fetching your URL is that
  vendor's surface and is usually out of scope.

## Validate & Promote

Findings from this skill are born `theoretical` (see the validation layer in the repo-root
`CLAUDE.md`). They do not enter a report or an external submission until promoted to `confirmed`
via `scripts/validate-finding.sh` after the independent check above.

**Produce the proof with the harness, then promote from it.** The primitive writes
`$PROJECT_DIR/evidence/<id>/verdict.json`; `--from-evidence` reads that record and promotes only
if it says `confirmed`, carrying the class, control and method across.

```bash
# 1. record the class AND the response-channel rung up front
bash scripts/finding.sh --project-dir "$PROJECT_DIR" --agent specter --severity high \
  --title '<what you proved>' --description '<...>' --impact '<...>' \
  --class ssrf --channel-rung full

# 2. produce the proof
python3 scripts/confirm/oob-client.py mint
PROJECT_DIR="$PROJECT_DIR" python3 scripts/confirm/oob-client.py verdict NONCE SPE-NNN ssrf full

# 3. promote from the artifact
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent specter \
  --id SPE-NNN --from-evidence
```

**`--channel-rung` is enforced, not documentation.** The evidence gate refuses a `critical`
promotion unless the recorded rung is `credential` or `execution`, and a `high` promotion unless
it is `full`, `credential` or `execution`. An absent rung resolves to `blind`, so forgetting the
flag blocks the over-claim rather than waiving the check. You can also supply it at promotion
time (`--channel-rung credential`). If the rung genuinely understates the impact, say why in
`--note` and override with `GRIMNIR_EVIDENCE_GATE=warn` - but the honest path is to file at the
severity the channel supports.

Manual promotion is the fallback for when the harness cannot reach the target:

```bash
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent specter \
  --id SPE-NNN --state confirmed --method out-of-band --method manual-repro \
  --negative-control "payload -> callback from <target ASN> UA python-requests/2.31 at T+0.4s; non-resolving control host -> no callback; plain 169.254.169.254 -> rejected, mapped-IPv6 form -> accepted" \
  --by specter
```

**Severity by rung, not by class.** Blind with no channel is Medium at best and frequently a
duplicate. Do not inflate; an honest rung with a clear negative control survives triage, and an
aspirational one does not (see feedback-honest-cvss-beats-aspirational-severity).

## Related
- `nimbus/.claude/skills/metadata-ssrf/SKILL.md` — the cloud credential half
- `specter/.claude/skills/xxe/SKILL.md` — entity-driven fetches in the pipeline surface
- `specter/.claude/skills/open-redirect/SKILL.md` — the redirect half of the bypass ladder
- `specter/.claude/skills/file-upload/SKILL.md` — getting a payload into the pipeline surface
- Playbooks: `ssrf-fetch-by-url`, `ssrf-processing-pipeline`, `ssrf-rendering-bot`,
  `webhook-ssrf-deblind`, `ssrf-parser-confusion-rebind`, `ssrf-gopher-internal-rce`,
  `ssrf-cloud-metadata`, `agent-tool-ssrf`, `ssrf-host-header-framework`,
  `ssrf-second-order`
