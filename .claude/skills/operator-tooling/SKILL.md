---
name: operator-tooling
description: Operator-facing tooling used directly during an engagement, not delegated to a specialist — APK extraction, the confirmation harness (theoretical to confirmed), the intelligence layer (reachability + brief + fertility), attack playbooks, the decision log, SARIF findings export, session upkeep for our own test accounts (harvest, refresh, login), and the coverage gate. Invoke when running any of these tools or when deciding where to spend testing effort.
---

# Operator Tooling

Operator-facing capabilities used directly during an engagement (not delegated to a specialist). Each tool's usage is also documented at its point of use — the relevant agent definition or slash command — this skill is the single index.

## APK extraction

`bash scripts/pull-apk.sh <package.id> [output_dir]` pulls an installed app's APK(s), including split APKs, over `adb` (requires exactly one authorized device). Writes to `$PROJECT_DIR/apk/<pkg>` when `PROJECT_DIR` is set, else `./apk/<pkg>`. Find the id with `adb shell pm list packages | grep <name>`, then decompile with `jadx` and feed endpoints/secrets back into recon.

## Confirmation harness (`scripts/confirm/`)

Converts `theoretical` findings into `confirmed` ones with reproducible proof (the yield bottleneck). Non-interactive primitives, each emitting a machine-readable `verdict.json`:

- `oob-listener.py` / `oob-client.py` — self-hosted out-of-band recorder for blind SSRF/injection/IMDS; 2-hop redirect proves port-allowlist bypass; echoes trace headers for self-correlation.
- `authz-confirm.py` — 4-way BOLA/IDOR/BFLA differential (own/cross/nonexistent/malformed); confirms only on distinguishable victim data, records the `negative_control`.
- `authn-confirm.py` — missing authentication. Replays one of our own authenticated GETs three ways: as captured (`own`, the positive control), with every credential header stripped (`anon`), and with the second account's credentials (`other`, optional). See [Missing-authentication lanes](#missing-authentication-lanes-authn).
- `tier-confirm.py` — function-level authorization. Replays a high-tier account's read as the high tier (positive control), as a lower tier, anonymously, and, on a scope that doesn't exist, as both tiers. See [Tier-differential lanes](#tier-differential-lanes-tier-function-level-authorization).
- `render-confirm.py` — headless Chromium proving an XSS/DOM payload executed vs escaped, with screenshot.
- `poc-export.py` — bundles `evidence/<id>/poc/`.

**Firing a primitive by hand.** Read-only verbs on safe routes are fine to repeat. Writes (POST/PUT/PATCH) go only to objects in your own tenant with an account you hold. Never fire these without an explicit operator go-ahead: an account-level action (email, phone, password, MFA, account deletion; Rule 33), anything with financial effect (payments, orders, credits, balances), DELETE, or a race burst. Mark an account `scarce: true` in `credentials.jsonl` when it is expensive to replace (phone-verified, KYC'd, purchase-gated, invite-only, device-bound) and do not spend it on writes. Add `cookie_domains: [".acme.example"]` to an account whose `Cookie` header was minted for specific sites so its credentials are never sent elsewhere. `bopla-confirm.py` writes the baseline value back after a write that stuck; the restore result is in the evidence. Flags for every primitive: `scripts/confirm/README.md`.

**Evidence gate**: `scripts/validate-finding.sh` HARD-blocks promotion of High/Critical findings without the class-appropriate artifact (WARN for Low/Med; `GRIMNIR_EVIDENCE_GATE=warn|off` to relax). Record the class once at creation (`finding.sh --class`); the gate re-derives it, so a promotion cannot skip enforcement by omitting a flag.

**Promote from the artifact, not by retyping it**: `validate-finding.sh --from-evidence` reads `evidence/<id>/*.json` and promotes only if a primitive recorded `verdict: confirmed`, carrying the class, negative control, screenshot and method across; `--scan` lists findings proven on disk but not yet promoted (hunting Rule 29). Makes "confirmed" mean a triager can reproduce it.

## Missing-authentication lanes (`authn`)

The `authn` class (alias `missing-auth`, playbook `missing-auth-replay`) tests whether a route the client only calls with a session also answers without one. It needs no payloads: the input is traffic you already captured.

- **Where candidates come from:** the successful authenticated GETs in the captured corpus, which are the `authed-traffic` endpoints `caido-export.py` writes. Export and rebuild the corpus first, pick routes by hand, and run `authn-confirm.py` on each.
- **Verdicts:**
  - `confirmed`: the anonymous 2xx carries a private marker (email, phone) that the owner's response also carries. Also confirmed: the second account reads a private marker from a URL that names the owner's object (`--own-id`).
  - `authn-likely` (candidate, parks for review): the anonymous response carries a public identifier (user id, handle). Or it matches the owner's response while the second account gets a different one, which means the response is per-account.
  - `negative`: the anonymous request is denied, gets a different response with none of the owner's data, or every caller gets the same public content.
  - `inconclusive`: the owner's request failed, or the arms match with nothing marking the data as the owner's.
- **The wall control (Rule 27).** When the anonymous arm gets a 403, the oracle also requests the host root anonymously. If the root is 403 too, a bot wall or WAF is refusing all anonymous clients. That 403 isn't the route's auth check, so the verdict is `inconclusive`, not `negative`. The host is cached as walled for the day in `evidence/authn-walls.json`, and later lanes on that host return `inconclusive` without sending a request. A walled host isn't covered by authn: report it as untested, not clean.
- **Markers:** pass the owner's identifiers so a match can be attributed. A marker that also appears in the URL counts for nothing.
- **Promotion:** `validate-finding.sh` accepts a confirmed `evidence/<id>/authn.json` in place of a hand-recorded negative control.
- **Scope of the class:** the cross arm uses an account of the same role, so authn covers missing authentication and same-role cross-account reads. It does not test function-level authorization (a lower role reaching a privileged route). That's the `tier` class.

## Tier-differential lanes (`tier`, function-level authorization)

The `tier` class (playbook `tier-differential`) tests whether a route only a privileged role calls also answers a lower role. Findings it creates carry class `tier` (API5, CWE-285).

1. **Label the tiers** in `credentials.jsonl`: `tier_rank` (an integer, higher is more privileged) and `tier` (a name) on each account. On the high-tier account, set `tier_scope` to what it administers (a community, org, or project name as it appears in URLs) and, once seeded, `tier_markers` (privileged-only strings; see step 5).
2. **Crawl as the high-tier account through Caido.** `session.py storage-state --project-dir DIR --account B --out FILE [--fingerprint-from OLD_SESSION]` writes the account's cookie session as an `authed-crawl.py` session file (mode 600), with the User-Agent from `request-headers.json` and, optionally, client hints from an earlier session file. Then run `authed-crawl.py --project-dir DIR --session-source caido --session-file FILE --start <privileged pages> --spider --proxy http://127.0.0.1:8080 --live`. The spider doesn't click moderation or membership actions (Approve, Ban, Mute, Leave, Lock, Block, Report), and route-aborts every mutating request.
3. **Export with attribution:** `caido-export.py` tags each record with `accounts: {label: status}`, from a stored session token in the request's Authorization or Cookie header, or a JWT there whose subject or email names a vault account.
4. **Pick the routes:** the privileged set is the 2xx GET route templates the highest-tier account read that no lower-tier account ever requested, restricted to routes naming `tier_scope` when it's set. Replay each as the lowest-tier account with `tier-confirm.py`.
5. **Verdicts:**
   - `confirmed`: the low-tier 2xx carries a `tier_markers` string that the high-tier response carries and the anonymous response doesn't.
   - `tier-likely` (candidate): the low tier gets the high tier's page (both accounts' identifiers blanked), the anonymous caller doesn't, and the page differs for a scope that doesn't exist. To confirm, seed a marker: as the high-tier account, put a unique string in a privileged-only field on your own scope (a removal reason, a moderation note), add it to `tier_markers`, and refire. That's a write, so the operator makes it.
   - `negative`: the low tier is denied (401/403/404/redirect), gets a different view, gets the same page it gets for a scope that doesn't exist, or the page is public.
   - `inconclusive`: the high-tier positive control failed (an expired session, or a host that blocks the replay client even with credentials), or the high tier's own page is the same for a scope that doesn't exist. That page is an app shell that loads its data from another request (a GraphQL POST, or a server-rendered partial the page fetches after load), so neither a match nor a difference means anything.
   - **Derived markers:** with a scope token, the oracle also repeats the high request and takes the tokens the high tier's page carries for the real scope but not for a nonexistent one. It drops tokens the repeat doesn't carry (per-request noise), tokens the anonymous caller gets, and tokens naming the scope. This catches a few-kilobyte privileged section in a large page, which passes the similarity bar against its nonexistent-scope twin. With at least 5 derived markers, a low tier carrying at least 50% of them is `tier-likely`, and one carrying at most 10% is `negative`. Derived markers include public scope data (a community's title), so they never confirm. `tier.json` records `derived_markers` and `low_carries`.
- **Promotion:** `validate-finding.sh` accepts a confirmed `evidence/<id>/tier.json` in place of a hand-recorded negative control.
- **GraphQL reads.** Many SPAs load their privileged data through GraphQL POSTs, which a GET replay never sees. `scripts/graphql_ops.py` judges a body: query text is definitive (`query` vs `mutation`). A name-only operation (`{"operation": "X"}`, a persisted query) counts as `read-likely` only when the name has a read shape (`Get…`, `…Settings`, `…Queue`) and no write word, otherwise `write-likely` or `unknown`.
  - Crawl with `authed-crawl.py --allow-graphql-reads` to let reads out (every other POST stays aborted). Endpoint records list `graphql_ops` (sent) and `graphql_ops_not_executed` (aborted).
  - `caido-export.py` also writes `recon/graphql-ops.jsonl`: one record per operation with its kind, the accounts that sent it, and a per-account sample body with secret-named fields blanked (mode 600).
  - `tier-confirm.py` refuses a POST whose body isn't a read, and treats a 200 carrying only GraphQL `errors` as a failed arm.
  - **Firing:** a body with query text is a definitive read. A name-only `read-likely` operation is a heuristic, so confirm by hand before replaying it.
- **Writes stay human:** the lanes are reads. The privileged actions the crawl recorded as `observed_not_executed` are the next step after a confirmed read, fired by the operator on your own scope with the effect read back as the high tier.

## Intelligence layer

Decides where to spend and where NOT to *before* the expensive testing.

- `scripts/reachability.sh init --project-dir DIR` labels each high-value lane REACHABLE / GATED(gate) / UNKNOWN against the gate taxonomy (kyc, funded-balance, second-account, device, paid-tier, geo-egress, browser-interactive, otp-2fa, approval-role) — do not plan a primary lane you cannot reach.
- Gates unlock mid-engagement (accounts registered, emulator stood up) — re-sync so the matcher does not silently block a now-reachable lane: `reachability.sh set-gate --gate G --held true|false` flips one gate, `reachability.sh sync` re-derives second-account from the creds files present.
- `scripts/brief.sh init --project-dir DIR` fuses reachability + the lessons loader + fertility + the intake's focus areas into one spend/skip/gated prior.
- Log a dead lane with `bash scripts/event-emitter.sh record-negative --lane L [--class C] --program P`.
- `scripts/fertility.sh band|score|show <handle>` modulates the dig-vs-pivot threshold (a HOT surface raises it).

Both reachability and brief run at `/engage`; see hunting Rules 20-23 for the discipline they encode.

## Attack playbooks, decision log, findings export

- `scripts/playbook.py match --project-dir DIR` ranks the declarative attack chains in `rules/playbooks/*.yaml` (schema: `schemas/playbook.schema.json`) against HUGINN's asset map + intel signals and the reachability gates, printing each REACHABLE / BLOCKED(gate) / UNKNOWN so the plan leads with lanes the operator can actually reach. `playbook.py plan <id> --project-dir DIR` then renders that chain as runnable commands — each step's confirm primitive with its arguments, `finding.sh` with the step's evidence class, and the `--from-evidence` promote (also `list`/`show`/`validate`/`selftest`).
- `scripts/decision-log.sh record --project-dir DIR --type T --reason ...` appends to `decisions.jsonl` the audit trail of WHY a lane was engaged/skipped/deferred — the reasoning `/sitrep` and `/resume` read back (complements `state.json` lifecycle + `intel.jsonl` discoveries + `event-emitter record-negative` dead-lane outcomes).
- `scripts/export-findings.py --project-dir DIR [--format sarif|json]` emits the gate-passing findings (confirmed/validated only, mirroring the `/report` HARD gate) as SARIF 2.1.0 for external vuln managers / pentest deliverables.

## Activity ledger

`$PROJECT_DIR/activity.jsonl` is the one append-only record of work on an engagement: who did what, to which target, with what verdict. `scripts/activity.py` owns the schema, `ACT-NNNNNN` ids (assigned under a file lock), and redaction of token-shaped values before anything is written. Records also roll up to `$GRIMNIR_HOME/activity/activity.jsonl` for queries across programs.

- **Writers record automatically.** `finding.sh`, `validate-finding.sh`, `decision-log.sh`, `event-emitter.sh record-negative`, and `state.sh` (dispatch, completion, blocked) write to it. Shell tools go through `_activity_event` in `event-emitter.sh`.
- **Record interactive work by hand** until the session-digest hook exists: `activity.py append --project-dir DIR --kind probe|negative|note|... --actor operator --summary "..." [--verdict V] [--target URL] [--ref finding:SPE-004]`.
- **Read it:** `activity.py show --project-dir DIR [--kind K] [-n N]`, and `activity.py yield (--project-dir DIR | --all)` for confirm-primitive outcomes by class, playbook, and program.

An activity record is never an authorization. A specialist reads authorization from `decisions.jsonl`, which verifies operator presence.

## Rules of engagement (`roe.json`) and batch firing

`$PROJECT_DIR/roe.json` makes a program's limits machine-readable, so unattended firing can't outrun them. `scripts/roe.py` loads it.

- **Fields:** `max_rps_per_host`, `daily_request_budget`, `required_headers` (overlays `request-headers.json`), `auto_fire_allowed` (`false` means supervised only), `automated_scanning_banned`, `ai_tools_banned`, `quiet_hours_utc`, and `proxy`.
- **`proxy`:** routes all of a program's target traffic through one proxy (`socks5h`, `socks5`, `http` or `https` URL), for programs that block the host's own egress. `GRIMNIR_PROXY` overrides it, and the confirm primitives pass it to every request they send. `scripts/egress.py` is the one reader. It fails closed: an unusable value is refused where it is read (the calling script exits 4, `refused-egress`), and a client that cannot use the proxy refuses rather than connecting directly. Shell scripts read it through `scripts/egress-env.sh` (`egress_init DIR || exit 4`, which evals `egress.py env` and exports `ALL_PROXY`/`HTTPS_PROXY`/`HTTP_PROXY`/`GRIMNIR_PROXY`; the program's proxy replaces any `--proxy`). Wired: the MCP broker and `mcp-enum`/`mcp-probe`/`mcp-call`/`mcp-shadow-scan`; `huginn/scripts/recon-pipeline.sh` and `js-pipeline.sh`; the artemis sprays and probes (`prompt-injection-spray`, `rag-poisoning-spray`, `rag-document-extract`, `system-prompt-extract`, `output-xss-test`, `guardrail-probe`, `agent-tool-enum`, `llm-recon`); `nimbus/scripts/firebase-probe.sh` and `storage-scan.sh`; and `specter/scripts/triage-probe.sh` and `spec-analyzer.sh`. A script with no project dir of its own reads `GRIMNIR_PROXY` from the environment (the caller exports it). When proxied, `recon-pipeline.sh` skips what cannot ride a proxy (naabu, whatweb, `openssl s_client`) and records it in `recon/preflight.json` `skipped_proxied`; `js-pipeline.sh` skips gospider and getJS. The hunter scripts (`host-discovery`, `service-enum`, `vuln-scan`, `smb-enum`, `cred-spray`, `full-audit`) are raw-socket port/service scans that cannot ride a proxy, so they **refuse** (`egress_refuse_if_proxied`, exit 4) when one is set rather than scanning from an unproxied address. Passive third-party lookups (subfinder, gau, waybackurls, the Wayback CDX query, dnsx on public resolvers) are not target traffic and stay direct. Not yet wired: specter `full-audit`/`recon-pipeline`/`graphql-enum`/`rest-api-test` chain Go/Python sub-tools (katana, nuclei, wafw00f, kr, ffuf, arjun, `graphql-probe.py`) whose per-tool proxy support must be verified before they can be made fail-closed — `graphql-probe.py` in particular fetches through bare `urllib` and does not honor egress (a Python-side follow-up); and `nimbus/scripts/metadata-probe.sh` whose `direct` mode probes the host's own link-local IMDS (169.254.169.254), which must NOT be sent through the program's proxy. Run those with `GRIMNIR_PROXY` set only after verifying the underlying tool honors it.
- **No `roe.json` means conservative defaults:** 1 request per second, 300 requests a day, and one unattended lane per run. A malformed value keeps its default. Unparseable quiet hours count as always quiet.
- **Create it once per program:** `roe.py init --project-dir DIR` writes a conservative template. If onboarding left a policy-derived `roe.proposed.json`, `init` takes the stricter values from it. Review the file against the policy before relying on it.
- **Enforcement:**
  - `roe.py` exposes `check_lane` (auto-fire switch, quiet hours, scanning ban, budget) for any harness that fires unattended. An interactive session treats `auto_fire_allowed: false` and an exhausted budget as a stop sign and asks the operator.
  - Every confirm primitive paces each request per host through `scripts/confirm/_pace.py` and counts it against the budget.
  - Quiet hours and the budget bind the operator too.
- **Usage:** `roe.py usage --project-dir DIR` shows today's request count and throttling.
- **`ai_tools_banned`:** an operator opt-in, off by default. When a program bans AI tools, do not run model-driven testing against it.

## Parameter map

`scripts/params.py` records which parameters reach the server and what it does with them. The injection classes (XSS, SSTI, SQLi, cache poisoning) read the result from `$PROJECT_DIR/params.json`.

- **Inventory** (offline): `params.py inventory --project-dir DIR` lists every query, path, and body parameter that `endpoints[]` names, with its sources and a concrete example URL. Re-run `huginn/scripts/corpus-build.py` first if the asset map predates it; archive URLs carry most of the parameters.
- **Probe** (live, read-only): `params.py probe --project-dir DIR` sends, per GET query parameter, one inert canary and, only if it comes back, one request that tags each of `'`, `"`, `<`, `>`, and the backtick with its own canary. It also sends one baseline per endpoint. It records the context (HTML text, attribute, script, JSON, header), which characters came back raw, status changes, and cache headers.
- **Gates:** the probe refuses with no parseable scope (exit 3). Unattended, it refuses on a supervised-only or scanning-banned program (exit 4); `--supervised` lifts both. Every request is paced and counted by `roe.py`, and a run spends at most `--budget-share` (default half) of the day's remaining budget.
- **Order:** each (host, name) is probed once before repeats on other paths, live-crawled before archive-only, and tracking parameters (`utm_*`, `fbclid`) go last. `--max-params` caps a run (default 40).
- **Output:** `params.py show --project-dir DIR --reflected`. Each run writes one `recon` event to the activity ledger and, when something reflected, one intel entry tagged `reflected-<context>` (plus `xss-candidate` when the context's characters came back raw), which `playbook.py match` reads as signals.
- **Injection lanes:** Run the injection confirmers against the map by hand. **SSTI**: one per reflected GET query parameter; `scripts/confirm/ssti-confirm.py` confirms when tagged template arithmetic tracks fresh operands and the bare operands don't evaluate. **SQLi**: one per probed parameter that answered without a server error, likely ones first; `sqli-confirm.py` confirms with a quote-balance pair or two agreeing TRUE/FALSE rounds with a misspelled-keyword control. **XSS**: one per XSS-shaped reflection; `xss-confirm.py` confirms by execution in headless Chromium that fetches only the main document. Escalation (code execution, data reach, session impact) is the operator's step in each playbook (`ssti-reflected`, `sqli-inband`, `xss-reflected`).

## Sessions for our own accounts

`scripts/session.py` keeps each test account's session live, and `scripts/login.py` mints a new one when nothing is left to refresh. Every authed lane reads the result through `credentials.jsonl`.

- **Harvest** (local read): `session.py harvest --project-dir DIR` reads Caido's history (its SQLite files, read-only) for hosts on the engagement's scope domains plus configured auth hosts (`session.py config --auth-host H`). It stores the newest token mint per account and client in `$PROJECT_DIR/sessions.json` (mode 600). It learns the refresh request and the login request as templates, with secrets replaced by placeholders, and flags a refresh token that a later request already spent. Accounts match `credentials.jsonl` by JWT subject or email. `config --alias sub:<id>=<account>` links a subject the vault doesn't name.
- **Exchange** (cross-client minting): when history shows a response minting client Y's token for a request that carried the same account's live session cookie (a web session cookie to an API bearer), harvest learns that request as an exchange recipe, and `get`/`refresh` mint Y from the cookie whenever it has no refresh path. Harvest also records which client's bearer each host accepted, and sync writes per-host bearers (`host_auth`).
- **Liveness by use:** `session.py check --url <who-am-I URL> [--expect REGEX]` sends one GET per live session and marks a 401/403 (or a 2xx whose body misses `--expect`, for endpoints that answer logged-out callers too) as rejected. The URL and pattern are remembered.
- **Get and refresh** (live): `session.py get --account A [--client C]` prints a live access token. When it is near expiry, the refresh runs under a lock, writes a pending marker, journals the raw response (fsynced), and saves the rotated refresh token before returning. A crash mid-refresh recovers from the journal, and a spent or rejected chain is never resent. `refresh --sync` does every entry and copies live credentials into `credentials.jsonl`: each session cookie into the `Cookie` header, the bearer most hosts accept into `token`, and other hosts' bearers into `host_auth`. Vault JWTs whose `exp` has passed move to `token_expired` / `auth_headers_expired` instead of riding along. A one-generation backup is kept in `credentials.jsonl.bak`.
- **Login** (live): `login.py --project-dir DIR --account A` replays the learned login request with the vault's username and password, or drives Chromium through the sign-in page (`--mode browser --login-url URL`; one-page, two-step, and cookie-only sessions). For an OTP login it runs the learned send-code step, carries echoed values such as a challenge id into the verify step, and stops with BLOCKED (exit 5) until the operator supplies the code (`--otp CODE` within 10 minutes, or `--otp-prompt`). A CAPTCHA or bot challenge is always BLOCKED, never attempted. One attempt per account per 15 minutes protects against lockout. `session.py get --login` and `refresh --login` fall back to it.
- **Traffic as corpus:** `scripts/caido-export.py --project-dir DIR` writes the engagement's in-scope Caido requests to `recon/caido-traffic.jsonl` (URL, method, status, body field names, an `authed-traffic` tag; never header or body values, and secret-named query values blanked). `huginn/scripts/corpus-build.py` merges it into `endpoints[]` as live-seen requests.
- **Not covered yet:** minting from another client's refresh token, SMS codes, and device session injection.

## Coverage gate

The accounting system that keeps a claim honest at the end of an engagement.

- `scripts/coverage.py --project-dir DIR [--gate]` reconciles scope against what was actually tested, resolving each high-value item TESTED / SKIPPED / GATED / UNTOUCHED; `--gate` exits non-zero on a REACHABLE+UNTOUCHED must-cover item or an unparseable scope intake, so an engagement is never closed on the strength of the assets that happened to get attention (hunting Rule 25; read by `/progress`, `/sitrep`, `/report`). Always report coverage with its denominator.

