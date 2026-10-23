# Grimnir Hunting Rules

Shared operational rules that all specialist agents ingest at startup. These encode
lessons from live engagements — read them, follow them, and add to them when you
discover a new pattern.

---

## Rule 0 — Harm Check

Will this test cause damage? If yes → **gate behind operator approval.**
- Destructive payloads (DELETE, DROP, rm, shutdown, overwrite) require explicit confirmation
- Version + config evidence is preferred over live exploit on production targets
- For bug bounty: non-destructive proof of impact only (read one record, not a dump)

## Rule 1 — Scope First

Verify the target is in scope before ANY request or scan.
- Check `scope.md` for the engagement's in-scope and out-of-scope entries
- Check `asset-map.json` for discovered assets that have been scope-verified
- If uncertain, pause and ask GRIMNIR before proceeding
- A finding on an out-of-scope target is NOT a finding — it is a scope violation

## Rule 2 — Read Intel First

Before testing anything, check what other agents already found:
```bash
bash scripts/intel.sh route --project-dir "$PROJECT_DIR" --for-agent <agent>
```
- Other agents may have already tested the same surface — don't duplicate work
- Intel from HUGINN pre-populates the feed with discovered endpoints, services, and technologies
- Intel from other specialists may reveal cross-domain attack paths

## Rule 3 — Negative Control Required

Identical-looking cross-account responses are NOT proof of a bypass.
- For BOLA/IDOR/BFLA: test with a non-existent ID as the negative control — it must behave differently
- Owner positive control: the legitimate owner must see DISTINGUISHABLE data at the same endpoint
- For auth bypass: the bypassed request must succeed WHERE a properly-denied request fails
- `identical-response = no-bypass`: if user A and user B get identical responses, it's scoping, not a bug

## Rule 4 — Validate Against Deployed Version

Source-code or repository findings must be verified against the DEPLOYED version.
- Check `Server` header, `X-Powered-By`, and version endpoints for the actual running version
- A vulnerability patched upstream may not be deployed yet — and vice versa
- A feature present in `main` may not be on the deployed tag/branch
- Git history is not deployment history

## Rule 5 — Embedded Chatbots Are Third-Party

Site chat and AI widgets are typically third-party SaaS — often out of scope, and sometimes
not even an LLM.
- Identify the vendor FIRST (inspect the widget DOM, network requests, script src)
- Check scope: third-party SaaS widgets are frequently out of scope
- Verify it IS an LLM before dispatching ARTEMIS — scripted FAQ bots (DigitalCX, etc.) are not AI
- Even if it IS an LLM, confirm it's in scope before testing (the AI provider may be out of scope)

## Rule 6 — Mint Auth Before Building a Rig

Before building an emulator, MITM proxy, or Frida rig for a mobile app, check whether
the app's own login API mints a session token you can use directly.
- Many apps use standard OAuth/OIDC — the token works from curl
- An emulator rig is hours of work; a curl-based token mint is minutes
- Test the login flow from Caido/Burp first — if you can auth without the app, skip the rig

## Rule 7 — Decode JWT Privilege Claims Early

Custom or namespaced JWT claims are privilege signals — decode them immediately.
- `is_employee`, `role`, `subscription_tier`, `tenant_id`, `org_id` → authz boundary signals
- Multiple `aud` claims → the token may be valid across services
- BUT: verify a REACHABLE consumer trusts the claim before scoring impact
- A token with `is_employee: true` that no service checks is a latent finding, not a Critical

## Rule 8 — Sibling Check

Did another agent already test this exact surface?
- Check the intel feed and state.json for tested endpoints before re-testing
- Check existing findings before reporting — two agents finding the same bug is not two findings
- If in doubt, log to intel with `--tag tested` after testing a surface

## Rule 9 — A-to-B Signal

Does a Low-severity finding chain into something higher?
- An open redirect alone is Low; an open redirect that steals an OAuth code is High
- A verbose error alone is Info; a verbose error leaking an internal API key is Critical  
- Flag chain opportunities with `--chain-id` and `--chain-position` in finding.sh
- Before closing a Low finding, ask: "what would I need to chain this with to make it High?"

## Rule 10 — Screenshot for Visual Bugs

UI/DOM bugs, stored XSS, and client-side injection NEED screenshot evidence.
- Use `--screenshot` with `validate-finding.sh` for visual confirmation
- For DOM-based findings: the screenshot must show the exploit running in the browser
- For stored XSS: the screenshot must show the payload executing in the victim context
- The headless browser pipeline provides automated screenshot capture (when available)

## Rule 11 — Out-of-Band for Blind Vulnerabilities

Blind SQLi, blind SSRF, and blind command injection NEED out-of-band callback proof.
- Use InteractSH, Burp Collaborator, or a controlled DNS/HTTP callback server
- The callback MUST arrive from the target's infrastructure during the vulnerable request
- A callback that arrives minutes later or from a different IP is not proof
- Record the callback proof with `--method out-of-band` in `validate-finding.sh`

## Rule 12 — Success Rate for AI Findings

A one-off jailbreak is `validated`, not `confirmed`.
- AI/LLM findings must report success rate: "bypassed guardrail in 3/5 attempts"
- Single-success findings stay at `validated` — the guardrail may have caught it 90% of the time
- For `confirmed`, demonstrate consistent bypass (≥3/5 attempts) AND capture the transcript
- Different seeds/temperatures may produce different results — test across multiple attempts

## Rule 13 — Never Test Prod Destructively

Version + config evidence is better than a destructive PoC on production.
- CVE-2024-6387 (regreSSHion): version banner is sufficient, no need to run the race condition
- SQL injection: prove with a time delay or version extraction, not a DROP TABLE
- Race conditions on payment flows: test on non-production or with minimal value
- The finding is valid without destroying data — and the program will thank you

## Rule 14 — CloudFront/Akamai UA Blocking

Some CDNs block curl's default User-Agent.
- Always use a browser UA string: `-H "User-Agent: Mozilla/5.0 ..."`
- CloudFront, Akamai, and Cloudflare may return 403 or captcha for curl UA
- Test with a browser UA first; if still blocked, the target may be geo-gated or bot-walled

## Rule 15 — Platform Research-Attribution Header

Many platforms support a research-attribution header that ties traffic to your
researcher account for compliance and allowlisting. Send it on all requests.
- HackerOne: `X-HackerOne-Research: <your-h1-handle>` (substitute your own handle)
- Include the header in all PoC examples in reports and documentation
- Other platforms use different headers (or none); check the program's RoE

## Rule 16 — API Tokens Outlive Frontend Blocks

Bearer tokens often work at the API layer even when the web frontend is blocked.
- Akamai/Cloudflare may 403 the HTML page but pass through API requests with valid auth
- FunCaptcha/Arkose may block the OAuth page but the token works on API endpoints
- Capture Bearer tokens early in the engagement while the session is fresh
- Store tokens in the credential registry — they may outlast the frontend block

## Rule 17 — FunCaptcha / VPS IP Blocking

Arkose FunCaptcha blocks OVH/VPS IP ranges server-side — no amount of UA spoofing helps.
- If you hit FunCaptcha on a VPS, try from the operator's residential/mobile IP
- Pre-captured Bearer tokens work from any IP (see Rule 16)
- Consider using a geo-pivot VPS in a different provider's IP range as fallback
- The block is at the IP level — rotating UAs, cookies, or TLS fingerprints won't help

## Rule 18 — Preserve Session Tokens

Session tokens are the most valuable engagement artifact. Preserve them.
- Save all tokens, cookies, and API keys at engagement start
- Compact and save state at natural breakpoints (end of phase, end of session)
- The credential registry tracks what tokens work on which surfaces
- A lost session token often means a dead engagement — especially on strict-OTP/KYC targets

## Rule 19 — SSP Signal Check

Endpoints that accept nested objects, duplicate parameters, or unusual content types
are SSP (Server-Side Parameter Pollution) candidates.
- If an endpoint accepts BOTH query params and JSON body with the same field names → flag
- If error messages include internal field names, stack traces, or backend routes → flag
- If the tech stack has known parser differentials (Express vs qs, Spring vs Tomcat) → flag
- Route SSP candidates to the `ssp-testing` skill for deep testing

## Rule 20 — Activity Feed Is a Fertility Map, Not Just a Dupe Warning

Recent public activity on a surface (CrowdStream/hacktivity payouts, clustered finds by
one researcher) is a signal that the surface STILL YIELDS — read it as where-the-bugs-are,
not only as dupe risk.
- The untouched/pristine lane is often pristine *because* it is hardened; if it were soft it
  would already be on the activity feed.
- Clustered payouts (one tester landing several finds in one area) = soft, fertile area →
  hunt an adjacent/variant instance.
- Dupe-aversion should narrow your specific *instance* on a fertile surface, never make you
  abandon the surface. "Someone else found one here" ≠ "this surface is dead."

## Rule 21 — Lead With the Program's Focus Areas; Match Method to Bug Class

Hunt the program's STATED focus areas first, then your own hypothesis — and assign the right
tool to each class.
- Focus areas are where triage is primed to pay and where the program has signalled weakness.
  Start there; bring your pet thesis (e.g. cross-tenant BOLA) second.
- Interactive classes — XSS (incl CSP-bypass), CSRF on critical actions, DOM injection,
  clickjacking-on-sensitive-action, live-LLM/agent injection — require an authenticated REAL
  browser for *discovery*, not just validation. A curl/API-only pass structurally cannot find
  them. If a focus area is an interactive class, schedule the browser harness EARLY; do not
  perpetually defer it as "next session."
- Don't write off paid lower tiers: P3/P4 from the focus areas are real money even when the
  headline P1 lane (cross-tenant) is hardened. Calibrate EV to realistic reachable yield.

## Rule 22 — Confirming a Negative Is Not Progress

When a thesis goes negative, the next move is a different bug CLASS on a different SURFACE —
not the Nth variant of the same negative.
- Tenant resolution that is credential-bound is bound everywhere: prove it once with a clean
  marker differential, then STOP re-proving it per-endpoint.
- Time-box disconfirmation. Three passes confirming "isolation is airtight" is sunk cost;
  pivot to the focus areas / fertile surfaces instead.
- Having a methodology rule in memory is not the same as executing it — when the easy path
  (more of the same negative test) is right there, deliberately switch lanes.

## Rule 23 — Log Disproven Lanes (Negative Budget)

A negative that never becomes a finding is invisible — it leaves no trace that the effort
was spent, so the same dead lane gets re-tested next session. Record it.
- When a lane/thesis goes negative (a BOLA differential comes back clean, a class is
  disproven on a surface), log it:
  `bash scripts/event-emitter.sh record-negative --lane "cross-tenant BOLA" --surface api.example.com --reason "JWT-scoped, path id ignored" --program $PROGRAM`
- This feeds effort accounting (the negative-test ratio) and the pivot signal: when the same
  class keeps coming back negative, stop re-proving it and switch lanes (Rule 22).
- A GATED lane (per reachability.md) is NOT a tested negative — record gated lanes as gated,
  not as disproven. Only log what you actually tested and falsified.

## Rule 24 — Memory-Safe Grep on Large / Minified Files

`grep` is `ugrep` on some hosts, and ugrep buffers whole lines. A minified JS bundle is often
ONE multi-hundred-KB line, so a plain grep can balloon to many GB, trip the kernel OOM-killer
(which then kills whatever process is biggest — frequently a sibling agent), and **silently
truncate its own output so you think "no more matches."** This has almost certainly cost
completeness on past JS mining. Do not plain-grep bundles.
- **Mining JS/bundles for endpoints/secrets:** use `python3 scripts/js-endpoints.py <dir>
  [--host REGEX] [--all]` — it reads each file individually, so it cannot OOM on one long line.
- **Ad-hoc matching on a big/minified file:** use match-only or streaming methods that don't
  buffer the giant line — `grep -oaE 'pat'`, `rg -oa`, `python3 -c "import re,sys;..."`, or
  `tr '"{},;' '\n' < file | grep -oE 'pat'`.
- **Any grep that might be large:** invoke it through `scripts/safe-grep.sh` (identical args to
  grep) — it caps the process's address space (`GRIMNIR_GREP_MAXMEM_KB`, default 8 GiB) so a
  runaway fails cleanly with ENOMEM instead of OOM-killing a sibling and truncating results.
- If a JS grep returns suspiciously few endpoints for a large bundle, assume it was truncated
  and re-run with `js-endpoints.py` before concluding the surface is mapped.

## Rule 25 — Coverage Before Close

Discovered surface that never reaches a terminal state is how the highest-value lane gets
silently skipped: on a real engagement all effort went into one wildcard and the program was
nearly shelved while a whole sibling domain (a separate CTMS, 150+ ID-keyed endpoints,
multi-tenant) sat untested — because the intel had no forcing function. Recon that isn't
reconciled is recon wasted.
- Before an engagement is **reported or shelved**, every in-scope scope entry and every
  REACHABLE high-value intel item must reach a terminal state: **TESTED** (named in a finding,
  a recorded negative, or an agent checkpoint), **SKIPPED** (a logged skip/defer decision with
  a reason), or **GATED** (a reachability lane you cannot reach). **UNTOUCHED is the only
  failing state.**
- Run `python3 scripts/coverage.py --project-dir "$PROJECT_DIR"` (add `--gate` for a non-zero
  exit on any reachable + untouched item). It derives status from artifacts that already exist
  (scope.md, intel.jsonl, findings, decisions.jsonl, reachability.json, state checkpoints) — it
  adds no bookkeeping, it only reconciles what you already produced.
- Untouched reachable high-value items block the wind-down **decision**, not the testing. Clear
  each by testing it or by logging a conscious skip (`scripts/decision-log.sh record --type skip
  --reason ...`). A gated lane is not a gap — record it as gated (cf. Rule 23), not skipped.
- This is the recon-side analog of the evidence gate (`validate-finding.sh`): the evidence gate
  makes "confirmed" mean reproducible; the coverage gate makes "exhausted / hardened" mean
  everything of value was actually looked at.

## Rule 26 — A Human-Gated Step Is an Interrupt, Not a Wall

A dispatched agent that meets a gate needing a human (email/SMS OTP, 2FA, a CAPTCHA that
escalates, an approval role, a payment step) must **report BLOCKED and stop that lane
immediately**. It must not attempt to grind through it.

This cost a real engagement most of a session: a specialist hit reCAPTCHA Enterprise escalating
to 30-40 sequential image rounds followed by a mandatory email OTP. Its brief told it to report
BLOCKED and it instead built tile-index solving automation and ground through. The operator was
reachable the whole time and relayed the OTP on request in seconds — the cheap path existed from
the first round. Burning a session tunnelling through a wall you were told to report is the
single most expensive failure mode in agent dispatch, because the token spend is unbounded and
the yield is zero.

- **Check auth liveness FIRST, before any test work.** If re-auth needs a human step, stop there.
- **A running agent can be messaged by the operator.** BLOCKED is not the end of the run — it is
  a request for a 10-second human action. Report it and wait; do not route around it.
- **Never attempt to defeat an anti-automation control** (CAPTCHA solving, bot-detection evasion)
  unless the program's rules explicitly permit it. Most forbid it, and it is not the finding.
- Orchestrators: put the BLOCKED protocol and a spend ceiling **near the top** of the handoff, not
  buried in a constraints list. An agent's drive to complete the task will beat a footnote.

## Rule 27 — Prove the Rejection Is Identity-Sensitive Before Trusting an Authz Differential

An authz differential only means something if the rejection you observe is caused by **identity**.
Many APIs sit behind a control that rejects a *modified request* uniformly — request signing,
body-integrity/HMAC checks, anti-tampering nonces, strict schema validation. Against one of those,
the cross-user arm fails, the nonexistent-id arm fails, the malformed arm fails, and the endpoint
looks beautifully hardened. It has told you nothing: every arm failed for the same reason, and that
reason was never authorization.

This produced a false "hardened" verdict that stood for eleven days on a real engagement. A single
JSON endpoint returned the same error for a genuine cross-user id swap and for a same-length change
to an unrelated field on the tester's *own* record. The lane was closed as negative. Re-testing
found the error was a body-integrity gate that rejected any body edit at all.

**The control that settles it:** change something in the request that is the same *shape* as your
attack but carries no authorization meaning — an unrelated field, same length, on your own object.

- It is **accepted** → the endpoint distinguishes edits, so your differential is measuring authz. Proceed.
- It is **rejected identically** to your cross-user attempt → the response is not an authz signal.
  Verdict is **INCONCLUSIVE, not negative.** Say so in exactly those words.

Then look for a surface that carries identity *outside* the protected region — an id in a query
string, a path segment, a header, a websocket subscribe frame, a GET with no body at all. Those
routes bypass the gate entirely and give an interpretable answer for a fraction of the effort. Where
none exists, the real lane is the signing routine itself; reverse it from whichever client is
cheapest (a decompiled mobile binary is usually far more tractable than minified JS) rather than
grinding uninterpretable differentials.

- An arm that fails for a **non-authz reason is not a negative result** — it is a missing result.
- Never let "we tested it and it held" enter a report or a ledger when the confound was untested.
  Rule 22 already says confirming a negative is not progress; recording a confounded negative is worse,
  because it also closes the lane.

## Rule 28 — Whose Data Is In Your Evidence?

A PoC that proves *you can reach something* is an argument. A PoC that contains *someone else's
data* is evidence. Programs close arguments as "working as designed"; they do not close evidence.

This is the clearest pattern in submission-outcome data, and the weight sits on the negative:
capability-only proofs — your own access, against your own account, with your own token —
consistently fail to earn, *including* ones filed as Critical. A handful of payouts cannot prove
that victim data always wins; a long run of failures does prove that capability alone does not.

Crowding is not the explanation. The pattern holds on surfaces where the report was demonstrably
first and took no duplicates, and rejections often say so in as many words: no second account, no
third-party data involved.

The corollary matters just as much: a finding that DOES carry victim data is worth racing for. An
otherwise-identical report filed hours earlier by someone else takes the bounty. Being right is not
the same as being first.

The failure mode is not weak writing, and it does not respond to better argument. A capability-only
finding can come back `informative` even after a rebuttal that cites the right OWASP item, walks the
business impact and requests mediation. A better-argued capability demo is still a capability demo.

**Before filing, answer one question: whose data is in my evidence?** If the only answer is "mine",
the finding is not ready.

- The fix is usually a second account, and usually cheap. Register one, then
  `reachability.sh set-gate --gate second-account --held true`.
- `authz-confirm.py` already refuses to confirm without distinguishable victim data — the harness
  was right about this before the outcome data existed. Do not talk yourself past it.
- `validate-finding.sh --victim-data yes|no` records the answer; for access-control classes
  (bola/idor/bfla/authz/privesc/agentic/llm/mcp) a capability-only finding returns **CHAIN_REQUIRED**
  from the Q2 impact gate no matter how well the impact section reads.
- This does **not** mean "only file authz bugs". It means the evidence must contain someone else. A
  prompt-injection or MCP finding that ends in another tenant's data qualifies; one that ends in
  "the model complied" does not (Rule 21, and see `feedback-injection-fires-is-not-impact`).
- If a second party's data is genuinely unreachable, that is the finding's ceiling, not a formatting
  problem. Log the lane and move on rather than polishing the writeup.

Distinguish this from crowding. Capability-only findings on picked-over surfaces come back
`duplicate`; on fresh surfaces they come back `informative`. Neither pays, and the fix for one is
not the fix for the other.

## Rule 29 — Validate What You Have Before You Look For More

The moment a lane produces something that looks reportable, finish it: reproduce it, run the
class-appropriate confirmation, promote it with `validate-finding.sh`, and get the evidence on disk
under `evidence/<id>/`. Only then open the next lane.

This is not a wall-clock deadline. It is about what survives a break.

**A hunt spans sessions; a finding in flight does not.** Context windows end, sessions pause for
hours, tokens expire (some auth captures live minutes, not days), chat rooms and orders get garbage
collected, and a WAF that was quiet at 08:00 is not at 18:00. An unvalidated finding carried across
a break costs a re-derivation that a validated one does not — you pay twice for the same bug, and
sometimes the second attempt no longer reproduces at all.

**And the clock is real.** Duplicate races are routinely decided by a handful of hours, and the
losing report is frequently one whose evidence was already captured and sitting on disk before the
race was lost — the hours went into more recon and more polish on a finding that was already good
enough to file. Reconstruct your own margins from engagement-dir timestamps if you want the number
for your own process; the lever is the interval between "confirmed" and "filed", and it is the one
part of the funnel you fully control.

- **Finish the finding before opening the next lane.** "One more endpoint first" is how a confirmed
  bug becomes a duplicate.
- **Route the expansion, keep the validation.** Broad sweeps, bulk enumeration, JS/APK grinding and
  parsing go to a background job or a cheaper model; the interactive budget is for confirming, writing the
  PoC, and shipping. Delegating the wide work is what makes finishing the narrow work affordable in
  the same session.
- **A report can be edited after submission; a submission timestamp cannot be moved.** Polish is
  recoverable, priority is not. If the finding is confirmed and the impact is real, file it and
  improve it afterward.
- **Before a session ends, spend the remaining budget on promotion, not discovery.** A `theoretical`
  finding with the evidence already captured is the cheapest thing on the board to finish and the
  most expensive thing to resume.
- Corollary to Rule 25: coverage before close, but *validation before expansion*. Rule 22 says
  confirming a negative is not progress; this says leaving a positive unconfirmed is worse, because
  it can still be taken from you.

## Rule 30 — Attribute the Signal to the Target Before You Act On It

A recon artifact is a claim about *something*. Before it becomes a lead, confirm it is a claim
about the **target** — not about our own tooling, a shared CDN, a third-party widget, or another
engagement's leftovers.

This is not hypothetical. A recon run against a newly in-scope asset reported "2 JS-secret hits"
on a host that serves no JavaScript at all. The pipeline had merged a stale counter file into its
own URL list; `curl` reads a bare number as an integer-form IP, `0` resolves to `0.0.0.0`, and the
fetch landed on the operator's own evidence server. The "secret" was one of our own evidence
directory names matching an AWS URL regex. The artifact was real, the parsing was correct, and the
finding was about us. Sixty-nine recon directories were affected before anyone looked.

- **Check provenance before impact.** For any secret, endpoint, or interesting response: which
  request produced it, and what host answered? If the recon output does not record that, treat the
  signal as unattributed and re-fetch it by hand before spending anything on it.
- **A finding on a host that cannot produce it is a tooling bug.** No JS served but JS secrets
  found; no API but API paths responsive; a "vulnerable" endpoint that is a documented public
  asset. Reconcile the contradiction before writing it up — the tool is wrong more often than the
  target is exotic.
- **Loopback and RFC1918 answers are ours until proven otherwise.** `0.0.0.0`, `127.0.0.1`,
  `0.0.x.x`, `10/8`, `192.168/16` reached from our own scanner are our own infrastructure. That is
  the opposite of an SSRF proof, which requires the *target* to make the request. See Rule 12 and
  [[feedback-oob-listener-external-reachability]].
- **Cross-engagement contamination is a disclosure risk, not just noise.** Another program's
  finding names sitting in this program's recon directory will ship if that directory is ever
  bundled into a report. Keep engagement artifacts attributable, and clean them when they are not.

## Rule 31 — Identify the Intended Unauthenticated User Before Filing "Missing Authentication"

An unauthenticated endpoint is only a finding if nobody was *supposed* to reach it without
credentials. Many products deliberately expose a surface to an external party who has no account:
share links, invite links, guest documents, payment links, candidate/interview links. That is a
**capability-URL design** — the unguessable identifier *is* the credential. "No token is checked"
describes it accurately and is still not a vulnerability.

The failure mode is expensive because the report writes itself so persuasively: every sibling
service on the platform requires a session token, this one requires nothing, therefore a boundary
is broken. That contrast dissolves the moment you notice the surface serves a different audience
under a different trust model, and the vendor closes it in one line.

- **Read what the app says about itself, in a real browser, before writing anything.** Error copy,
  page title, favicon and bundle contents identify the product. An error string naming a role you
  had not modelled ("ask the organizer for a new link") reframes the entire threat model. A bundle
  that is mostly a code-editor library is not the drawing tool the hostname suggested. See
  [[feedback-spa-render-needs-real-browser]].
- **If it is capability-URL, re-aim at the real questions.** Are the identifiers guessable or
  predictable (sample enough of them and test the generator, do not assume)? Do they leak through
  referrers, archives, screenshots or logs? Does revocation work **server-side**, or does the SPA
  merely decline to render? Is *creation* unauthenticated, and does that let an outsider consume or
  persist data on the target's infrastructure?
- **A correct refusal is evidence against the finding.** If revoked or expired capability URLs are
  rejected at the origin rather than in the client, the design is working. Record that as a closed
  lane instead of arguing around it.
- **Capability-URL surfaces generate capability-only proofs.** Creating your own room, document or
  link and then reading it proves nothing about anyone else's data. Access to a resource you created
  is not access to a victim's. See Rule 28 and [[feedback-victim-data-predicts-payment]].

## Rule 32 — Reach Is Not Read: Rate a Server-Side Request by What Comes Back

A server-side request primitive (SSRF above all, but also any fetch-on-your-behalf feature) is
almost never interesting because it fires. It is interesting because of **where it lands and
whether the response comes back**. Those are two separate questions and only the second one sets
severity. Published analysis of the public HackerOne SSRF corpus makes the shape plain: a large
majority of disclosed SSRF reports never earn anything, the paid median sits near the bottom of
the scale, and the top of the range is an order of magnitude above it. The request in the cheap
reports and the request in the expensive ones is frequently the *same request*.

**The response-channel ladder.** Place every server-side request finding on this ladder before
you decide what it is worth, and say which rung in the finding itself:

| Rung | What you have | Realistic ceiling |
|---|---|---|
| `blind` | The request fires. Nothing comes back. | Low/Medium, high dupe risk |
| `partial` | A constrained reflection: an `og:` field, an error string, a status code, a response-length or timing delta | Medium/High |
| `full` | The whole response body is returned to you | High |
| `credential` | The body contains cloud role credentials, tokens, or keys | Critical |
| `execution` | Code execution, root, or account takeover on the reached host | Critical |

- **Do not file at the floor by default.** A blind result is the *start* of the work, not the
  finding. Before writing anything, spend the effort on climbing one rung: hunt for the oracle.
- **The oracle is the whole game, and it is usually somewhere else in the product.** A webhook
  delivery log that shows the response code and body. A screenshot or PDF that *draws* what the
  fetch returned. A link-preview that echoes one `og:` field. An import that attaches the fetched
  bytes. An error message that differs for open and closed ports. Find the surface that renders the
  response and you have converted a blind primitive into a readable one.
- **Make the target's own renderer read for you.** When a channel only returns rendered output, the
  job is to coerce the internal response into a shape that renderer will display — request a JSON
  variant of an endpoint that otherwise returns plain text, or point the fetch at something the
  pipeline will embed rather than discard.
- **A negative here is a real answer.** If the primitive is provably blind, every reachable
  internal target is filtered, and no surface in the product reflects the response, that lane is
  closed. Log it under Rule 23 and move on rather than filing an informative.
- **Say the rung out loud in the report.** "The server issues the request but the response is not
  returned to the reporter" is a sentence a triager will write for you if you do not write it
  first, and it is what caps the payout. If you did climb, show the climb.

See also Rule 11 (out-of-band proof for blind vulnerabilities), Rule 22 (confirming a negative is
not progress), and Rule 30 (loopback answers from your own scanner are not SSRF proof).

## Rule 33 — Never Fire an Irreversible Action on an Account You Need

Some endpoints do not have a dry run. Account deletion, account deactivation, closing a wallet,
cancelling a subscription, consuming a one-time token, rotating a credential, submitting a
withdrawal — the test *is* the destructive act. For these, status code is the only oracle, and you
only get it by doing the thing. That makes them a trap: the natural "just send it once to see"
reflex permanently burns whatever account the token belongs to, and on a mobile/OTP-gated target a
replacement account can cost hours (new SIM, OTP, KYC) or be unrecoverable.

**Before sending any request whose success is irreversible, stop and classify the target object.**

- **If the object is a real/primary test account or its data** — do NOT send it. Either (a) perform
  the test against a **disposable throwaway account** minted for exactly this (a victim you are
  willing to destroy), or (b) treat the lane as **BLOCKED** and surface it to the operator for an
  explicit go/no-go. "I can delete my own account to prove deletion works" is almost never worth the
  account; the authz defect (e.g. a destructive endpoint accepting the wrong token audience / no
  step-up auth) is usually demonstrable the first time you fire it, so fire it on something
  expendable.
- **A flag that looks like a safety toggle is not one until proven.** `delete_anyway=false`,
  `dry_run`, `confirm=false`, `test=true` — do not assume these prevent the effect. Verify the flag's
  real semantics (docs, the app's own traffic, a read-back) on a disposable object first. (Field-
  observed: a `delete_anyway:false` flag gated *balance-blocking*, not the deletion — the DELETE
  completed and deactivated the primary account.)
- **The authz finding does not require your good account.** A broken-function-level-authz or
  missing-step-up finding on a destructive endpoint is proven by: the control the app enforces
  (OTP/password re-auth/scoped token) **on a principal in the attacker's starting state, captured from
  the first-party client** (Rule 34) + the endpoint accepting a request without it. Demonstrate that
  on a disposable victim; cross-account proof uses attacker-token-against-disposable-victim, never
  against an account you want to keep.

When dispatching a specialist, put the destructive-endpoint list (deletion/deactivation/withdrawal/
token-consumption) in the handoff with "disposable-account-only or BLOCKED" next to it — do not bury
it in a constraints paragraph. An agent's drive to confirm a High finding will run straight through a
footnote. See also Rule 26 (BLOCKED protocol) and Rule 1 (harm check before you send).

## Rule 34 — A Bypass Needs a Baseline: Prove the Gate Applies to Your Starting State

A "bypass" finding (missing step-up, missing re-authentication, skipped OTP, skipped confirmation)
makes two claims: (1) the legitimate path challenges a principal in the attacker's starting state,
and (2) the attacker's path reaches the same effect without the challenge. The PoC only ever
demonstrates (2). The effect landing proves the endpoint works; it says nothing about whether anyone
was ever gated. If the first-party client performs the same operation with the same credential, you
have documented the intended design.

The failure is expensive because the evidence for (2) is strong and reproducible. Analysts reproduce
it, report assistants pass it, and the report reads as airtight until someone opens the app and taps
the button.

- **Capture the baseline from the attacker's starting state.** If the threat model is "attacker holds
  a session token", record the first-party client, signed in with that kind of session, performing
  the operation. It must be challenged. A challenge captured on a different path does not count: a
  signed-out page, a different client, a different role, a recovery flow. A challenge that *replaces*
  authentication (a code proving phone ownership to a visitor with no session) is a sign-in, not a
  step-up.
- **A purpose-scoped token or audience is not proof of enforcement intent on that endpoint.** It
  proves some path mints it. Establish which clients call the endpoint with which token. If any
  first-party path sends the ordinary token, accepting it is the design.
- **Read the wiring, not the helpers.** In a minified bundle, API helper functions defined side by
  side are not a flow. Find the router and the component behind each route, and trace which route
  calls which helper. One bundle often serves several routes for different audiences.
- **Label every basis by its real source.** "Captured traffic" means a capture is on disk; a bundle
  read is a bundle read. A gap-closure row marked *demonstrated* on a mislabelled basis is the most
  dangerous row in the table, because nobody reopens it.
- **An unexplained contradiction keeps the premise open.** If someone sees the operation succeed
  without the challenge, or the analyst keeps asking you to show the gate, run the decisive test
  (walk the first-party flow from the attacker's starting state). Do not explain it away. A residual
  your own trace lists as open is open; do not send a claim that depends on it.
- **No baseline capture, no submission.** Without it the finding is theoretical, and theoretical
  findings never ship.

Field-observed: an account-deletion "OTP step-up bypass" was filed at High. The SMS code belonged to
the signed-out deletion page, where it replaced a session; the in-app option sent the ordinary session
token behind a single confirmation button. The finding was conceded after triage. See Rule 31 (the
unauthenticated-audience form of this mistake) and Rule 33.

## Rule 35 — File at the Floor; Escalations Are Comments

A finding is a bundle of claims: the base bug, and zero or more escalations ("and it reaches
the internal network", "and it works across tenants"). Record them separately (`finding.sh
--claim`), verdict each one (`validate-finding.sh --claim-verdict`), and file at the **floor**:
the highest severity whose claims, and every claim below it, survived. A refuted escalation is
skipped, not a reason to retract the finding; an untested one stops the climb until it is tested.

The failure this prevents is expensive and quiet: a late control retracts one escalation, the
whole finding is "downgraded", and filing stalls for days although the base bug was never in
doubt. Meanwhile the clock runs against you on exactly the surfaces where it matters most.

- **On a newly added asset (under 72 hours old), speed outranks completeness.** New surface is
  where duplicates arrive within hours (Rule 29). Once the floor has survived the fresh-eyes
  review (`scripts/fresh-eyes.py`) and an operator run of the repro script (`finding.sh
  --repro`), file at the floor within hours.
- **Never hold a report for an escalation.** File what survived; test the escalation after, and
  add it to the filed report as a comment with its evidence. An upgrade that arrives as a comment
  on an accepted report costs nothing; a base finding that loses the race for an escalation
  usually pays nothing.
  Holding is a bet on three things at once: that the escalation (or a higher-paying variant)
  exists, that nobody else is racing you, and that filing later will not meet a fix the first
  report would have prompted anyway. On fresh surface all three go the wrong way: a newly added,
  high-signal asset is crowded, not quiet, and "no disclosed reports" is a floor, not a ceiling,
  because undisclosed duplicates never show. The fresher the asset, the stronger the case to file
  now.
- **The floor is a ceiling on what the report states.** `check-report-hygiene.sh --finding`
  warns when the report's severity exceeds the recorded floor. Do not argue past it; do the test.
