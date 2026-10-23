# Confirmation Harness — `scripts/confirm/`

Turns `theoretical` findings into `confirmed` ones with reproducible evidence. The validation gate
(`scripts/validate-finding.sh`) enforces that a `confirmed` finding carries the class-appropriate proof
(decision: **HARD-block for high/critical, WARN for low/medium**; escape with
`GRIMNIR_EVIDENCE_GATE=warn|off`). Design + roadmap: `~/dev/ROADMAP-confirmation-harness.md`.

Mechanism/policy split: the primitives are non-interactive (args in, JSON verdict out); the
human-in-the-loop lives only in the gate's policy. The same primitives + verdict contract drive a
future autonomous validator unchanged (roadmap §8).

## MVP components (built)

### OOB interaction listener — blind SSRF / injection / IMDS
Self-hosted, IP-based (no domain needed): the target's backend calls `http://<public-ip>:<port>/h/<nonce>`.
The per-test `<nonce>` is the correlation **and** the isolation, so one always-on listener serves every
engagement without collision.

```bash
# 1) run the listener (or install the service below)
python3 scripts/confirm/oob-listener.py            # reads GRIMNIR_OOB_* env

# 2) PROVE IT IS REACHABLE before spending a lane on it
python3 scripts/confirm/oob-client.py preflight               # vantage, ports, journalled loop
python3 scripts/confirm/oob-client.py preflight --external    # + proves the INTERNET reaches it

# 3) mint a nonce + callback URLs, plant them in the target, then read the verdict
python3 scripts/confirm/oob-client.py mint --label 'avatar_url on PATCH /profile'
python3 scripts/confirm/oob-client.py poll  <nonce> 120
PROJECT_DIR=~/workspace/<prog> \
  python3 scripts/confirm/oob-client.py verdict <nonce> SPE-003 ssrf full
```

`GRIMNIR_OOB_*` is read from the environment first and then from `~/.grimnir/oob/config.env` --
the same file the systemd unit already uses -- so a fresh shell needs no exports.

Plain `preflight` proves the listener runs and journals; it does **not** prove a target can reach
it, because the request never leaves the host. `--external` bounces a callback off a third-party
server-side fetcher and confirms the hit arrives from that third party's address, which is the
cheap proof of real inbound reachability. It discloses the listener URL to that service, so it is
opt-in.

`mint` refuses to run while `GRIMNIR_OOB_BASE` is unset or still the placeholder: a callback URL
nothing can reach produces silence, and silence is indistinguishable from a target with no
vulnerability, so the lane closes on a misconfiguration (hunting Rule 27). `preflight` is the
check that separates the two, and `poll` says so whenever it times out empty.

The trailing argument on `verdict` is the **response-channel rung** (hunting Rule 32):
`blind|partial|full|credential|execution`. Omitted it resolves to `blind`, which caps the finding
at medium in the gate. Every primitive that writes a verdict takes `--channel-rung` and they share
one definition in `_rung.py` -- when only `oob-client.py` carried it, findings confirmed by the
TLS listener, by `mcp-confirm.py`, or by a renderer were all silently capped.

**Second-order sinks:** `mint --count N --label '<field>'` mints one nonce per candidate field and
records the map itself, so a callback arriving hours later can still name its sink.
`oob-client.py plants` reads it back and marks which plants have fired.

The **2-hop URL** (`/r/<nonce>?to=.../h/<nonce>`) proves redirect-follow + port/host-allowlist bypass:
hop1 on an allowed port `302`s to hop2 on a non-allowed port; a hit on the second port is the bypass.
This is the canonical blind-SSRF evidence pattern. The listener captures the target's own trace headers
(`Traceparent`/`X-Request-ID`/`X-Amzn-Trace-Id`) so the callback self-correlates in the target's tracing.

**Reachability note:** the listener must be internet-reachable (the target calls it). On a 443-only
allowlist you need hop1 on 443 (TLS), which needs a domain + cert — `tls-oob-listener.py` covers
that case and records TCP-connect / SNI / HTTP as three escalating levels of proof.

### DNS interaction recorder — the floor of the ladder
`dns-rebind.py` in its default `--mode record` answers and **journals every query** to the same
`hits.jsonl`, so `poll` and `verdict` see DNS and HTTP interactions together under one nonce.

```bash
sudo python3 scripts/confirm/dns-rebind.py --domain oob.example.com --public <your-ip>
export GRIMNIR_OOB_DNS_DOMAIN=oob.example.com     # mint then also emits a DNS-only callback host
```

This exists because a target that resolves your hostname and is then blocked from connecting out
looks *exactly* like a target with no SSRF when the only channel is HTTP. A logged DNS query proves
the fetch was attempted, which keeps the lane open at an honest `blind` rung instead of closing it
as a negative. `verdict` marks such a record `dns_only` and warns if a rung above `blind` is claimed
against it — a lookup can also come from a resolver cache or a link-preview safety check.

`--mode rebind` is the TTL-0 alternating answer for defeating a validate-then-fetch check. Parity is
tracked **per hostname**, so a concurrent probe, an A/AAAA pair or a resolver retry cannot flip the
sequence out from under the test.

### Evidence gate (in `validate-finding.sh`)
Promotion to `confirmed --class <cls>` requires:
| class | required proof |
|-------|----------------|
| `ssrf` `injection` `sqli` `ssti` `rce` `imds` `xxe` | `evidence/<id>/verdict.json` with `verdict: confirmed` (from `oob-client.py`, `tls-oob-listener.py verdict`, `mcp-confirm.py`, `render-confirm.py --vuln-class ssrf`, or `ssti-confirm.py` for `ssti`) |
| `ssrf` `imds` above medium | additionally a `channel_rung` justifying the severity: `full`+ for high, `credential`/`execution` for critical |
| `bola` `idor` `bfla` `authz` | `--negative-control` (the 4-way differential) |
| `race` | a confirmed `evidence/<id>/race.json` (race-confirm.py concurrent-burst overrun) |
| `xss` `dom` `redirect` `csrf` | `--screenshot FILE` or `evidence/<id>/render.json` |
Omitting `--class` keeps legacy behavior (no new enforcement).

## Deploy the listener as an always-on service (on your public VPS)
```bash
cp scripts/confirm/grimnir-oob.service ~/.config/systemd/user/
# operator-local config (NOT in the repo — holds the public IP):
mkdir -p ~/.grimnir/oob
cat > ~/.grimnir/oob/config.env <<'EOF'
GRIMNIR_OOB_BASE=http://<your-public-ip>
GRIMNIR_OOB_PORTS=18080,18081
# GRIMNIR_OOB_LOG left unset -> defaults to ~/.grimnir/oob/hits.jsonl
# (do not use %h in an EnvironmentFile value; systemd does not expand it there)
EOF
systemctl --user daemon-reload && systemctl --user enable --now grimnir-oob
```
Ensure the chosen ports are reachable from the internet (ACL/security-group). Keep them log-only.

### authz-confirm — BOLA / IDOR / BFLA
Automates the 4-way differential (own / cross / nonexistent / malformed) with the attacker's creds and
writes `evidence/<id>/authz.json` (the negative-control the gate consumes).
```bash
python3 scripts/confirm/authz-confirm.py --finding-id SPE-003 --project-dir ~/workspace/<prog> \
  --url 'https://api.x/users/{id}/card' -H 'Authorization: Bearer ATTACKER' \
  --own-id 1001 --victim-id 1002 --nonexistent-id 999999 --victim-marker 'Lucinda'
```
`confirmed` needs a `--victim-marker` (distinguishable victim data, the bitso "Lucinda" rule); without
one a distinct cross-200 is `bola-likely` (enrich + re-test).

### race-confirm — race / limit-overrun (TOCTOU, double-spend, coupon reuse, faucet, quota)
Fires N concurrent copies of one state-changing request (in-process sockets aligned on a barrier, so
TLS setup is paid *before* the burst) and decides whether more attempts succeeded than the limit
should allow. Writes `evidence/<id>/race.json`.
```bash
python3 scripts/confirm/race-confirm.py --finding-id SPE-004 --project-dir ~/workspace/<prog> \
  --method POST --url 'https://api.x/v1/coupons/redeem' -H 'Authorization: Bearer TOKEN' \
  --body '{"code":"PROMO50"}' --count 30 --expected-max 1 --success-marker '"redeemed":true'
```
`confirmed` = successes > `--expected-max`. Add `--sequential-control` (REPLENISHABLE resources only)
to split a true TOCTOU race (`subtype: race` — limit holds sequentially, breaks under concurrency)
from a missing limit entirely (`subtype: no-limit`). `--success-marker` avoids counting a 200 error
page as a spend. A race is state-changing by nature, so `the calling harness` never auto-fires it — a human
runs the lane with `--operator-override`, pointed only at a throwaway / reversible resource.

### ssti-confirm — server-side template injection (in-band)
Sets one reflected GET query parameter to tagged template arithmetic with random operands and reads
the computed result back. Writes `evidence/<id>/verdict.json` (the file the evidence gate reads for
`ssti`). Read-only, so `the calling harness` auto-fires the lanes `lane synthesis` builds from `params.json`.
```bash
python3 scripts/confirm/ssti-confirm.py --finding-id SPE-005 --project-dir ~/workspace/<prog> \
  --method GET --url 'https://app/search?q=a' --param q
```
One combined request covers eight syntax families (`{{ }}` `${ }` `#{ }` `<%= %>` `{ }` `@( )`
`[[${ }]]` `#set`); a family whose tags don't come back is retried alone. `confirmed` = a family
evaluated, a repeat with new operands tracked them, and the bare operands (no template syntax) did
not evaluate, which rules out a calculator or formula feature. `ssti-likely` = unstable, also
evaluated bare, or an engine error the control response lacks. A parameter that isn't reflected is
`inconclusive`: blind SSTI needs an out-of-band or timing probe. Escalation to code execution stays
with the operator.

### sqli-confirm — SQL injection (in-band, error and boolean)
Two read-only proofs against one GET query parameter, against a baseline fetched twice for its
noise floor. Writes `evidence/<id>/verdict.json` (the file the evidence gate reads for `sqli`).
```bash
python3 scripts/confirm/sqli-confirm.py --finding-id SPE-006 --project-dir ~/workspace/<prog> \
  --method GET --url 'https://app/items?cat=shoes' --param cat
```
`confirmed` = a single quote raises a database error the baseline lacks and the doubled quote clears
it, or a TRUE condition (numeric, string literal, or LIKE pattern) keeps the baseline while FALSE and
a misspelled-keyword TRUE change it, in two rounds with fresh literals. Responses are compared after
removing the reflected payload. Conditions are ANDed onto the existing predicate: never OR, never a
stacked statement, never a time delay (time-based is a human step). About 10 requests on a negative.

### xss-confirm — reflected XSS (browser execution)
Maps the reflection with a breaker canary, picks the payload the context allows with the
characters that came back raw, and loads it in headless Chromium. Writes `evidence/<id>/render.json`
and `render.png`.
```bash
python3 scripts/confirm/xss-confirm.py --finding-id SPE-007 --project-dir ~/workspace/<prog> \
  --method GET --url 'https://app/search?q=a' --param q
```
The browser fetches only the main document (every other request is aborted), so each load is one
request to the target, and the payload sets `window.__grimnir_xss` to a random number that only it
could set. `confirmed` = that number read back; the screenshot carries a labeled harness annotation
of it. `xss-likely` = the payload came back intact but did not run (a CSP, a click-only context such
as a `javascript:` URL, or no browser installed). At most three requests per lane.

### render-confirm — XSS / DOM
Headless Chromium loads the URL/HTML with auth, detects execution (`alert`/`prompt`/`window.__grimnir_xss`),
and screenshots to `evidence/<id>/render.png` for **orchestrator vision** review. Writes `render.json`.
```bash
python3 scripts/confirm/render-confirm.py --finding-id SPE-003 --project-dir ~/workspace/<prog> \
  --url 'https://app/x?q=<payload>' --cookie 'session=...'      # or --html-file stored.html
```

### Promoting from the artifact — `--from-evidence`
Every primitive above writes the same contract: a record carrying `vuln_class` and
`verdict`, plus `negative_control` or `screenshot` where the class needs one. So the
promotion is derivable from the artifact rather than retyped after it:

```bash
bash scripts/validate-finding.sh --project-dir ~/workspace/<prog> --agent specter \
  --id SPE-003 --from-evidence
```

It promotes only on `verdict: confirmed`, and refuses an inconclusive or negative record
without touching the finding. Class, negative control, screenshot and method all come
from the record that proved it, so the promotion cannot claim more than the evidence does.

Record the class at creation (`finding.sh --class bola`) and the evidence gate arms
itself at promotion without being told again -- passing `--class` only on the promoting
call used to be the sole trigger, so the ordinary `--state confirmed` call silently
waived the proof requirement.

### Finding what is proven but unpromoted — `--scan`
```bash
bash scripts/validate-finding.sh --project-dir ~/workspace/<prog> --scan
```
Lists findings whose evidence is confirmed on disk but whose state is not, with the
command to promote each. Run it before opening a new lane: a finished lane that never
got promoted loses the race to whoever files first (hunting Rule 29).

### poc-export — reproducible bundle
```bash
python3 scripts/confirm/poc-export.py --finding-id SPE-003 --project-dir ~/workspace/<prog>
# -> evidence/<id>/poc/{poc.md, repro.sh}
```

## Roadmap (not yet built)
Caido-SDK integration for authz-confirm (replay organic auth instead of raw curl headers); the autonomy
phases in `ROADMAP-confirmation-harness.md` §8 (auto-confirm mode, Council, exploit-chainer).
