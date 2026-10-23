---
name: cache-poisoning
description: Web cache poisoning and deception testing (CWE-444/CWE-525, WSTG-INPV-cache). Use where a CDN/edge cache fronts the app.
allowed-tools: Read, Grep, Glob, Bash
---

# Web Cache Poisoning / Deception Skill

Get a malicious or sensitive response stored in a shared cache and served to other
users. Poisoning = inject a payload via an unkeyed input that the cache serves to
everyone; deception = trick the cache into storing a victim's authenticated page.

## Prerequisites
- A caching layer (CDN/edge/Varnish). Look for `X-Cache`, `CF-Cache-Status`,
  `Age`, `Via` headers.

## Methodology

### Step 1: Identify the cache key vs unkeyed inputs
Determine what the cache keys on (usually host + path + some query). **Unkeyed**
inputs (e.g. `X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Host`, extra params,
some headers) that still affect the response are the lever.

### Step 2: Poisoning
Send an unkeyed header that reflects into the response (e.g. `X-Forwarded-Host:
evil.example` reflected into an absolute URL / script src), then confirm a
**cache HIT** serves your payload to a fresh, header-less request.

### Step 3: Cache deception
Request an authenticated page with an appended static-looking suffix
(`/account/profile.css`, `/account/profile/nonexistent.js`) — if the cache stores
the authenticated body under that URL, another user (or you, unauth) can read it.

### Step 4: Parameter cloaking / key normalisation quirks
Duplicate params, fat-GET, delimiter confusion to slip unkeyed values past the key.

## Payloads / wordlists
Param Miner-style unkeyed header list; `specter/wordlists/`.

## Validate (negative control)
- **Attack:** prove a **second, clean request** (no attacker header) gets the
  poisoned response from cache (`X-Cache: HIT`), or that an unauthenticated request
  retrieves a cached victim page.
- **Negative control:** before poisoning, the clean request returns the normal
  response. The HIT-serving-payload-to-a-bystander step is what proves impact —
  reflection without caching is just reflection.

## Evidence to capture
The poisoning request, the cache-status headers, and the clean bystander request
served the poisoned/sensitive content. Mind the blast radius — self-scope the key
(e.g. a unique path) where possible to avoid harming real users.

## False-positive traps
- Reflection that is never cached (`Cache-Control: no-store`).
- Your own cache bucket only (keyed on a cookie you set) — no bystander impact.
- `X-Cache: MISS` every time — not actually stored.

## Validate & Promote

Findings from this skill are born `theoretical` (see the repo-root `CLAUDE.md`). Promote via `scripts/validate-finding.sh` only after a bystander-served HIT.

```bash
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent specter \
  --id SPE-NNN --state confirmed --method manual-repro \
  --negative-control "X-Forwarded-Host payload cached; clean request returns it with X-Cache: HIT; pre-poison clean request was normal" --by specter
```
