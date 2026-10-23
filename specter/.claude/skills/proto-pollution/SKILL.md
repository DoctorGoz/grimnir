---
name: proto-pollution
description: Test for prototype pollution in JS/Node APIs (CWE-1321). Use on JSON merge/clone/config endpoints and client-side sinks that process attacker-controlled keys.
allowed-tools: Read, Grep, Glob, Bash
---

# Prototype Pollution Testing Skill (CWE-1321)

Server-side prototype pollution can chain to RCE (via gadget) or auth/logic bypass;
client-side can chain to DOM XSS. The pollution itself is rarely the finding — the
**gadget it triggers** is. Always hunt the downstream effect.

## Prerequisites
- A Node/JS backend (check tech fingerprint), or a JS-heavy SPA.
- Endpoints that merge/clone objects: settings, config, profile, bulk update,
  anything taking nested JSON.

## Methodology

### Step 1: Server-side pollution probes
Send polluting keys in JSON bodies:
- `{"__proto__":{"polluted":"yes"}}`
- `{"constructor":{"prototype":{"polluted":"yes"}}}`
- Dotted/bracketed in query or form: `__proto__[polluted]=yes`

### Step 2: Detect the pollution
Look for a reflected/observable effect: a property you never set appearing on
later responses, a status/feature flag flipping, type-juggling errors, or a 500
revealing a polluted property. Use a benign canary key first.

### Step 3: Find the gadget (this is the actual finding)
- **Auth/logic bypass:** pollute a default that a later check reads
  (`isAdmin`, `role`, `authenticated`).
- **RCE:** pollute options consumed by `child_process`, template engines
  (`lookup`, `compile`), or argument arrays — only in scope and non-destructively.
- **Client-side -> DOM XSS:** pollute `src`/`innerHTML`/sanitizer-config gadgets.

### Step 4: Isolate impact
Confirm the pollution affects a real code path, not just a throwaway object.

## Validate (negative control)
- **Attack:** show the gadget effect (privileged flag set, command/template output,
  XSS firing) AFTER the polluting request.
- **Negative control:** the SAME request WITHOUT the `__proto__`/`constructor`
  payload does NOT produce the effect. That isolates pollution as the cause rather
  than coincidental behavior or a different bug.

## Evidence to capture
The polluting request, the observed downstream effect, and the clean-control
request showing no effect. For DOM XSS, attach a screenshot (use --method screenshot).

## False-positive traps
- Pollution that touches a dead object with no consumer (no impact -> Info at most).
- The app already had the property (not actually polluted).
- A framework that freezes `Object.prototype` (pollution silently no-ops).

## Validate & Promote

Findings from this skill are born `theoretical` (see the validation layer in the repo-root `CLAUDE.md`). They do NOT enter a report or external submission until promoted to `confirmed` with `scripts/validate-finding.sh`, after the independent check above.

- Severity follows the gadget: no-consumer pollution is Info; auth bypass/RCE is High/Critical.
- Only `confirmed` findings ship.

```bash
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent specter \
  --id SPE-NNN --state confirmed --method negative-control \
  --negative-control "with __proto__ payload: isAdmin=true reached; identical request without payload: isAdmin absent" --by specter
```
