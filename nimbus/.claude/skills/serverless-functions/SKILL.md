---
name: serverless-functions
description: Serverless security — Lambda / Azure Functions / Cloud Functions env secrets, event injection, over-privileged execution roles. CLD05.
allowed-tools: Read, Grep, Glob, Bash
---

# Serverless Functions Skill (CLD05)

Functions concentrate risk: secrets in environment variables, over-privileged
execution roles, and injectable event sources. Often reachable via API Gateway /
HTTP triggers.

## Methodology

### Step 1: Inventory
`aws lambda list-functions` + `get-function-configuration` (env vars, role,
layers); Azure `az functionapp list`; GCP `gcloud functions list`. Note public
URLs / API Gateway / trigger sources.

### Step 2: Environment secrets
Read function env vars for keys/tokens/DB creds (a top finding). Inspect layers and
deployment packages for baked-in secrets.

### Step 3: Execution-role privilege
Resolve the function's role and run it through `iam-privesc` logic — over-privileged
function roles turn any function compromise into account compromise.

### Step 4: Event / input injection
For HTTP-triggered functions, test injection in the event (path, headers, body,
query) and SSRF from the function (chain to `metadata-ssrf`). For event-driven
(S3/queue), test poisoned event records if in scope.

### Step 5: Public exposure
Unauthenticated function URLs, missing authorizers on API Gateway, permissive
resource policies (`lambda:InvokeFunction` to `*`).

## Validate (negative control)
- **Attack:** demonstrate the concrete impact — read a real secret from env, invoke
  an unauthenticated function that returns sensitive data, or reach metadata from
  inside the function.
- **Negative control:** an authenticated-only sibling / a non-injectable input
  behaves safely. Distinguishes the flaw from normal behaviour.

## Evidence to capture
The configuration showing the env secret / permissive policy, the invocation, and
the result (redacted).

## False-positive traps
- Env "secret" that is a non-sensitive config value.
- Function URL that requires IAM auth (you invoked it with your creds, not anon).
- Broad role that is actually constrained by a permission boundary.

## Validate & Promote

Findings from this skill are born `theoretical` (see the repo-root `CLAUDE.md`). Promote via `scripts/validate-finding.sh` only after demonstrating concrete impact.

```bash
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent nimbus \
  --id NIM-NNN --state confirmed --method manual-repro \
  --negative-control "anon GET to function URL returns DB creds in env; an IAM-auth sibling returns 403 to the same anon request" --by nimbus
```
