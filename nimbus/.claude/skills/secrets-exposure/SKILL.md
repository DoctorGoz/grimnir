---
name: secrets-exposure
description: Exposed cloud secrets — keys in env/config, secrets managers, public snapshots/AMIs/images. CLD04. Maps to MITRE T1552.
allowed-tools: Read, Grep, Glob, Bash
---

# Cloud Secrets Exposure Skill (CLD04)

Find credentials and secrets that grant cloud access: hardcoded keys, readable
secrets managers, and (the under-checked one) **public snapshots, AMIs, and
container images** that bake in secrets.

## Methodology

### Step 1: Keys in code / config / artifacts
From HUGINN's `js-analysis`/`passive-osint` and any leaked-credential monitor: AWS
`AKIA…`/`ASIA…`, GCP service-account JSON, Azure connection strings, in JS, repos,
CI logs, env files, `terraform.tfstate`, container layers.

### Step 2: Secrets managers (with creds)
`aws secretsmanager list-secrets` / `get-secret-value`, SSM Parameter Store
(`--with-decryption`), Azure Key Vault (`az keyvault secret list/show`), GCP Secret
Manager (`gcloud secrets versions access`). Over-broad read here is a finding.

### Step 3: Public snapshots / images (high value)
Public EBS snapshots & AMIs, RDS snapshots, GCP images, Azure managed disks shared
publicly, and **public container registries** (ECR/GCR/ACR) — mount/pull and grep
for secrets. `trivy image`/`trivy fs` to scan layers.

### Step 4: Verify liveness
A leaked key is only a finding if it **works**. Test with the least-privilege call
(`sts get-caller-identity`) — never with a destructive action.

## Validate (negative control)
- **Attack:** the discovered secret/key **authenticates** and grants access
  (caller identity / a single read).
- **Negative control:** a revoked/garbage key of the same shape is rejected — proving
  liveness, not just format.

## Evidence to capture
Where the secret was found (redacted), the authenticating call result, and the
access it grants. Never paste full live secrets into the report; keep raw in evidence.

## False-positive traps
- Example/placeholder keys (`AKIAIOSFODNN7EXAMPLE`), test/sandbox creds.
- A key that authenticates but has zero effective permissions.
- Secret manager entries you can list but not decrypt.

## Validate & Promote

Findings from this skill are born `theoretical` (see the repo-root `CLAUDE.md`). Promote via `scripts/validate-finding.sh` only after proving the secret is live and grants access.

```bash
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent nimbus \
  --id NIM-NNN --state confirmed --method manual-repro --method negative-control \
  --negative-control "leaked AKIA key -> sts get-caller-identity OK (user app-ci); revoked key of same shape -> InvalidClientTokenId" --by nimbus
```
