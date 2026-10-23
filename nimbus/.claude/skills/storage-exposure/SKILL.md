---
name: storage-exposure
description: Public cloud storage exposure — S3 / Azure Blob / GCS bucket ACL and policy misconfig. CLD02. Maps to MITRE T1530.
allowed-tools: Read, Grep, Glob, Bash
---

# Cloud Storage Exposure Skill (CLD02)

Publicly readable/writable object storage is a top cloud data-leak source. The
finding is **sensitive data actually exposed** (or writable), not merely "bucket exists".

## Prerequisites
- Bucket/container names (from recon, JS, DNS CNAMEs, `bucket-permutations.txt`).

## Methodology

### Step 1: Discover buckets
Permutate org/app names (`gcpbucketbrute`, `s3scanner`); harvest from JS, CORS
errors, CDN origins, and DNS CNAMEs to `*.s3.amazonaws.com` / `*.blob.core.windows.net`
/ `storage.googleapis.com`.

### Step 2: Test access (anonymous first)
```bash
aws s3 ls s3://BUCKET --no-sign-request
aws s3api get-bucket-acl --bucket BUCKET --no-sign-request
curl -s "https://BUCKET.s3.amazonaws.com/?list-type=2"      # public list
```
Azure: anonymous container list / blob GET. GCP: `gsutil ls -a gs://BUCKET`,
`storage.objects.list` unauthenticated.

### Step 3: Classify exposure
Public **list**, public **read** of objects, public **write** (upload/overwrite →
defacement/supply-chain), or full-control ACL. Check object contents for PII /
secrets / backups.

### Step 4: Writable test (carefully)
Only if in scope: write a single innocuous canary object, confirm, then delete it.
Never overwrite existing objects.

## Payloads / wordlists
`nimbus/wordlists/bucket-permutations.txt`.

## Validate (negative control)
- **Attack:** retrieve an actual sensitive object **unauthenticated** (or write+read
  back a canary). Capture the object key + a snippet proving sensitivity.
- **Negative control:** a properly-locked sibling bucket / a non-existent key
  returns AccessDenied/404 — showing this bucket is genuinely public, not your creds.

## Evidence to capture
The unauthenticated request, the listing/object proving exposure (redact PII in the
report, keep raw in evidence), and the negative control.

## False-positive traps
- You listed it because YOUR creds are valid, not because it is public (re-test with `--no-sign-request`).
- Public bucket of intentionally-public assets (static site) — Info, not a leak.
- Bucket policy allows list but denies GetObject — limited impact.

## Validate & Promote

Findings from this skill are born `theoretical` (see the repo-root `CLAUDE.md`). Promote via `scripts/validate-finding.sh` only after unauthenticated retrieval of sensitive data (or a confirmed canary write).

```bash
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent nimbus \
  --id NIM-NNN --state confirmed --method manual-repro --method negative-control \
  --negative-control "--no-sign-request GET returns prod backup .sql; locked sibling bucket returns AccessDenied" --by nimbus
```
