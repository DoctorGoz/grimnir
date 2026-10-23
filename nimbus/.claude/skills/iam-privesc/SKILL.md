---
name: iam-privesc
description: Cloud IAM enumeration and privilege escalation (AWS/Azure/GCP). CLD01. Maps least-priv violations and assume-role/PassRole chains to admin.
allowed-tools: Read, Grep, Glob, Bash
---

# Cloud IAM Privilege Escalation Skill (CLD01)

Identity is the cloud perimeter. The goal: from whatever principal/credentials are
in scope, find a path to higher privilege (often to admin) through policy
misconfiguration. Map MITRE `T1078.004`, `T1098`.

## Prerequisites
- In-scope credentials (key, token, or SSO) and the account/sub/project id.

## Methodology

### Step 1: Who am I + what can I do
```bash
aws sts get-caller-identity
az account show ; az ad signed-in-user show
gcloud auth list ; gcloud config list
```
Enumerate effective permissions (`iam-enum.sh`, enumerate-iam, cloudsplaining,
`gcloud projects get-iam-policy`, `az role assignment list`).

### Step 2: Hunt known privesc primitives (AWS)
`iam:Create*`/`Attach*Policy`/`PutUserPolicy`, `iam:PassRole` + a compute service
(`lambda:CreateFunction`, `ec2:RunInstances`, `glue`, `cloudformation`),
`iam:CreateAccessKey` on another user, `sts:AssumeRole` on a more-privileged role,
`iam:UpdateAssumeRolePolicy`, `iam:CreatePolicyVersion`/`SetDefaultPolicyVersion`.

### Step 3: Azure / GCP equivalents
Azure: role-assignment write (`Microsoft.Authorization/roleAssignments/write`),
Owner/Contributor sprawl, managed-identity abuse, AAD app credential add.
GCP: `iam.serviceAccounts.actAs` + deploy, `setIamPolicy`, key creation,
`iam.serviceAccounts.getAccessToken` / `signJwt`, owner sprawl.

### Step 4: Prove the path (minimal, non-destructive)
Execute the smallest step that yields the higher privilege, then
`sts get-caller-identity` (or equivalent) as the escalated principal. Clean up any
resource you created.

## Validate (negative control)
- **Attack:** demonstrate the escalated identity (e.g. new caller identity = admin
  role) reached via the documented permission.
- **Negative control:** the same escalation step **fails** for a principal lacking
  the abused permission (or simulate-principal-policy denies it). That proves the
  specific misconfig is the cause.

## Evidence to capture
The permission set proving the primitive, the escalation commands, and the
post-escalation identity/access — plus the negative control.

## False-positive traps
- A permission present but blocked by an SCP / permission boundary / deny policy.
- `iam:PassRole` without a usable target role (no admin role to pass).
- Read-only enumeration mistaken for write capability.

## Validate & Promote

Findings from this skill are born `theoretical` (see the repo-root `CLAUDE.md`). Promote via `scripts/validate-finding.sh` only after demonstrating the escalated access with a negative control. Clean up created resources.

```bash
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent nimbus \
  --id NIM-NNN --state confirmed --method manual-repro --method negative-control \
  --negative-control "PassRole+CreateFunction -> admin caller identity; unprivileged principal denied (simulate-principal-policy)" --by nimbus
```
