#!/bin/bash
set -euo pipefail
# Nimbus — identity & permission enumeration with privesc hints. Read-only.
# Usage: iam-enum.sh [aws|azure|gcp]

# Egress: the cloud CLIs reach the provider control plane (the in-scope account) — route that target
# traffic through the program's egress proxy (roe.json "proxy" / GRIMNIR_PROXY) or refuse (exit 4).
# aws/az/gcloud read the exported HTTP(S)_PROXY. No project dir here -> env only. Same pattern as
# storage-scan.sh / firebase-probe.sh.
source "$(dirname "${BASH_SOURCE[0]}")/../../scripts/egress-env.sh"
egress_init "" || exit 4

PROVIDER="${1:-aws}"
have() { command -v "$1" >/dev/null 2>&1; }

case "$PROVIDER" in
  aws)
    have aws || { echo "aws cli not installed"; exit 1; }
    echo "== caller ==" ; aws sts get-caller-identity
    echo "== attached/inline (self) ==" ; aws iam list-attached-user-policies --user-name "$(aws sts get-caller-identity --query Arn --output text | awk -F/ '{print $NF}')" 2>/dev/null || echo "(cannot self-read; try enumerate-iam)"
    echo "[hint] privesc primitives to look for: iam:PassRole(+lambda/ec2/cfn), iam:Create*/Attach*Policy,"
    echo "       iam:CreateAccessKey(other user), sts:AssumeRole(priv role), iam:CreatePolicyVersion."
    have enumerate-iam.py && echo "[hint] run enumerate-iam for brute permission discovery"
    have cloudsplaining && echo "[hint] run cloudsplaining on the account authorization details"
    ;;
  azure)
    have az || { echo "az cli not installed"; exit 1; }
    az ad signed-in-user show 2>/dev/null || az account show
    az role assignment list --all -o table 2>/dev/null | head -50
    echo "[hint] look for Owner/Contributor sprawl, roleAssignments/write, managed-identity abuse"
    ;;
  gcp)
    have gcloud || { echo "gcloud not installed"; exit 1; }
    gcloud auth list ; gcloud config get-value project
    PROJ="$(gcloud config get-value project 2>/dev/null)"
    [[ -n "$PROJ" ]] && gcloud projects get-iam-policy "$PROJ" 2>/dev/null | head -80
    echo "[hint] look for iam.serviceAccounts.actAs(+deploy), setIamPolicy, key creation, getAccessToken/signJwt, owner sprawl"
    ;;
  *) echo "Usage: iam-enum.sh [aws|azure|gcp]"; exit 1 ;;
esac
