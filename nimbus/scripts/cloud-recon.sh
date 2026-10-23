#!/bin/bash
set -euo pipefail
# Nimbus — cloud posture recon launcher.
# Detects available cloud CLIs/creds and runs a read-only posture scan
# (ScoutSuite / Prowler) when present. Non-destructive.
#
# Usage: cloud-recon.sh [aws|azure|gcp]   (auto-detects if omitted)

# Egress: the cloud CLIs and posture scanners reach the provider control plane (the in-scope
# account) — route that target traffic through the program's egress proxy (roe.json "proxy" /
# GRIMNIR_PROXY) or refuse (exit 4). aws/az/gcloud and prowler/scout read the exported HTTP(S)_PROXY.
# No project dir here -> env only. Same pattern as storage-scan.sh / firebase-probe.sh.
source "$(dirname "${BASH_SOURCE[0]}")/../../scripts/egress-env.sh"
egress_init "" || exit 4

PROVIDER="${1:-auto}"
have() { command -v "$1" >/dev/null 2>&1; }

detect() {
  if have aws && aws sts get-caller-identity >/dev/null 2>&1; then echo aws; return; fi
  if have az && az account show >/dev/null 2>&1; then echo azure; return; fi
  if have gcloud && gcloud auth list --filter=status:ACTIVE --format='value(account)' 2>/dev/null | grep -q .; then echo gcp; return; fi
  echo none
}

[[ "$PROVIDER" == auto ]] && PROVIDER="$(detect)"
echo "[nimbus] provider: $PROVIDER"

case "$PROVIDER" in
  aws)
    aws sts get-caller-identity || { echo "No valid AWS creds"; exit 1; }
    if have prowler; then echo "[nimbus] running prowler (read-only)..."; prowler aws -M json -q || true
    elif have scout; then echo "[nimbus] running ScoutSuite..."; scout aws || true
    else echo "[nimbus] install prowler or scoutsuite for a full posture scan"; fi
    ;;
  azure)
    az account show
    have scout && { echo "[nimbus] ScoutSuite azure..."; scout azure --cli || true; } || echo "[nimbus] install scoutsuite/prowler"
    ;;
  gcp)
    gcloud projects list 2>/dev/null | head
    have scout && { echo "[nimbus] ScoutSuite gcp..."; scout gcp --user-account || true; } || echo "[nimbus] install scoutsuite/prowler"
    ;;
  *)
    echo "No active cloud credentials detected. Configure aws/az/gcloud (in-scope account only) and retry." ; exit 1 ;;
esac
