#!/bin/bash
set -euo pipefail
# Nimbus — public object-storage exposure check (anonymous). Non-destructive: read-only.
# Supports AWS S3, Azure Blob, and Google Cloud Storage.
# Usage: storage-scan.sh <target> [--type aws|azure|gcs|auto]
#   <target>: bucket name (aws/gcs), container URL (azure), or file with one target per line
#   --type: force provider; auto detects from name if omitted

TYPE="auto"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --type) TYPE="$2"; shift 2 ;;
    --help|-h) echo "Usage: storage-scan.sh <target> [--type aws|azure|gcs|auto]"; exit 0 ;;
    *) ARG="$1"; shift ;;
  esac
done
[[ -z "${ARG:-}" ]] && { echo "Usage: storage-scan.sh <target> [--type aws|azure|gcs|auto]" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# ── Egress ──
# A program's egress proxy (roe.json "proxy" / GRIMNIR_PROXY) carries its target traffic — here the
# bucket/container endpoints. This script takes no project dir, so egress_init reads GRIMNIR_PROXY
# from the environment (the calling harness exports it) and exports ALL_PROXY/HTTP(S)_PROXY for curl. An
# unusable proxy refuses the run (exit 4) rather than scanning from an unproxied address.
source "$(dirname "${BASH_SOURCE[0]}")/../../scripts/egress-env.sh"
egress_init "" || exit 4

scan_aws() {
  local b="$1"
  echo "== AWS S3: $b =="
  if have aws; then
    if aws s3 ls "s3://$b" --no-sign-request >/dev/null 2>&1; then
      echo "  [PUBLIC-LIST] s3://$b is anonymously listable"
      aws s3 ls "s3://$b" --no-sign-request 2>/dev/null | head -10
    else
      echo "  s3 ls failed (not public or wrong region)"
    fi
    aws s3api get-bucket-acl --bucket "$b" --no-sign-request 2>/dev/null | grep -i 'AllUsers\|AuthenticatedUsers' && echo "  [ACL] public grant present" || true
  else
    # HTTP fallback
    local code
    code=$(curl -s -o /dev/null -w '%{http_code}' "https://$b.s3.amazonaws.com/?list-type=2" 2>/dev/null || true)
    echo "  s3 HTTP list: $code ($([ "$code" = "200" ] && echo 'PUBLIC' || echo 'not public'))"
  fi
}

scan_azure() {
  # Accept: <account>.blob.core.windows.net/<container> or just <account>/<container>
  local target="$1" account container
  if [[ "$target" == *blob.core.windows.net* ]]; then
    account="${target%%.blob.core.windows.net*}"
    container="${target#*/}"
  elif [[ "$target" == */* ]]; then
    account="${target%%/*}"
    container="${target#*/}"
  else
    echo "  [azure] format: <account>.blob.core.windows.net/<container> or <account>/<container>"
    return 1
  fi
  echo "== Azure Blob: $account / $container =="
  # Anonymous container listing
  local code body
  body=$(curl -s -m 15 -w '\n%{http_code}' \
    "https://${account}.blob.core.windows.net/${container}?restype=container&comp=list" 2>/dev/null || true)
  code=$(echo "$body" | tail -1)
  if [[ "$code" == "200" ]]; then
    echo "  [PUBLIC-LIST] Container $container is anonymously listable"
    local count
    count=$(echo "$body" | grep -o '<Blob>' 2>/dev/null | wc -l || echo 0)
    echo "  ($count blobs visible — showing first 5 paths)"
    echo "$body" | grep -oP '<Name>\K[^<]+' 2>/dev/null | head -5 | sed 's/^/    /'
  else
    echo "  azure anon list: $code ($([ "$code" = "404" ] && echo 'not found' || [ "$code" = "403" ] && echo 'forbidden' || echo 'check manually'))"
  fi
  # Negative control: account-level listing
  local neg
  neg=$(curl -s -o /dev/null -w '%{http_code}' -m 10 \
    "https://${account}.blob.core.windows.net/?comp=list" 2>/dev/null || true)
  echo "  account-level list (neg control): $neg ($([ "$neg" != "200" ] && echo 'properly gated' || echo 'ALSO PUBLIC — flag this'))"
}

scan_gcs() {
  local b="$1"
  echo "== GCS: $b =="
  local code
  code=$(curl -s -o /dev/null -w '%{http_code}' -m 10 \
    "https://storage.googleapis.com/${b}?max-results=10" 2>/dev/null || true)
  echo "  gcs anon list: $code ($([ "$code" = "200" ] && echo 'PUBLIC' || echo 'not public'))"
  # Try bucket-level ACL via uniform bucket-level access check
  local iam_code
  iam_code=$(curl -s -o /dev/null -w '%{http_code}' -m 10 \
    "https://storage.googleapis.com/${b}?acl" 2>/dev/null || true)
  [[ "$iam_code" == "200" ]] && echo "  [ACL] bucket ACL is publicly readable" || true
}

scan() {
  local target="$1" inferred="${TYPE}"
  if [[ "$inferred" == "auto" ]]; then
    if [[ "$target" == *.blob.core.windows.net/* ]] || [[ "$target" == *blob.core.windows.net ]]; then
      inferred="azure"
    elif [[ "$target" == *.appspot.com ]] || [[ "$target" == *firebaseio.com ]]; then
      inferred="gcs"
    elif have aws; then
      inferred="aws"   # default to aws if cli present
    else
      echo "  cannot auto-detect provider for '$target' — pass --type aws|azure|gcs"
      return 1
    fi
  fi
  case "$inferred" in
    aws|s3)   scan_aws "$target" ;;
    azure)    scan_azure "$target" ;;
    gcs|gcp)  scan_gcs "$target" ;;
    *)        echo "Unknown type: $inferred (use aws, azure, or gcs)" >&2; return 1 ;;
  esac
}

if [[ -f "$ARG" ]]; then
  while read -r t; do [[ -n "$t" && "$t" != \#* ]] && scan "$t"; done < "$ARG"
else
  scan "$ARG"
fi
echo "[note] Public list != sensitive data. Confirm with a single object GET + negative control before reporting."
