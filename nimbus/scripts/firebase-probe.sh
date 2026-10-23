#!/bin/bash
set -euo pipefail
# Nimbus — Firebase project anonymous-access probe. Non-destructive: read-only.
# Tests common Firebase backend surfaces reachable without authentication.
# Usage: firebase-probe.sh <project-id> [api-key]
#   project-id: Firebase project ID (e.g. "mobile-app-2dc3b")
#   api-key:    optional web API key for Firestore REST (from the app's google-services.json)

PROJECT="${1:?Usage: firebase-probe.sh <project-id> [api-key]}"
API_KEY="${2:-}"
CURL=(curl -s -m 10 -w '\n%{http_code}')

# ── Egress ──
# A program's egress proxy (roe.json "proxy" / GRIMNIR_PROXY) carries its target traffic — here the
# project's Firebase backends. This script takes no project dir, so egress_init reads GRIMNIR_PROXY
# from the environment (the calling harness exports it) and exports ALL_PROXY/HTTP(S)_PROXY for curl. An
# unusable proxy refuses the run (exit 4) rather than probing from an unproxied address.
source "$(dirname "${BASH_SOURCE[0]}")/../../scripts/egress-env.sh"
egress_init "" || exit 4

echo "=== Firebase probe: $PROJECT ==="
echo ""

# ── 1. Realtime Database ──
echo "--- Realtime Database ---"
code=$("${CURL[@]}" -o /tmp/nimbus-rtdb-$$.txt "https://${PROJECT}.firebaseio.com/.json" 2>/dev/null | tail -1)
body=$(cat /tmp/nimbus-rtdb-$$.txt 2>/dev/null || true)
rm -f /tmp/nimbus-rtdb-$$.txt
case "$code" in
  200) echo "  [OPEN] RTDB root is WORLD-READABLE"
       echo "$body" | head -10 ;;
  401) echo "  [LOCKED] RTDB requires auth (401)" ;;
  423) echo "  [OFF] RTDB is deactivated (423)" ;;
  *)   echo "  RTDB: $code $([ -n "$body" ] && echo "- $(echo "$body" | head -1)")" ;;
esac

# Regional RTDB variant
for region in europe-west1 us-central1 asia-southeast1; do
  rcode=$("${CURL[@]}" -o /dev/null "https://${PROJECT}-default-rtdb.${region}.firebasedatabase.app/.json" 2>/dev/null | tail -1)
  [[ "$rcode" != "404" ]] && echo "  regional (${region}): $rcode"
done

# ── 2. Firestore REST API (needs API key) ──
echo "--- Firestore ---"
if [[ -n "$API_KEY" ]]; then
  # Common collection names to probe
  for col in users customers orders email_sender loyalty messages notifications; do
    fcode=$("${CURL[@]}" -o /dev/null \
      "https://firestore.googleapis.com/v1/projects/${PROJECT}/databases/(default)/documents/${col}?key=${API_KEY}" 2>/dev/null | tail -1)
    [[ "$fcode" != "404" && "$fcode" != "403" ]] && echo "  [${col}] $fcode ($([ "$fcode" = "200" ] && echo 'READABLE — CHECK DATA' || echo 'check manually'))"
  done
  # Also check if ANY collection is listable
  list_code=$("${CURL[@]}" -o /tmp/nimbus-fs-$$.txt \
    "https://firestore.googleapis.com/v1/projects/${PROJECT}/databases/(default)/documents?key=${API_KEY}&pageSize=5" 2>/dev/null | tail -1)
  if [[ "$list_code" == "200" ]]; then
    echo "  [LIST] Firestore collection listing is ENABLED"
    head -5 /tmp/nimbus-fs-$$.txt
  else
    echo "  collection listing: $list_code (gated)"
  fi
  rm -f /tmp/nimbus-fs-$$.txt
else
  echo "  (no API key — skip Firestore REST; pass as 2nd arg)"
fi

# ── 3. Cloud Storage (GCS bucket) ──
echo "--- Cloud Storage ---"
# Default Firebase Storage bucket: <project>.appspot.com
for bucket in "${PROJECT}.appspot.com" "${PROJECT}.firebasestorage.app"; do
  gcs_code=$("${CURL[@]}" -o /dev/null \
    "https://storage.googleapis.com/${bucket}?max-results=5" 2>/dev/null | tail -1)
  echo "  ${bucket}: $gcs_code ($([ "$gcs_code" = "200" ] && echo 'PUBLIC' || echo 'gated'))"
done

# ── 4. Auth: anonymous / email-password signup check ──
echo "--- Auth ---"
if [[ -n "$API_KEY" ]]; then
  # Check if anonymous sign-in is enabled
  anon_resp=$("${CURL[@]}" -X POST \
    -H 'Content-Type: application/json' \
    -d '{"returnSecureToken":true}' \
    "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=${API_KEY}" 2>/dev/null | head -1)
  if echo "$anon_resp" | grep -q 'ADMIN_ONLY_OPERATION'; then
    echo "  anonymous signup: DISABLED (admin-only)"
  elif echo "$anon_resp" | grep -q 'idToken'; then
    echo "  [OPEN] anonymous signup ENABLED — anyone can create accounts"
  else
    echo "  anonymous signup: $(echo "$anon_resp" | head -c 100)"
  fi

  # Check if email/password signup is enabled (light probe — don't create accounts)
  email_resp=$("${CURL[@]}" -X POST \
    -H 'Content-Type: application/json' \
    -d '{"email":"test@example.com","password":"test123456","returnSecureToken":false}' \
    "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=${API_KEY}" 2>/dev/null | head -1)
  if echo "$email_resp" | grep -q 'ADMIN_ONLY_OPERATION'; then
    echo "  email/password signup: DISABLED (admin-only)"
  elif echo "$email_resp" | grep -q 'WEAK_PASSWORD'; then
    echo "  email/password signup: ENABLED (weak password rejected — signup IS available)"
  elif echo "$email_resp" | grep -q 'EMAIL_EXISTS'; then
    echo "  email/password signup: ENABLED (test account already exists)"
  else
    echo "  email/password signup: $(echo "$email_resp" | head -c 100)"
  fi
else
  echo "  (no API key — skip Auth check)"
fi

# ── 5. Hosting / config ──
echo "--- Hosting ---"
hcode=$("${CURL[@]}" -o /dev/null "https://${PROJECT}.web.app/__/firebase/init.json" 2>/dev/null | tail -1)
[[ "$hcode" == "200" ]] && echo "  Firebase Hosting config is PUBLICLY accessible (may leak project config)" || echo "  hosting config: $hcode"

# ── Summary ──
echo ""
echo "[note] Check any 200/OPEN result for actual data sensitivity. Public access alone may not be a finding — confirm the DATA is customer/sensitive before reporting."
