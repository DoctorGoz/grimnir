#!/bin/bash
set -euo pipefail
# Nomad — APK static triage: decompile, secrets, endpoints. Read-only.
# Usage: apk-recon.sh <app.apk | package.id> [out_dir]
#   If a package id is given, pulls it first via scripts/pull-apk.sh (needs adb).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
JADX="${JADX:-$HOME/tools/jadx/bin/jadx}"
TARGET="${1:?Usage: apk-recon.sh <app.apk | package.id> [out_dir]}"
OUT="${2:-./nomad-recon}"
have() { command -v "$1" >/dev/null 2>&1; }

APK="$TARGET"
if [[ "$TARGET" != *.apk ]]; then
  echo "[nomad] '$TARGET' looks like a package id — pulling via pull-apk.sh"
  bash "$REPO_ROOT/scripts/pull-apk.sh" "$TARGET" "$OUT/apk" || { echo "pull failed"; exit 1; }
  APK="$(find "$OUT/apk" -name '*.apk' | grep -iE 'base|/[^/]*\.apk$' | head -1)"
  echo "[nomad] using $APK"
fi
[[ -f "$APK" ]] || { echo "APK not found: $APK"; exit 1; }

mkdir -p "$OUT/src"
FORCE="${FORCE:-0}"
if [[ -d "$OUT/src/sources" && -n "$(ls -A "$OUT/src/sources" 2>/dev/null)" && "$FORCE" != "1" ]]; then
  echo "[nomad] reusing existing jadx output in $OUT/src (set FORCE=1 to re-decompile)"
elif [[ -x "$JADX" ]]; then
  echo "[nomad] decompiling with jadx (large APKs take minutes)..."
  "$JADX" -d "$OUT/src" "$APK" 2>/dev/null || echo "[nomad] jadx exited non-zero — partial output is still usable"
else
  echo "[nomad] jadx not at $JADX — set JADX=... (see reference-jadx-install)"
fi

echo "== Hardcoded secret candidates =="
grep -rEon -f "$SCRIPT_DIR/../wordlists/secret-patterns.txt" "$OUT/src" 2>/dev/null | head -40 || echo "(none / jadx output missing)"

echo "== Endpoints / URLs =="
grep -rEoh 'https?://[a-zA-Z0-9._/~%-]+' "$OUT/src" 2>/dev/null | sort -u | head -60 || true

echo "[nomad] Review $OUT/src. Route endpoints -> needs-specter, cloud keys -> needs-nimbus. Verify any secret is LIVE before reporting."
