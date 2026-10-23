#!/bin/bash
set -uo pipefail
# Nomad — jadx launcher with binary auto-detection.
# Usage: jadx-run.sh <apk> <out_dir> [extra jadx args...]
# Auto-detects the jadx binary across common install locations; extra args are
# passed through (e.g. --no-res). Progress goes to stdout/stderr of the caller.

APK="${1:?Usage: jadx-run.sh <apk> <out_dir> [extra jadx args...]}"
OUT="${2:?Usage: jadx-run.sh <apk> <out_dir> [extra jadx args...]}"
shift 2

for candidate in "${JADX:-}" "$HOME/bin/jadx" "$HOME/tools/jadx/bin/jadx" \
                 "$(command -v jadx 2>/dev/null)"; do
  if [[ -n "$candidate" && -x "$candidate" ]]; then
    JADX_BIN="$candidate"
    break
  fi
done
if [[ -z "${JADX_BIN:-}" ]]; then
  echo "[jadx-run] jadx not found: set JADX=/path/to/jadx" >&2
  exit 127
fi

echo "[jadx-run] using $JADX_BIN -> $OUT"
"$JADX_BIN" -d "$OUT" "$@" "$APK"
rc=$?
echo "[jadx-run] jadx exit code: $rc"
exit $rc
