#!/usr/bin/env bash
# Pull all APK splits for a package from a connected Android device.
# Usage: pull-apk.sh <package.id> [output_dir]

set -euo pipefail

PACKAGE="${1:-}"
OUT_DIR="${2:-}"

usage() {
    echo "Usage: $(basename "$0") <package.id> [output_dir]"
    echo "  output_dir defaults to ./apk/<package.id>"
    exit 1
}

die() { echo "ERROR: $*" >&2; exit 1; }

[[ -z "$PACKAGE" ]] && usage

# Verify adb is available and exactly one device is connected
command -v adb &>/dev/null || die "adb not found in PATH"

DEVICE_COUNT=$(adb devices | tail -n +2 | grep -c 'device$' || true)
if [[ "$DEVICE_COUNT" -eq 0 ]]; then
    die "no device connected (run 'adb devices' to check)"
elif [[ "$DEVICE_COUNT" -gt 1 ]]; then
    die "multiple devices connected — set ANDROID_SERIAL or disconnect extras"
fi

# Resolve output directory
if [[ -z "$OUT_DIR" ]]; then
    if [[ -n "${PROJECT_DIR:-}" ]]; then
        OUT_DIR="${PROJECT_DIR}/apk/${PACKAGE}"
    else
        OUT_DIR="./apk/${PACKAGE}"
    fi
fi
mkdir -p "$OUT_DIR"

# Get all APK paths for the package (handles splits)
mapfile -t APK_PATHS < <(adb shell pm path "$PACKAGE" 2>/dev/null | sed 's/^package://')

if [[ "${#APK_PATHS[@]}" -eq 0 ]]; then
    die "package '$PACKAGE' not found on device"
fi

echo "[+] Found ${#APK_PATHS[@]} APK(s) for $PACKAGE"

for REMOTE_PATH in "${APK_PATHS[@]}"; do
    FILENAME=$(basename "$REMOTE_PATH")
    LOCAL_PATH="$OUT_DIR/$FILENAME"
    echo "    pulling $FILENAME ..."
    adb pull "$REMOTE_PATH" "$LOCAL_PATH"
done

echo ""
echo "[+] Done — files in $OUT_DIR:"
ls -lh "$OUT_DIR"
