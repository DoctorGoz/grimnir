#!/usr/bin/env bash
# pull-apk-remote.sh — Acquire APKs from remote sources without a connected device
#
# Tries multiple sources in priority order, with geo-egress awareness for
# region-locked Play Store apps.
#
# Usage: pull-apk-remote.sh <package.id> [output_dir] [--source <source>] [--egress <host>]
#
# Sources (tried in order if not specified):
#   1. apk-pure     — APKPure  CDN (no auth, no geo, fastest)
#   2. google-play  — Google Play Store (needs geo-egress if region-locked)
#   3. aurora       — Anonymous Play Store via gplaydl (needs geo-egress, no Google account)
#
# Egress: SSH host to run downloads from (configure in ~/.ssh/config). Use when
# the app is geo-restricted and your local IP doesn't match the target region.
# Requires apkeep binary on the egress host (auto-installed if missing).
#
# Examples:
#   pull-apk-remote.sh com.example.app                              # auto all sources, local
#   pull-apk-remote.sh com.example.app --egress geo-host            # route through egress
#   pull-apk-remote.sh com.example.app --source google-play --egress geo-host

set -euo pipefail

PACKAGE="${1:?Usage: pull-apk-remote.sh <package.id> [output_dir] [--source src] [--egress host]}"
shift

OUTDIR="."
SOURCE=""
EGRESS=""
APKEEP_URL="https://github.com/EFForg/apkeep/releases/latest/download/apkeep-x86_64-unknown-linux-gnu"
APKEEP_BIN="apkeep"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --source) SOURCE="$2"; shift 2 ;;
        --egress) EGRESS="$2"; shift 2 ;;
        *) OUTDIR="$1"; shift ;;
    esac
done

mkdir -p "$OUTDIR"

# ---- ensure apkeep available ----
ensure_apkeep() {
    local host="${1:-local}"
    if [[ "$host" == "local" ]]; then
        if ! command -v "$APKEEP_BIN" &>/dev/null; then
            echo "[pull-apk-remote] downloading apkeep..."
            curl -sL "$APKEEP_URL" -o /tmp/apkeep && chmod +x /tmp/apkeep
            APKEEP_BIN="/tmp/apkeep"
        fi
    else
        ssh "$host" "command -v apkeep &>/dev/null || { curl -sL '$APKEEP_URL' -o /tmp/apkeep && chmod +x /tmp/apkeep; }"
    fi
}

# ---- run apkeep on a host ----
run_apkeep() {
    local host="${1:-local}"
    local source="${2:-apk-pure}"
    local package="$3"
    local out="$4"
    local bin="$APKEEP_BIN"

    if [[ "$host" != "local" ]]; then
        bin="/tmp/apkeep"
        ssh "$host" "mkdir -p $out && $bin -a '$package' -d '$source' '$out'" 2>&1
    else
        "$bin" -a "$package" -d "$source" "$out" 2>&1
    fi
}

# ---- try gplaydl on a host ----
run_gplaydl() {
    local host="${1:-local}"
    local package="$2"
    local out="$3"

    local cmd="~/.local/bin/gplaydl auth 2>&1 && ~/.local/bin/gplaydl download '$package' -o '$out' 2>&1"
    if [[ "$host" != "local" ]]; then
        ssh "$host" "$cmd"
    else
        bash -c "$cmd"
    fi
}

# ---- main ----

SOURCES=()
if [[ -n "$SOURCE" ]]; then
    SOURCES=("$SOURCE")
else
    SOURCES=("apk-pure")  # APKPure first (fast, no geo)
fi

HOST="${EGRESS:-local}"
if [[ "$HOST" != "local" ]]; then
    echo "[pull-apk-remote] egress: $HOST"
fi

for src in "${SOURCES[@]}"; do
    echo "[pull-apk-remote] trying $src for $PACKAGE..."
    ensure_apkeep "$HOST"

    RESULT=$(run_apkeep "$HOST" "$src" "$PACKAGE" "$OUTDIR" || true)

    if echo "$RESULT" | grep -q "downloaded successfully"; then
        echo "[pull-apk-remote] ✓ $PACKAGE from $src"

        # If run remotely, rsync back
        if [[ "$HOST" != "local" ]]; then
            echo "[pull-apk-remote] rsyncing from $HOST..."
            rsync -avz -e 'ssh' "$HOST:$OUTDIR/" "$OUTDIR/"
        fi

        # Handle xapk bundles
        for xapk in "$OUTDIR"/*.xapk; do
            if [[ -f "$xapk" ]]; then
                BASENAME=$(basename "$xapk" .xapk)
                echo "[pull-apk-remote] extracting xapk: $xapk → ${OUTDIR}/${BASENAME}_extracted/"
                mkdir -p "${OUTDIR}/${BASENAME}_extracted"
                unzip -o "$xapk" -d "${OUTDIR}/${BASENAME}_extracted" > /dev/null
                echo "[pull-apk-remote] apk files:"
                find "${OUTDIR}/${BASENAME}_extracted" -name "*.apk" -exec ls -lh {} \;
            fi
        done

        # List downloaded files
        echo "[pull-apk-remote] output:"
        find "$OUTDIR" -name "*.apk" -o -name "*.xapk" | while read -r f; do
            echo "  $(basename "$f") ($(du -h "$f" | cut -f1))"
        done
        exit 0
    fi

    echo "[pull-apk-remote] ✗ $src failed: ${RESULT:0:200}"
done

# apkeep sources exhausted — try gplaydl if egress host available and source not pinned
if [[ -z "$SOURCE" && "$HOST" != "local" ]]; then
    echo "[pull-apk-remote] trying gplaydl (anonymous Play Store) via $HOST..."
    GPLAY_RESULT=$(run_gplaydl "$HOST" "$PACKAGE" "$OUTDIR" || true)
    if echo "$GPLAY_RESULT" | grep -q "downloaded successfully"; then
        echo "[pull-apk-remote] ✓ $PACKAGE via gplaydl"
        rsync -avz -e 'ssh' "$HOST:$OUTDIR/" "$OUTDIR/"
        exit 0
    fi
    echo "[pull-apk-remote] ✗ gplaydl failed"
fi

# Everything failed
echo "[pull-apk-remote] ✗ ALL automated sources exhausted for $PACKAGE"
echo "[pull-apk-remote] → Fallback: install Aurora Store on an emulator routed through a geo-matching egress point"
exit 1
