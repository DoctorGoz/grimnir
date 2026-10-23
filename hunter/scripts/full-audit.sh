#!/bin/bash
# Hunter — Full Infrastructure Audit Pipeline
# Usage: ./full-audit.sh TARGET [OPTIONS]
#
# Runs the complete Hunter workflow: discover → enumerate → scan → report
# OPTIONS:
#   --skip-creds     Skip credential spraying
#   --ports PORTS    Limit to specific ports
#   --output DIR     Custom output directory

set -euo pipefail

TARGET="${1:?Usage: $0 TARGET [OPTIONS]}"
shift

# Parse options
SKIP_CREDS=false
PORTS=""
OUTPUT_DIR="./recon"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-creds) SKIP_CREDS=true; shift ;;
        --ports) PORTS="$2"; shift 2 ;;
        --output) OUTPUT_DIR="$2"; shift 2 ;;
        *) shift ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p "$OUTPUT_DIR"

# ── Egress ──
# A program's egress proxy (roe.json "proxy" / GRIMNIR_PROXY, exported by the calling harness) carries
# HTTP(S) target traffic, but this pipeline is raw-socket scanning end to end (nmap/enum4linux/hydra).
# When a proxy is configured the whole audit refuses here (exit 4), up front and with one clear
# message, rather than failing mid-phase once a sub-script refuses.
source "$SCRIPT_DIR/../../scripts/egress-env.sh"
egress_init "" || exit 4
egress_refuse_if_proxied "the Hunter infrastructure audit (nmap/enum4linux/hydra)" || exit 4

echo "============================================"
echo "  Hunter — Full Infrastructure Audit"
echo "============================================"
echo "[*] Target: $TARGET"
echo "[*] Output: $OUTPUT_DIR"
echo "[*] Started: $(date)"
echo "============================================"

# Phase 1: Host Discovery & Port Scanning
echo ""
echo "[===] PHASE 1: DISCOVERY [===]"
bash "$SCRIPT_DIR/host-discovery.sh" "$TARGET" "$OUTPUT_DIR"

# Phase 2: Service Enumeration
echo ""
echo "[===] PHASE 2: ENUMERATION [===]"
bash "$SCRIPT_DIR/service-enum.sh" "$TARGET" "$PORTS" "$OUTPUT_DIR"

# Phase 3: Vulnerability Scanning
echo ""
echo "[===] PHASE 3: VULNERABILITY SCANNING [===]"
bash "$SCRIPT_DIR/vuln-scan.sh" "$TARGET" "$PORTS" "$OUTPUT_DIR"

# Phase 4: SMB Enumeration (if SMB ports found)
if grep -qE "445/open|139/open" "$OUTPUT_DIR"/full-ports-*.gnmap 2>/dev/null; then
    echo ""
    echo "[===] PHASE 4: SMB ENUMERATION [===]"
    bash "$SCRIPT_DIR/smb-enum.sh" "$TARGET" "" "" "$OUTPUT_DIR"
fi

# Phase 5: Credential Testing (unless skipped)
if [ "$SKIP_CREDS" = false ]; then
    echo ""
    echo "[===] PHASE 5: CREDENTIAL TESTING [===]"
    # Test default creds on discovered services
    for service in ssh ftp mysql; do
        if grep -qE "${service}" "$OUTPUT_DIR"/deep-scan-*.nmap 2>/dev/null; then
            echo "[+] Testing default credentials on $service"
            bash "$SCRIPT_DIR/cred-spray.sh" "$TARGET" "$service" "" "" "$OUTPUT_DIR" || true
        fi
    done
fi

echo ""
echo "============================================"
echo "  Hunter — Audit Complete"
echo "============================================"
echo "[*] All results saved to: $OUTPUT_DIR/"
echo "[*] Review key findings in:"
echo "    - $OUTPUT_DIR/vulns/     — vulnerability scan results"
echo "    - $OUTPUT_DIR/services/  — service enumeration"
echo "    - $OUTPUT_DIR/creds/     — credential test results"
echo "    - $OUTPUT_DIR/smb/       — SMB/Windows enumeration"
echo "[*] Completed: $(date)"
echo "============================================"
