#!/bin/bash
# Hunter — Host Discovery & Port Scanning
# Usage: ./host-discovery.sh TARGET [OUTPUT_DIR]
#
# TARGET can be: IP, CIDR, hostname, or file with targets (-iL)

set -euo pipefail

TARGET="${1:?Usage: $0 TARGET [OUTPUT_DIR]}"
OUTPUT_DIR="${2:-./recon}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p "$OUTPUT_DIR"

# ── Egress ──
# A program's egress proxy (roe.json "proxy" / GRIMNIR_PROXY, exported by the calling harness) carries
# HTTP(S) target traffic, but nmap uses raw sockets (SYN/ICMP) and cannot ride it. When a proxy is
# configured this refuses (exit 4) rather than scanning from an address outside the proxy.
source "$(dirname "${BASH_SOURCE[0]}")/../../scripts/egress-env.sh"
egress_init "" || exit 4
egress_refuse_if_proxied "nmap host discovery / port scan" || exit 4

echo "[*] Hunter — Host Discovery & Port Scanning"
echo "[*] Target: $TARGET"
echo "[*] Output: $OUTPUT_DIR"
echo "[*] Started: $(date)"
echo "---"

# Phase 1: Host Discovery (if CIDR or range)
if [[ "$TARGET" == *"/"* ]] || [[ "$TARGET" == *"-"* ]]; then
    echo "[+] Phase 1: Host discovery on range $TARGET"
    nmap -sn "$TARGET" -oG "$OUTPUT_DIR/host-discovery-${TIMESTAMP}.gnmap" 2>/dev/null | grep "Up" | awk '{print $2}' > "$OUTPUT_DIR/live-hosts.txt"
    LIVE_COUNT=$(wc -l < "$OUTPUT_DIR/live-hosts.txt")
    echo "[+] Found $LIVE_COUNT live hosts"
    SCAN_TARGET="-iL $OUTPUT_DIR/live-hosts.txt"
else
    echo "[+] Single target mode: $TARGET"
    echo "$TARGET" > "$OUTPUT_DIR/live-hosts.txt"
    SCAN_TARGET="$TARGET"
fi

# Phase 2: Fast port scan (top 1000)
echo "[+] Phase 2: Fast port scan (top 1000 ports)"
nmap -sS -sV --top-ports 1000 -T4 --open -oA "$OUTPUT_DIR/fast-scan-${TIMESTAMP}" $SCAN_TARGET 2>/dev/null
echo "[+] Fast scan complete"

# Phase 3: Full port scan (all 65535)
echo "[+] Phase 3: Full port scan (all ports)"
nmap -sS -p- -T4 --open -oG "$OUTPUT_DIR/full-ports-${TIMESTAMP}.gnmap" $SCAN_TARGET 2>/dev/null
echo "[+] Full scan complete"

# Phase 4: Service version detection on discovered ports
OPEN_PORTS=$(grep -oP '\d+/open' "$OUTPUT_DIR/full-ports-${TIMESTAMP}.gnmap" 2>/dev/null | cut -d/ -f1 | sort -un | tr '\n' ',' | sed 's/,$//')
if [ -n "$OPEN_PORTS" ]; then
    echo "[+] Phase 4: Deep service scan on ports: $OPEN_PORTS"
    nmap -sV -sC -O -p "$OPEN_PORTS" -oA "$OUTPUT_DIR/deep-scan-${TIMESTAMP}" $SCAN_TARGET 2>/dev/null
    echo "[+] Deep scan complete"
fi

# Phase 5: OS fingerprinting summary
echo "[+] Phase 5: Results summary"
echo "---"
echo "[*] Scan results saved to: $OUTPUT_DIR/"
echo "[*] Key files:"
echo "    - live-hosts.txt       — discovered hosts"
echo "    - fast-scan-*          — top 1000 port results"
echo "    - full-ports-*         — all-port scan results"
echo "    - deep-scan-*          — service/version/OS details"
echo "[*] Completed: $(date)"
