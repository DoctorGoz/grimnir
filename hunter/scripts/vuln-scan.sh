#!/bin/bash
# Hunter — Vulnerability Scanning Pipeline
# Usage: ./vuln-scan.sh TARGET [PORTS]
#
# Runs nuclei (network templates), nmap NSE vuln scripts, and searchsploit

set -euo pipefail

TARGET="${1:?Usage: $0 TARGET [PORTS]}"
PORTS="${2:-}"
OUTPUT_DIR="${3:-./recon}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p "$OUTPUT_DIR/vulns"

# ── Egress ──
# A program's egress proxy (roe.json "proxy" / GRIMNIR_PROXY, exported by the calling harness) carries
# HTTP(S) target traffic, but the nmap NSE vuln scans here use raw sockets and cannot ride it. When a
# proxy is configured this refuses (exit 4) rather than scanning from an address outside the proxy.
source "$(dirname "${BASH_SOURCE[0]}")/../../scripts/egress-env.sh"
egress_init "" || exit 4
egress_refuse_if_proxied "nmap NSE vulnerability scan" || exit 4

echo "[*] Hunter — Vulnerability Scanning"
echo "[*] Target: $TARGET"
echo "[*] Started: $(date)"
echo "---"

# Phase 1: Nmap vulnerability scripts
echo "[+] Phase 1: Nmap NSE vulnerability scan"
if [ -n "$PORTS" ]; then
    nmap -sV --script vuln -p "$PORTS" "$TARGET" -oA "$OUTPUT_DIR/vulns/nmap-vuln-${TIMESTAMP}" 2>/dev/null
else
    nmap -sV --script vuln --top-ports 1000 "$TARGET" -oA "$OUTPUT_DIR/vulns/nmap-vuln-${TIMESTAMP}" 2>/dev/null
fi
echo "[+] Nmap vuln scan complete"

# Phase 2: Nuclei network templates
echo "[+] Phase 2: Nuclei network vulnerability scan"
if [ -n "$PORTS" ]; then
    # Build target list with ports for nuclei
    for port in $(echo "$PORTS" | tr ',' ' '); do
        echo "${TARGET}:${port}"
    done > "$OUTPUT_DIR/vulns/nuclei-targets.txt"
    nuclei -l "$OUTPUT_DIR/vulns/nuclei-targets.txt" -t network/ -t ssl/ -t dns/ -severity critical,high,medium -o "$OUTPUT_DIR/vulns/nuclei-network-${TIMESTAMP}.txt" 2>/dev/null || true
else
    echo "$TARGET" | nuclei -t network/ -t ssl/ -t dns/ -severity critical,high,medium -o "$OUTPUT_DIR/vulns/nuclei-network-${TIMESTAMP}.txt" 2>/dev/null || true
fi
echo "[+] Nuclei scan complete"

# Phase 3: SSL/TLS analysis
echo "[+] Phase 3: SSL/TLS analysis"
for port in 443 8443 993 995 465 636; do
    if [ -n "$PORTS" ] && ! echo ",$PORTS," | grep -q ",$port,"; then
        continue
    fi
    timeout 10 openssl s_client -connect "${TARGET}:${port}" </dev/null 2>/dev/null | openssl x509 -noout -text > "$OUTPUT_DIR/vulns/ssl-${port}-${TIMESTAMP}.txt" 2>/dev/null && \
        echo "[+] SSL cert analyzed on port $port" || true
done

# Phase 4: Searchsploit cross-reference
echo "[+] Phase 4: Cross-referencing services with exploit-db"
if compgen -G "$OUTPUT_DIR/deep-scan-*.nmap" >/dev/null; then
    # Extract service versions from nmap output
    grep -oP '\d+/tcp\s+open\s+\S+\s+.*' "$OUTPUT_DIR"/deep-scan-*.nmap 2>/dev/null | while read -r line; do
        SERVICE=$(echo "$line" | awk '{for(i=4;i<=NF;i++) printf "%s ", $i}' | sed 's/[[:space:]]*$//')
        if [ -n "$SERVICE" ]; then
            echo "=== $SERVICE ===" >> "$OUTPUT_DIR/vulns/searchsploit-${TIMESTAMP}.txt"
            searchsploit "$SERVICE" >> "$OUTPUT_DIR/vulns/searchsploit-${TIMESTAMP}.txt" 2>/dev/null || true
            echo "" >> "$OUTPUT_DIR/vulns/searchsploit-${TIMESTAMP}.txt"
        fi
    done
fi
echo "[+] Searchsploit lookup complete"

echo "---"
echo "[*] Vulnerability scanning complete"
echo "[*] Results saved to: $OUTPUT_DIR/vulns/"
echo "[*] Key files:"
echo "    - nmap-vuln-*            — NSE vulnerability results"
echo "    - nuclei-network-*       — nuclei findings"
echo "    - ssl-*                  — TLS certificate analysis"
echo "    - searchsploit-*         — exploit-db matches"
echo "[*] Completed: $(date)"
