#!/bin/bash
# Hunter — Deep Service Enumeration
# Usage: ./service-enum.sh TARGET [PORTS]
#
# Enumerates specific services with protocol-aware tools

set -euo pipefail

TARGET="${1:?Usage: $0 TARGET [PORTS]}"
PORTS="${2:-}"
OUTPUT_DIR="${3:-./recon}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p "$OUTPUT_DIR/services"

# ── Egress ──
# A program's egress proxy (roe.json "proxy" / GRIMNIR_PROXY, exported by the calling harness) carries
# HTTP(S) target traffic, but nmap/enum4linux speak service protocols over raw sockets and cannot
# ride it. When a proxy is configured this refuses (exit 4) rather than scanning from outside it.
source "$(dirname "${BASH_SOURCE[0]}")/../../scripts/egress-env.sh"
egress_init "" || exit 4
egress_refuse_if_proxied "nmap/enum4linux service enumeration" || exit 4

echo "[*] Hunter — Service Enumeration"
echo "[*] Target: $TARGET"
echo "[*] Started: $(date)"
echo "---"

# If no ports specified, get them from prior scan or do quick scan
if [ -z "$PORTS" ]; then
    if [ -f "$OUTPUT_DIR/live-hosts.txt" ]; then
        echo "[+] Getting open ports from prior scan..."
        PORTS=$(grep -oP '\d+/open' "$OUTPUT_DIR"/full-ports-*.gnmap 2>/dev/null | cut -d/ -f1 | sort -un | tr '\n' ',' | sed 's/,$//')
    fi
    if [ -z "$PORTS" ]; then
        echo "[+] No prior scan data, running quick port scan..."
        PORTS=$(nmap -sS --top-ports 1000 --open -T4 "$TARGET" 2>/dev/null | grep "^[0-9]" | cut -d/ -f1 | tr '\n' ',' | sed 's/,$//')
    fi
fi

echo "[+] Enumerating ports: $PORTS"

# Function to check if a port is in the list
has_port() {
    echo ",$PORTS," | grep -q ",$1,"
}

# SMB (445, 139)
if has_port 445 || has_port 139; then
    echo "[+] SMB detected — running enum4linux"
    enum4linux -a "$TARGET" > "$OUTPUT_DIR/services/smb-enum-${TIMESTAMP}.txt" 2>&1 || true
    echo "[+] SMB — running netexec"
    netexec smb "$TARGET" --shares > "$OUTPUT_DIR/services/smb-shares-${TIMESTAMP}.txt" 2>&1 || true
fi

# SSH (22)
if has_port 22; then
    echo "[+] SSH detected — grabbing banner and testing auth methods"
    nmap -p22 --script ssh-auth-methods,ssh2-enum-algos,ssh-hostkey "$TARGET" -oN "$OUTPUT_DIR/services/ssh-enum-${TIMESTAMP}.txt" 2>/dev/null || true
fi

# DNS (53)
if has_port 53; then
    echo "[+] DNS detected — attempting zone transfer"
    dnsrecon -d "$TARGET" -t axfr > "$OUTPUT_DIR/services/dns-axfr-${TIMESTAMP}.txt" 2>&1 || true
fi

# SNMP (161)
if has_port 161; then
    echo "[+] SNMP detected — testing community strings"
    nmap -p161 --script snmp-brute,snmp-info,snmp-sysdescr "$TARGET" -oN "$OUTPUT_DIR/services/snmp-enum-${TIMESTAMP}.txt" 2>/dev/null || true
fi

# HTTP/HTTPS (80, 443, 8080, 8443)
for port in 80 443 8080 8443; do
    if has_port "$port"; then
        PROTO="http"
        [ "$port" = "443" ] || [ "$port" = "8443" ] && PROTO="https"
        echo "[+] HTTP(S) on port $port — fingerprinting"
        whatweb "${PROTO}://${TARGET}:${port}" > "$OUTPUT_DIR/services/http-${port}-whatweb-${TIMESTAMP}.txt" 2>&1 || true
        nikto -h "${PROTO}://${TARGET}:${port}" -output "$OUTPUT_DIR/services/http-${port}-nikto-${TIMESTAMP}.txt" -Format txt 2>/dev/null &
    fi
done

# RDP (3389)
if has_port 3389; then
    echo "[+] RDP detected — checking encryption"
    nmap -p3389 --script rdp-enum-encryption,rdp-ntlm-info "$TARGET" -oN "$OUTPUT_DIR/services/rdp-enum-${TIMESTAMP}.txt" 2>/dev/null || true
fi

# MySQL (3306)
if has_port 3306; then
    echo "[+] MySQL detected — enumerating"
    nmap -p3306 --script mysql-info,mysql-enum "$TARGET" -oN "$OUTPUT_DIR/services/mysql-enum-${TIMESTAMP}.txt" 2>/dev/null || true
fi

# PostgreSQL (5432)
if has_port 5432; then
    echo "[+] PostgreSQL detected — enumerating"
    nmap -p5432 --script pgsql-brute "$TARGET" -oN "$OUTPUT_DIR/services/pgsql-enum-${TIMESTAMP}.txt" 2>/dev/null || true
fi

# Redis (6379)
if has_port 6379; then
    echo "[+] Redis detected — checking unauth access"
    nmap -p6379 --script redis-info "$TARGET" -oN "$OUTPUT_DIR/services/redis-enum-${TIMESTAMP}.txt" 2>/dev/null || true
fi

# FTP (21)
if has_port 21; then
    echo "[+] FTP detected — checking anonymous access"
    nmap -p21 --script ftp-anon,ftp-syst "$TARGET" -oN "$OUTPUT_DIR/services/ftp-enum-${TIMESTAMP}.txt" 2>/dev/null || true
fi

# Wait for background tasks
wait 2>/dev/null

echo "---"
echo "[*] Service enumeration complete"
echo "[*] Results saved to: $OUTPUT_DIR/services/"
echo "[*] Completed: $(date)"
