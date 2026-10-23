#!/bin/bash
# Hunter — SMB/Windows Enumeration Suite
# Usage: ./smb-enum.sh TARGET [USERNAME] [PASSWORD]
#
# Comprehensive Windows/SMB enumeration using multiple tools

set -euo pipefail

TARGET="${1:?Usage: $0 TARGET [USERNAME] [PASSWORD]}"
USERNAME="${2:-}"
PASSWORD="${3:-}"
OUTPUT_DIR="${4:-./recon}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p "$OUTPUT_DIR/smb"

# ── Egress ──
# A program's egress proxy (roe.json "proxy" / GRIMNIR_PROXY, exported by the calling harness) carries
# HTTP(S) target traffic, but SMB enumeration (enum4linux/netexec/nmap/smbclient) speaks SMB over raw
# sockets and cannot ride it. When a proxy is configured this refuses (exit 4) rather than enumerating
# from an address outside the proxy.
source "$(dirname "${BASH_SOURCE[0]}")/../../scripts/egress-env.sh"
egress_init "" || exit 4
egress_refuse_if_proxied "SMB enumeration (enum4linux/netexec/nmap/smbclient)" || exit 4

echo "[*] Hunter — SMB/Windows Enumeration"
echo "[*] Target: $TARGET"
echo "[*] Started: $(date)"
echo "---"

# Build auth flags
NXC_AUTH=""
E4L_AUTH=""
if [ -n "$USERNAME" ] && [ -n "$PASSWORD" ]; then
    NXC_AUTH="-u $USERNAME -p $PASSWORD"
    E4L_AUTH="-u $USERNAME -p $PASSWORD"
    echo "[+] Using credentials: $USERNAME"
fi

# Phase 1: enum4linux
echo "[+] Phase 1: enum4linux full enumeration"
enum4linux -a $E4L_AUTH "$TARGET" > "$OUTPUT_DIR/smb/enum4linux-${TIMESTAMP}.txt" 2>&1 || true

# Phase 2: netexec enumeration
echo "[+] Phase 2: netexec SMB enumeration"
netexec smb "$TARGET" $NXC_AUTH > "$OUTPUT_DIR/smb/nxc-info-${TIMESTAMP}.txt" 2>&1 || true
netexec smb "$TARGET" $NXC_AUTH --shares > "$OUTPUT_DIR/smb/nxc-shares-${TIMESTAMP}.txt" 2>&1 || true
netexec smb "$TARGET" $NXC_AUTH --users > "$OUTPUT_DIR/smb/nxc-users-${TIMESTAMP}.txt" 2>&1 || true
netexec smb "$TARGET" $NXC_AUTH --groups > "$OUTPUT_DIR/smb/nxc-groups-${TIMESTAMP}.txt" 2>&1 || true
netexec smb "$TARGET" $NXC_AUTH --pass-pol > "$OUTPUT_DIR/smb/nxc-passpol-${TIMESTAMP}.txt" 2>&1 || true

# Phase 3: Nmap SMB scripts
echo "[+] Phase 3: Nmap SMB scripts"
nmap -p 139,445 --script smb-enum-shares,smb-enum-users,smb-os-discovery,smb-security-mode,smb-vuln-ms17-010,smb-vuln-ms08-067 "$TARGET" -oN "$OUTPUT_DIR/smb/nmap-smb-${TIMESTAMP}.txt" 2>/dev/null || true

# Phase 4: Null session check
echo "[+] Phase 4: Null session check"
smbclient -L "//$TARGET/" -N > "$OUTPUT_DIR/smb/null-session-${TIMESTAMP}.txt" 2>&1 || true

echo "---"
echo "[*] SMB enumeration complete"
echo "[*] Results saved to: $OUTPUT_DIR/smb/"
echo "[*] Completed: $(date)"
