#!/usr/bin/env bash
set -euo pipefail
TARGET="${1:?Usage: $0 <target_url> <wordlist> [token] [proxy]}"
WORDLIST="${2:?Specify wordlist}"
TOKEN="${3:-}"; PROXY="${4:-}"
TS=$(date +%Y%m%d-%H%M%S); OUT="reports/raw/fuzz-$TS"; mkdir -p "$OUT"

# Egress: ffuf reaches the target, so it rides the program's egress proxy (roe.json "proxy" /
# GRIMNIR_PROXY, exported by the calling harness) or the run refuses (exit 4). The program proxy wins
# over any explicit 4th-arg proxy. No project dir here -> egress_init reads GRIMNIR_PROXY from env;
# ffuf also reads the exported HTTP(S)_PROXY.
source "$(dirname "${BASH_SOURCE[0]}")/../../scripts/egress-env.sh"
egress_init "" || exit 4
PROXY="$(egress_effective_proxy "$PROXY")"
PROXY_FLAG=()
[ -n "$PROXY" ] && PROXY_FLAG=(-x "$PROXY")

echo "[*] API Fuzzing: $TARGET with $WORDLIST"
CMD="ffuf -w $WORDLIST -u ${TARGET}/FUZZ -mc all -fc 404,400 -o $OUT/ffuf-paths.json -of json -t 40 -rate 50"
[ -n "$TOKEN" ] && CMD="$CMD -H 'Authorization: Bearer $TOKEN'"
[ -n "$PROXY" ] && CMD="$CMD -x $PROXY"
eval "$CMD" 2>/dev/null || echo "[-] ffuf failed"

echo "[*] Method fuzzing on discovered paths..."
[ -f "$OUT/ffuf-paths.json" ] && python3 -c "
import sys,json
d=json.load(open('$OUT/ffuf-paths.json'))
for r in d.get('results',[]): print(r.get('url',''))
" 2>/dev/null | head -20 | while IFS= read -r url; do
  ffuf -w wordlists/http-methods.txt -u "$url" -X FUZZ -mc all -fc 405 -s "${PROXY_FLAG[@]}" 2>/dev/null >> "$OUT/methods.txt" || true
done
echo "[*] Done: $OUT/"
