#!/usr/bin/env bash
set -euo pipefail
TARGET="${1:?Usage: $0 <target_domain>}"
TS=$(date +%Y%m%d-%H%M%S); OUT="reports/raw/waf-$TS"; mkdir -p "$OUT"

# Egress: wafw00f and the crt.sh curl are HTTP(S) traffic — route them through the program's egress
# proxy (roe.json "proxy" / GRIMNIR_PROXY) or refuse (exit 4). dig is DNS/UDP and cannot ride a
# proxy, so the DNS sections are skipped (never sent direct) when a proxy is configured. No project
# dir here -> egress_init reads GRIMNIR_PROXY from env; curl/wafw00f read the exported proxy vars.
source "$(dirname "${BASH_SOURCE[0]}")/../../scripts/egress-env.sh"
egress_init "" || exit 4

echo "===== WAF Detection: $TARGET ====="

echo "[*] Fingerprinting..."
command -v wafw00f &>/dev/null && wafw00f -a "https://$TARGET" -o "$OUT/wafw00f.json" -f json 2>/dev/null || true

echo "[*] Certificate Transparency..."
curl -s "https://crt.sh/?q=%25.${TARGET}&output=json" 2>/dev/null | python3 -c "
import sys,json
try:
  d=json.load(sys.stdin); names=set()
  for e in d:
    for n in e.get('name_value','').split(chr(10)): names.add(n.strip())
  for n in sorted(names)[:20]: print('  ',n)
except: print('  No CT data')
" 2>/dev/null

# dig is DNS over UDP and cannot ride an HTTP/SOCKS proxy; when the program has an egress proxy
# configured, skip the DNS probes rather than leak them from the host's real address (Rule: a tool
# that cannot be proxied refuses when proxied). egress_refuse_if_proxied returns 0 only when there
# is no proxy, so the DNS block runs only then.
if egress_refuse_if_proxied dig; then
  echo "[*] DNS Records..."
  for t in A AAAA CNAME MX TXT; do
    R=$(dig +short "$TARGET" "$t" 2>/dev/null | head -2)
    [ -n "$R" ] && echo "  $t: $R"
  done

  echo "[*] Mail server origin check..."
  MX=$(dig +short "$TARGET" MX 2>/dev/null | head -1 | awk '{print $2}')
  [ -n "$MX" ] && echo "  MX: $MX ($(dig +short "$MX" A 2>/dev/null | head -1))"
fi

echo "===== WAF Detection Complete: $OUT/ ====="
