#!/usr/bin/env bash
set -euo pipefail
TARGET="${1:?Usage: $0 <target_url> [auth_token]}"
TOKEN="${2:-}"
TS=$(date +%Y%m%d-%H%M%S)
OUT="reports/raw/recon-${TS}"
mkdir -p "$OUT"

# Egress: every tool here (wafw00f, katana, linkfinder, secretfinder, curl, kr, ffuf, arjun) reaches
# the target — route through the program's egress proxy (roe.json "proxy" / GRIMNIR_PROXY, exported
# by the calling harness) or refuse (exit 4). curl reads ALL_PROXY; the Go tools (katana, kr, ffuf) and
# the Python tools read HTTP(S)_PROXY — all exported by egress_init. No project dir here -> env only.
source "$(dirname "${BASH_SOURCE[0]}")/../../scripts/egress-env.sh"
egress_init "" || exit 4

echo "===== Specter Recon Pipeline ====="
echo "Target: $TARGET | Output: $OUT"

echo "[*] Phase 1: WAF Detection"
wafw00f -a "$TARGET" -o "$OUT/waf.json" -f json 2>/dev/null || echo "[-] wafw00f unavailable"

echo "[*] Phase 2: Crawling"
if command -v katana &>/dev/null; then
  katana -u "$TARGET" -d 5 -jc -silent -f qurl 2>/dev/null | sort -u > "$OUT/endpoints.txt"
  katana -u "$TARGET" -d 3 -jc -silent 2>/dev/null | grep -iE '\.js([?#]|$)' | sort -u > "$OUT/js_files.txt"
  echo "  Endpoints: $(wc -l < "$OUT/endpoints.txt") | JS: $(wc -l < "$OUT/js_files.txt")"
fi

echo "[*] Phase 3: JS Analysis"
touch "$OUT/js_endpoints.txt" "$OUT/js_secrets.txt"
[ -s "$OUT/js_files.txt" ] && while IFS= read -r u; do
  linkfinder -i "$u" -o cli 2>/dev/null >> "$OUT/js_endpoints.txt" || true
  secretfinder -i "$u" -o cli 2>/dev/null >> "$OUT/js_secrets.txt" || true
done < "$OUT/js_files.txt"

echo "[*] Phase 4: API Doc Discovery"
for p in /swagger.json /openapi.json /api-docs /v2/api-docs /v3/api-docs /.well-known/openid-configuration /graphql /graphiql /playground /actuator /health /info; do
  S=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}${p}" 2>/dev/null || echo 000)
  [ "$S" = "200" ] || [ "$S" = "301" ] && echo "  [+] ${TARGET}${p} ($S)" | tee -a "$OUT/api_docs.txt"
done

echo "[*] Phase 5: Route Brute-Force"
command -v kr &>/dev/null && kr scan "$TARGET" -A=apiroutes-210328:20000 -x 5 -j 100 \
  --fail-status-codes 400,401,404,403,501,502,426,411 > "$OUT/kiterunner.txt" 2>/dev/null || true
[ -f wordlists/api-endpoints.txt ] && command -v ffuf &>/dev/null && \
  ffuf -w wordlists/api-endpoints.txt -u "${TARGET}/FUZZ" -mc all -fc 404 -o "$OUT/ffuf.json" -of json -s 2>/dev/null || true

echo "[*] Phase 6: Parameter Discovery"
command -v arjun &>/dev/null && [ -s "$OUT/endpoints.txt" ] && \
  head -20 "$OUT/endpoints.txt" | arjun -i /dev/stdin -m JSON -oJ "$OUT/params.json" -t 5 2>/dev/null || true

echo "===== Recon Complete: $OUT ====="
