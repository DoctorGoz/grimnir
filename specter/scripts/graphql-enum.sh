#!/usr/bin/env bash
set -euo pipefail
EP="${1:?Usage: $0 <graphql_endpoint> [auth_token]}"
TOKEN="${2:-}"
TS=$(date +%Y%m%d-%H%M%S); OUT="reports/raw/graphql-$TS"; mkdir -p "$OUT"
AH=""; [ -n "$TOKEN" ] && AH="-H 'Authorization: Bearer $TOKEN'"

# Egress: every probe here hits the target GraphQL endpoint — route through the program's egress
# proxy (roe.json "proxy" / GRIMNIR_PROXY, exported by the calling harness) or refuse (exit 4). curl and
# graphw00f read the exported ALL_PROXY/HTTP(S)_PROXY; graphql-probe.py (a child) reads GRIMNIR_PROXY
# itself. No project dir here -> env only.
source "$(dirname "${BASH_SOURCE[0]}")/../../scripts/egress-env.sh"
egress_init "" || exit 4

echo "===== GraphQL Enumeration: $EP ====="

echo "[*] Confirming GraphQL..."
R=$(eval curl -s -X POST "$EP" -H "Content-Type: application/json" $AH -d "'{\"query\":\"{__typename}\"}'" 2>/dev/null)
echo "$R" | grep -q "__typename" && echo "  [+] Confirmed!" || { echo "  [-] Not GraphQL"; exit 1; }

echo "[*] Fingerprinting..."
command -v graphw00f &>/dev/null && graphw00f -t "$EP" 2>/dev/null | tee "$OUT/fingerprint.txt" || true

echo "[*] Introspection..."
INTRO='{"query":"{ __schema { types { name fields { name args { name type { name } } } } } }"}'
eval curl -s -X POST "$EP" -H "Content-Type: application/json" $AH -d "'$INTRO'" 2>/dev/null \
  | python3 -m json.tool > "$OUT/introspection.json" 2>/dev/null
if [ -s "$OUT/introspection.json" ] && grep -q "fields" "$OUT/introspection.json"; then
  echo "  [+] Introspection ENABLED"
else
  echo "  [-] Introspection disabled — recovering ROOT schema via the field-suggestion oracle..."
  # our own bounded, paced, read-only clairvoyance replacement (no external dep).
  # Light root-only pass here (RoE-friendly); run the deep descent deliberately (below).
  python3 "$(dirname "$0")/graphql-probe.py" "$EP" ${TOKEN:+--token "$TOKEN"} \
    --depth 1 --max-requests 120 --delay 0.15 --out "$OUT/probe" 2>/dev/null \
    || echo "  [-] Schema recovery produced nothing (suggestions likely off); see graphql-probe.py --help"
  echo "  [i] Deep recovery (descends into object types, more requests — mind program RoE):"
  echo "      python3 $(dirname "$0")/graphql-probe.py '$EP'${TOKEN:+ --token '$TOKEN'} --depth 2 --delay 0.3"
fi

echo "[*] Unauthenticated access..."
curl -s -X POST "$EP" -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name } } }"}' 2>/dev/null | grep -q "name" \
  && echo "  [+] FINDING: Unauth introspection!" || echo "  [-] Auth required"

echo "[*] Batch testing..."
curl -s -X POST "$EP" -H "Content-Type: application/json" $AH \
  -d '[{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"}]' 2>/dev/null \
  | grep -c "__typename" | xargs -I{} echo "  Batch responses: {}"

echo "===== GraphQL Enum Complete: $OUT/ ====="
