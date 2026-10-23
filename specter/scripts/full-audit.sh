#!/usr/bin/env bash
set -euo pipefail
TARGET="${1:?Usage: $0 <target_url> [auth_token]}"
TOKEN="${2:-}"
TS=$(date +%Y%m%d-%H%M%S); OUT="reports/audit-$TS"; mkdir -p "$OUT"

# Egress: full-audit's own curl (GraphQL detection) and nuclei reach the target — route through the
# program's egress proxy (roe.json "proxy" / GRIMNIR_PROXY) or refuse (exit 4). curl reads ALL_PROXY,
# nuclei reads HTTP(S)_PROXY, both exported here; the child scripts (recon-pipeline, waf-detect,
# graphql-enum) re-apply the same contract themselves. No project dir here -> env only.
source "$(dirname "${BASH_SOURCE[0]}")/../../scripts/egress-env.sh"
egress_init "" || exit 4

echo "================================================================"
echo " Specter — Full OWASP API Top 10 Audit"
echo " Target: $TARGET | Started: $(date)"
echo "================================================================"

echo "==== PHASE 1: RECONNAISSANCE ===="
./scripts/recon-pipeline.sh "$TARGET" "$TOKEN" 2>&1 | tee "$OUT/phase1-recon.log"

echo "==== PHASE 2: WAF DETECTION ===="
DOMAIN=$(echo "$TARGET" | sed -E 's|https?://||;s|/.*||')
./scripts/waf-detect.sh "$DOMAIN" 2>&1 | tee "$OUT/phase2-waf.log"

echo "==== PHASE 3: NUCLEI SCAN ===="
command -v nuclei &>/dev/null && {
  CMD="nuclei -u $TARGET -tags api,cve -s critical,high -o $OUT/nuclei.json -json"
  [ -n "$TOKEN" ] && CMD="$CMD -H 'Authorization: Bearer $TOKEN'"
  eval "$CMD" 2>/dev/null || true
}

echo "==== PHASE 4: GRAPHQL DETECTION ===="
for gp in /graphql /graphiql /api/graphql /v1/graphql /query; do
  R=$(curl -s -X POST "${TARGET}${gp}" -H "Content-Type: application/json" -d '{"query":"{__typename}"}' 2>/dev/null)
  echo "$R" | grep -q "__typename" 2>/dev/null && {
    echo "[+] GraphQL at: ${TARGET}${gp}"
    ./scripts/graphql-enum.sh "${TARGET}${gp}" "$TOKEN" 2>&1 | tee "$OUT/phase4-graphql.log"
    break
  }
done

echo "================================================================"
echo " Automated Phases Complete. For manual testing run in Claude Code:"
echo "   /test-auth $TARGET"
echo "   /test-bola <endpoint>"
echo "   /test-jwt <token>"
echo " Output: $OUT/ | Finished: $(date)"
echo "================================================================"
