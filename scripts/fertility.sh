#!/usr/bin/env bash
# fertility.sh — how fertile is a target's surface? (intelligence-layer module #3)
# The OBJECTIVE half of the dig-vs-pivot call: is this program actually yielding bugs?
# Reads an operator-local fertility cache (populated by a platform puller) and normalizes
# it to a band. Generic + cache-driven; degrades to "unknown" with no data.
#
# Asymmetry by design: bands push only toward MORE digging (hot/warm) or no-change
# (unknown). Absence of disclosure is NOT evidence a surface is dead, so this never makes
# us pivot EARLIER. (A "cold" band needs live-activity evidence — a later increment.)
#
# Usage:
#   scripts/fertility.sh band  <handle>   # hot | warm | unknown   (for pivot modulation)
#   scripts/fertility.sh score <handle>   # normalized JSON        (for the Brief)
#   scripts/fertility.sh show  <handle>   # one-line human summary
#
# Cache:      ${GRIMNIR_FERTILITY_DIR:-~/.grimnir/fertility}/<handle>.json
# Thresholds: GRIMNIR_FERTILITY_HOT (default 15), GRIMNIR_FERTILITY_WARM (default 4)
set -euo pipefail
FDIR="${GRIMNIR_FERTILITY_DIR:-$HOME/.grimnir/fertility}"
HOT="${GRIMNIR_FERTILITY_HOT:-15}"; WARM="${GRIMNIR_FERTILITY_WARM:-4}"
CMD="${1:-}"; HANDLE="${2:-}"
[[ -z "$CMD" || -z "$HANDLE" ]] && { echo "usage: $(basename "$0") band|score|show <handle>" >&2; exit 2; }
F="$FDIR/$HANDLE.json"

_band() {  # echo just the band word: hot | warm | unknown
  [[ -f "$F" ]] || { echo unknown; return; }
  jq -r --argjson hot "$HOT" --argjson warm "$WARM" '
    ((.disclosed_count // 0)) as $c | ((.recent_activity // 0)) as $r |
    if ($c >= $hot or $r >= $hot) then "hot"
    elif ($c >= $warm or $r >= $warm) then "warm"
    else "unknown" end' "$F" 2>/dev/null || echo unknown
}

case "$CMD" in
  band) _band ;;
  score)
    b="$(_band)"
    if [[ -f "$F" ]]; then
      jq --arg band "$b" '. + {band:$band}' "$F" 2>/dev/null || jq -n --arg h "$HANDLE" '{handle:$h,band:"unknown"}'
    else
      jq -n --arg h "$HANDLE" '{handle:$h, band:"unknown", note:"no fertility data"}'
    fi ;;
  show)
    if [[ -f "$F" ]]; then
      b="$(_band)"
      jq -r --arg band "$b" '"fertility: \($band) | disclosed \(.disclosed_count // 0) (avg $\(.disclosed_avg_bounty // 0)) | \(.source // "?") as of \(.as_of // "?")"' "$F" 2>/dev/null || echo "fertility: $b"
      jq -r '(.hot_areas // []) | if length>0 then "hot areas: " + ([.[]|"\(.area)(\(.count))"]|join(", ")) else empty end' "$F" 2>/dev/null || true
    else
      echo "fertility: unknown (no data for $HANDLE — run the puller)"
    fi ;;
  *) echo "usage: $(basename "$0") band|score|show <handle>" >&2; exit 2 ;;
esac
