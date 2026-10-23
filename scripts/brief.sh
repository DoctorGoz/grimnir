#!/usr/bin/env bash
# brief.sh — Engagement Intelligence Brief (intelligence-layer synthesizer, module #4).
# At /engage, fuses the feeders into one "spend here / skip there / gated lanes /
# focus-areas-first / prior-methodology" prior, so effort is allocated BEFORE testing.
# Feeders: reachability.json (#1), the lessons loader (match/negative/reopen-radar),
# project.md Testing Priorities (focus areas). history/fertility/armory are stubbed and
# fill in as those modules come online. Degrades gracefully when a feeder is absent.
#
# Usage:
#   scripts/brief.sh init --project-dir DIR [--handle H] [--stack S] [--force]
#   scripts/brief.sh show --project-dir DIR
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LESSONS_QUERY="${GRIMNIR_LESSONS_QUERY:-$HOME/.grimnir/lessons/lessons-query.py}"

CMD="${1:-}"; shift || true
PROJECT_DIR=""; HANDLE=""; STACK=""; FORCE=false
while [[ $# -gt 0 ]]; do case "$1" in
  --project-dir) PROJECT_DIR="$2"; shift 2 ;;
  --handle)      HANDLE="$2"; shift 2 ;;
  --stack)       STACK="$2"; shift 2 ;;
  --force)       FORCE=true; shift ;;
  -h|--help)     sed -n '2,16p' "$0"; exit 0 ;;
  *) echo "unknown arg: $1" >&2; exit 2 ;;
esac; done
[[ -z "$PROJECT_DIR" ]] && { echo "Error: --project-dir required" >&2; exit 1; }
[[ "$PROJECT_DIR" != /* ]] && { echo "Error: --project-dir must be absolute" >&2; exit 1; }

PROJECT="$(basename "$PROJECT_DIR")"
INTAKE="$PROJECT_DIR/project.md"
REACH="$PROJECT_DIR/reachability.json"
BRIEF="$PROJECT_DIR/brief.md"
Q="${HANDLE:-${STACK:-$PROJECT}}"

case "$CMD" in
  show) [[ -f "$BRIEF" ]] && { cat "$BRIEF"; exit 0; }
        echo "no brief.md at $PROJECT_DIR — run: $0 init --project-dir $PROJECT_DIR" >&2; exit 1 ;;
  init) ;;
  *) echo "usage: $0 init|show --project-dir DIR" >&2; exit 2 ;;
esac
[[ -f "$BRIEF" && "$FORCE" != true ]] && { echo "brief.md exists (use --force to regenerate)" >&2; exit 0; }

lessons() {
  [[ -f "$LESSONS_QUERY" ]] && command -v python3 >/dev/null 2>&1 || return 0
  python3 "$LESSONS_QUERY" "$@" 2>/dev/null || true
}
FERT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/fertility.sh"

NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
{
  echo "# Engagement Intelligence Brief — $PROJECT"
  echo
  echo "_Generated $NOW by brief.sh. The funnel-front prior: allocate effort BEFORE testing._"
  echo
  echo "## Synthesis (complete at /engage — the orchestrator call)"
  echo
  echo "- **Spend here:** [reachable + focus-area lanes — from the sections below]"
  echo "- **Skip / deprioritize:** [gated lanes + negative-pattern matches below]"
  echo "- **Gated (unlock to reach):** [from Reachability]"
  echo

  echo "## Reachability (LANE gate — #1)"
  echo
  if [[ -f "$REACH" ]]; then
    echo "Gated lanes (do NOT plan as primary):"
    jq -r '.lanes[] | select(.verdict=="GATED") | "- \(.lane) [\(.gates|join(","))] — \(.note)"' "$REACH" 2>/dev/null || true
    echo
    echo "Reachable lanes:"
    jq -r '.lanes[] | select(.verdict=="REACHABLE") | "- \(.lane)"' "$REACH" 2>/dev/null || true
    echo
    if [[ "$(jq -r '.stack_known_gates // [] | length' "$REACH" 2>/dev/null || echo 0)" != "0" ]]; then
      echo "Stack-known gates (from lessons):"
      jq -r '.stack_known_gates[] | "- " + .' "$REACH" 2>/dev/null || true
      echo
    fi
  else
    echo "_No reachability.json — run \`scripts/reachability.sh init --project-dir $PROJECT_DIR\` first._"
    echo
  fi

  echo "## Prior methodology + negatives (lessons 2nd-brain)"
  echo
  _m="$(lessons match "$Q")"
  if [[ -n "$_m" ]]; then printf '```\n%s\n```\n' "$_m"; else echo "_No lessons match for '$Q'._"; fi
  echo
  _neg="$(lessons negative "$Q")"
  if [[ -n "$_neg" ]] && ! printf '%s' "$_neg" | grep -qi 'no .*match'; then
    echo "Negative-pattern warnings (resembles a low-yield prior):"; printf '```\n%s\n```\n\n' "$_neg"
  fi
  _rr="$(lessons reopen-radar)"
  if [[ -n "$_rr" ]]; then
    _hit="$(printf '%s\n' "$_rr" | grep -i "$PROJECT" || true)"
    [[ -n "$_hit" ]] && { echo "Reopen-radar (this looks shelved-warm — unlock condition):"; printf '%s\n' "$_hit" | sed 's/^/- /'; echo; }
  fi

  echo "## Focus areas (lead here — Rule 21)"
  echo
  if [[ -f "$INTAKE" ]]; then
    _fa="$(awk '/^##[[:space:]]+Testing Priorities/{f=1;next} /^##[[:space:]]/{f=0} f' "$INTAKE" | sed '/^[[:space:]]*$/d' | head -20)"
    if [[ -n "$_fa" ]]; then printf '%s\n' "$_fa" | sed 's/^/> /'; else echo "_Testing Priorities section empty — fill it in project.md._"; fi
  else
    echo "_No project.md — declare Testing Priorities in the intake._"
  fi
  echo

  echo "## Fertility (is this surface yielding? — #3)"
  echo
  if [[ -f "$FERT" ]]; then
    _fs="$(bash "$FERT" show "$Q" 2>/dev/null || true)"
    [[ -n "$_fs" ]] && printf '%s\n' "$_fs" | sed 's/^/- /'
    case "$(bash "$FERT" band "$Q" 2>/dev/null || echo unknown)" in
      hot)  echo "- Implication: HOT — negatives here mean 'not found yet', not 'dead'. Dig; narrow your instance (Rule 20). Pivot threshold is auto-raised." ;;
      warm) echo "- Implication: WARM — some yield here; persist on the focus areas." ;;
      *)    echo "- Implication: UNKNOWN — no disclosure signal (NOT evidence of dead). Lean on mechanism + anomaly judgment (dig-vs-pivot rubric)." ;;
    esac
  else
    echo "_fertility.sh not found — skipping._"
  fi
  echo
  echo "## Stubbed feeders (wire as modules land)"
  echo "- History (have we / others been here?): pending \`history.sh\` (ROADMAP-cred-vault-history)."
  echo "- Armory (stack CVE / PoC availability): pending ROADMAP-armory.md."
} > "$BRIEF"

echo "brief: wrote $BRIEF"
exit 0
