#!/usr/bin/env bash
# =============================================================================
# test-journal.sh — log dev-branch feature-validation observations
# =============================================================================
# Appends structured observations to ~/.grimnir/tests/test-journal.jsonl so we
# accumulate evidence across test engagements ("did feature X fire / help") and
# can make a per-feature merge decision instead of a vibe.
#
# Usage:
#   test-journal.sh add --feature ID [--program NAME] [--fired yes|no]
#                       [--helped yes|no|na] [--severity-impact ...] [--note "..."]
#   test-journal.sh summary [--feature ID]
#   test-journal.sh list [--program NAME]
#
# The journal lives in the host-global store (~/.grimnir/tests/), NOT the repo
# and NOT per-engagement — it spans all the test programs.
# =============================================================================
set -euo pipefail

CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'

JOURNAL_DIR="${GRIMNIR_HOME:-$HOME/.grimnir}/tests"
JOURNAL="$JOURNAL_DIR/test-journal.jsonl"
mkdir -p "$JOURNAL_DIR"

usage() {
    cat <<'HELPEOF'
Usage:
  test-journal.sh add --feature ID [OPTIONS]    Append an observation
  test-journal.sh summary [--feature ID]        Per-feature fired/helped tally
  test-journal.sh list [--program NAME]         Raw entries

add options:
  --feature ID        Feature id (1-6, or a name). Required.
  --program NAME      Program being tested (default: $PROJECT basename or 'unknown')
  --fired yes|no      Did the feature run at all?
  --helped yes|no|na  Did it change the outcome?
  --note "..."        Free-form observation
  --branch NAME       Branch (default: current git branch)

Journal: ~/.grimnir/tests/test-journal.jsonl
HELPEOF
    exit 1
}

[[ $# -eq 0 ]] && usage
CMD="$1"; shift

FEATURE=""; PROGRAM=""; FIRED=""; HELPED=""; NOTE=""; BRANCH=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --feature)  FEATURE="$2"; shift 2 ;;
        --program)  PROGRAM="$2"; shift 2 ;;
        --fired)    FIRED="$2"; shift 2 ;;
        --helped)   HELPED="$2"; shift 2 ;;
        --note)     NOTE="$2"; shift 2 ;;
        --branch)   BRANCH="$2"; shift 2 ;;
        --help|-h)  usage ;;
        *) echo "Unknown option: $1" >&2; usage ;;
    esac
done

# Defaults
# The branch we want is this checkout's, so derive it from where this script lives
# rather than guessing a path. A hardcoded ~/workspace/grimnir logged the wrong branch
# for anyone whose checkout is elsewhere, and silently logged "unknown" on a machine
# with no such directory — a journal entry attributed to the wrong branch is worse than
# no entry, because the merge decision it feeds cannot tell the difference.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ -z "$BRANCH" ]] && BRANCH=$(git -C "$REPO_ROOT" branch --show-current 2>/dev/null || echo "unknown")
[[ -z "$PROGRAM" && -n "${PROJECT_DIR:-}" ]] && PROGRAM=$(basename "$PROJECT_DIR")
[[ -z "$PROGRAM" ]] && PROGRAM="unknown"

case "$CMD" in
    add)
        [[ -z "$FEATURE" ]] && { echo "Error: --feature is required" >&2; exit 1; }
        TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
        jq -cn \
            --arg ts "$TS" --arg feature "$FEATURE" --arg program "$PROGRAM" \
            --arg fired "$FIRED" --arg helped "$HELPED" --arg note "$NOTE" --arg branch "$BRANCH" \
            '{ts:$ts, feature:$feature, program:$program, fired:$fired, helped:$helped, note:$note, branch:$branch}' \
            >> "$JOURNAL"
        printf "${GREEN}[+]${NC} logged: feature=%s program=%s fired=%s helped=%s\n" "$FEATURE" "$PROGRAM" "${FIRED:-?}" "${HELPED:-?}"
        ;;
    summary)
        [[ ! -f "$JOURNAL" ]] && { echo "No journal yet at $JOURNAL"; exit 0; }
        printf "${BOLD}Test journal summary${NC} (%s)\n\n" "$JOURNAL"
        if [[ -n "$FEATURE" ]]; then
            jq -s --arg f "$FEATURE" '[.[] | select(.feature==$f)]' "$JOURNAL"
        else
            jq -rs '
              group_by(.feature)[] |
              "Feature \(.[0].feature): \(length) obs | fired=yes:\([.[]|select(.fired=="yes")]|length) | helped=yes:\([.[]|select(.helped=="yes")]|length) | programs:\([.[].program]|unique|join(","))"
            ' "$JOURNAL"
        fi
        ;;
    list)
        [[ ! -f "$JOURNAL" ]] && { echo "No journal yet at $JOURNAL"; exit 0; }
        if [[ -n "$PROGRAM" && "$PROGRAM" != "unknown" ]]; then
            jq -c --arg p "$PROGRAM" 'select(.program==$p)' "$JOURNAL"
        else
            cat "$JOURNAL"
        fi
        ;;
    *) usage ;;
esac
