#!/usr/bin/env bash
# new-finding.sh — Create an ARTEMIS finding.
#
# Thin shim over the repo-root scripts/finding.sh. It exists because ARTEMIS's
# slash commands and spray scripts all call `new-finding.sh "Title" "Category"
# "Severity"`, and that call shape is baked into a dozen places. Keep the shape;
# delegate the work.
#
# Usage: new-finding.sh <title> <owasp_category> <severity> [DETAIL...]
#        new-finding.sh <project_dir> <title> <owasp_category> <severity> [DETAIL...]
#   DETAIL: --description TEXT | --impact TEXT | --target T | --cwe CWE, passed to finding.sh.
#   Nothing else passes: a caller (an unattended specialist among them) cannot set the status or
#   the validation state here.
# Example: new-finding.sh "System Prompt Extraction via Translation" LLM07 High
#
# PROJECT_DIR comes from the GRIMNIR handoff payload; pass it explicitly (4-arg
# form) only when running standalone.
#
# History: this used to be a parallel finding implementation that minted legacy
# FINDING-NNN ids into its own directory layout and marked every new finding
# "Confirmed" in the index. That is three violations of the repo-root CLAUDE.md
# at once -- ids are AGT-NNN and assigned by finding.sh, findings live under
# $PROJECT_DIR/<agent>/findings/, and findings are born `theoretical`. It also
# required 4 args while every documented call site passed 3, so it failed with
# "Missing severity" everywhere it was invoked.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
FINDING_SH="$REPO_ROOT/scripts/finding.sh"

if [[ ! -x "$FINDING_SH" && ! -f "$FINDING_SH" ]]; then
    echo "ERROR: cannot find scripts/finding.sh at $FINDING_SH" >&2
    exit 1
fi

# Both call shapes. A first arg that names an existing directory (or looks like a
# path) is the project dir; otherwise it is the title and PROJECT_DIR is expected
# in the environment.
# Split the positional arguments from the DETAIL flags that follow them.
POS=()
while [[ $# -gt 0 && "$1" != --* ]]; do POS+=("$1"); shift; done
DETAIL=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --description|--impact|--target|--cwe)
            [[ $# -ge 2 ]] || { echo "ERROR: $1 needs a value" >&2; exit 1; }
            DETAIL+=("$1" "$2"); shift 2 ;;
        *) echo "ERROR: $1 is not accepted here (only --description, --impact, --target, --cwe)" >&2
           exit 1 ;;
    esac
done
set -- "${POS[@]}"

if [[ $# -ge 4 ]] || { [[ $# -eq 3 ]] && [[ -d "${1:-}" || "${1:-}" == /* || "${1:-}" == ./* ]]; }; then
    PROJECT_DIR="$1"; shift
fi

TITLE="${1:?Usage: $0 [project_dir] <title> <owasp_category> <severity> [DETAIL...]}"
OWASP_CAT="${2:?Missing OWASP category (e.g., LLM01, ASI03, MCP05)}"
SEVERITY_IN="${3:?Missing severity (Critical/High/Medium/Low/Informational)}"

if [[ -z "${PROJECT_DIR:-}" ]]; then
    echo "ERROR: PROJECT_DIR is not set. Pass it as the first argument or export it." >&2
    echo "       It must be the absolute engagement path from the GRIMNIR handoff," >&2
    echo "       e.g. \$HOME/workspace/acme-corp" >&2
    exit 1
fi

# finding.sh takes lowercase; "Informational" is spelled "info" there.
SEVERITY="$(printf '%s' "$SEVERITY_IN" | tr '[:upper:]' '[:lower:]')"
[[ "$SEVERITY" == "informational" ]] && SEVERITY="info"
case "$SEVERITY" in
    critical|high|medium|low|info) ;;
    *) echo "ERROR: Invalid severity '$SEVERITY_IN'. Use Critical/High/Medium/Low/Informational" >&2
       exit 1 ;;
esac

# Born `theoretical` -- finding.sh's default, stated here because this script
# used to do the opposite. Promote with scripts/validate-finding.sh once the
# class-appropriate proof exists.
exec bash "$FINDING_SH" \
    --project-dir "$PROJECT_DIR" \
    --agent artemis \
    --severity "$SEVERITY" \
    --title "$TITLE" \
    --category "$OWASP_CAT" \
    "${DETAIL[@]}"
