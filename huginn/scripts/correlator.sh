#!/bin/bash
set -euo pipefail

# HUGINN Intel Correlator (Background Mode)
# Watches specialist agent output directories and auto-generates
# cross-agent intel entries from new recon/findings files.
#
# Designed to run in the background alongside specialist agents.

usage() {
    cat <<'EOF'
Usage: huginn/scripts/correlator.sh [OPTIONS]

Options:
  --project-dir DIR      Absolute path to project directory (required)
  --interval SECS        Poll interval in seconds (default: 30)
  --once                 Run once and exit (don't loop)
  -h, --help             Show this help

Watches:
  $PROJECT_DIR/specter/recon/    New recon files from Specter
  $PROJECT_DIR/artemis/recon/    New recon files from ARTEMIS
  $PROJECT_DIR/hunter/recon/     New recon files from Hunter
  $PROJECT_DIR/*/findings/       New findings from any agent

Writes:
  $PROJECT_DIR/intel.jsonl       Cross-agent intel entries
EOF
    exit 0
}

PROJECT_DIR=""
INTERVAL=30
ONCE=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --project-dir) PROJECT_DIR="$2"; shift 2 ;;
        --interval) INTERVAL="$2"; shift 2 ;;
        --once) ONCE=true; shift ;;
        -h|--help) usage ;;
        *) echo "Unknown: $1" >&2; exit 1 ;;
    esac
done

[[ -z "$PROJECT_DIR" ]] && { echo "Error: --project-dir required" >&2; exit 1; }

MARKER_FILE="$PROJECT_DIR/.huginn-correlator-marker"
GRIMNIR_DIR="$(cd "$(dirname "$0")/../.." && pwd)"

# Initialize marker with current timestamp
[[ ! -f "$MARKER_FILE" ]] && date +%s > "$MARKER_FILE"

correlate_once() {
    local LAST_RUN
    LAST_RUN=$(cat "$MARKER_FILE" 2>/dev/null || echo 0)
    local NEW_FILES=0

    # Find files newer than last run across all agent directories
    for agent_dir in specter artemis hunter; do
        RECON_DIR="$PROJECT_DIR/$agent_dir/recon"
        FINDINGS_DIR="$PROJECT_DIR/$agent_dir/findings"

        # Check recon files
        if [[ -d "$RECON_DIR" ]]; then
            while IFS= read -r file; do
                [[ -z "$file" ]] && continue
                BASENAME=$(basename "$file")
                AGENT="$agent_dir"

                # Skip if already processed (check by filename pattern in intel)
                if grep -q "$BASENAME" "$PROJECT_DIR/intel.jsonl" 2>/dev/null; then
                    continue
                fi

                # Auto-generate intel based on file content
                case "$BASENAME" in
                    *endpoint* | *api* | *routes*)
                        bash "$GRIMNIR_DIR/scripts/intel.sh" add \
                            --project-dir "$PROJECT_DIR" \
                            --agent huginn \
                            --type note --confidence medium \
                            --content "New recon data from $AGENT: $BASENAME" \
                            --context "auto-correlated" \
                            --tag "cross-agent" 2>/dev/null || true
                        NEW_FILES=$((NEW_FILES + 1))
                        ;;
                    *finding* | *vuln*)
                        # Route findings to other agents for awareness
                        for other in specter artemis hunter; do
                            [[ "$other" == "$agent_dir" ]] && continue
                            # Only route if the file contains something relevant
                            bash "$GRIMNIR_DIR/scripts/intel.sh" add \
                                --project-dir "$PROJECT_DIR" \
                                --agent huginn \
                                --type note --confidence medium \
                                --content "$AGENT produced finding: $BASENAME — check for cross-domain relevance" \
                                --context "auto-correlated" \
                                --tag "needs-$other" 2>/dev/null || true
                        done
                        NEW_FILES=$((NEW_FILES + 1))
                        ;;
                esac
            done < <(find "$RECON_DIR" -type f -newer "$MARKER_FILE" 2>/dev/null)
        fi

        # Check findings
        if [[ -d "$FINDINGS_DIR" ]]; then
            while IFS= read -r file; do
                [[ -z "$file" ]] && continue
                [[ "$file" != *.json ]] && continue
                BASENAME=$(basename "$file")

                if grep -q "$BASENAME" "$PROJECT_DIR/intel.jsonl" 2>/dev/null; then
                    continue
                fi

                # Parse finding severity and title
                TITLE=$(jq -r '.title // "Unknown"' "$file" 2>/dev/null || echo "Unknown")
                SEVERITY=$(jq -r '.severity // "unknown"' "$file" 2>/dev/null || echo "unknown")

                # High-value findings get routed to all other agents
                if [[ "$SEVERITY" == "critical" || "$SEVERITY" == "high" ]]; then
                    for other in specter artemis hunter; do
                        [[ "$other" == "$agent_dir" ]] && continue
                        bash "$GRIMNIR_DIR/scripts/intel.sh" add \
                            --project-dir "$PROJECT_DIR" \
                            --agent huginn \
                            --type vulnerability_hint --confidence high \
                            --hint "$agent_dir found $SEVERITY: $TITLE" \
                            --tag "needs-$other" --tag "high-value" 2>/dev/null || true
                    done
                    NEW_FILES=$((NEW_FILES + 1))
                fi
            done < <(find "$FINDINGS_DIR" -type f -newer "$MARKER_FILE" 2>/dev/null)
        fi
    done

    # Update marker
    date +%s > "$MARKER_FILE"

    [[ $NEW_FILES -gt 0 ]] && echo "[$(date +%H:%M:%S)] Correlated $NEW_FILES new items"
}

if [[ "$ONCE" == "true" ]]; then
    correlate_once
    exit 0
fi

echo "HUGINN Correlator started (polling every ${INTERVAL}s)"
echo "Project: $PROJECT_DIR"
echo "Press Ctrl+C to stop"

while true; do
    correlate_once
    sleep "$INTERVAL"
done
