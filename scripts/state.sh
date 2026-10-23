#!/bin/bash
set -euo pipefail

# Grimnir Engagement State Manager
# Tracks engagement lifecycle and per-agent progress

# Source the event hooks (optional — degrades gracefully)
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -f "$REPO/scripts/event-emitter.sh" ]]; then
    source "$REPO/scripts/event-emitter.sh"
fi
declare -F _emit >/dev/null 2>&1 || _emit() { :; }

usage() {
    cat <<'EOF'
Usage: state.sh COMMAND [OPTIONS]

Commands:
  init        Initialize state file for a new engagement
  update      Update agent phase/status/progress
  checkpoint  Save checkpoint data for an agent
  get         Read current state (full JSON or filtered)
  summary     Print human-readable status summary

init:
  --project-dir DIR        Absolute path (required)
  --engagement-id ID       e.g. ENG-20260310-ACME (required)
  --project-name NAME      Short dir slug (required)
  --handle HANDLE          Bug-bounty platform program handle (e.g. acme-corp-bbp).
                           BUG-BOUNTY ONLY — leave empty for pentest/direct targets.
                           This is the canonical id the sentinel/allowlist key on;
                           capturing it here ends the handle-vs-dir-slug mismatch.
  --platform PLATFORM      h1|intigriti|bugcrowd|ywh (bug-bounty only; empty otherwise)
  --target TARGET          Primary target URL/IP
  --target-type TYPE       Classification type
  --agents AGENT[,AGENT]   Comma-separated list (e.g. specter,artemis)

update:
  --project-dir DIR        Absolute path (required)
  --agent AGENT            huginn | specter | artemis | hunter | nimbus | nomad (required)
  --phase PHASE            recon|enumerate|map|test|exploit|report|completed
  --status STATUS          not_started|in_progress|blocked|completed
  --progress FLOAT         0.0 to 1.0
  --findings-count N       Current finding count
  --critical-count N       Current critical count
  --high-count N           Current high count
  --next-action TEXT       Next step description
  --blocker TEXT           Add a blocker (repeatable)
  --reachability VALUE     Engagement reachability: open|account-gated|geo-gated|sandbox|unknown
                           (stored and propagated to event sinks on change)
  --note TEXT              Note for phase_history

checkpoint:
  --project-dir DIR        Absolute path (required)
  --agent AGENT            (required)
  --last-action TEXT       Last completed action
  --completed-test CAT     Add to completed tests (repeatable)
  --pending-test CAT       Add to pending tests (repeatable)
  --target TARGET          Add to discovered targets (repeatable)

get:
  --project-dir DIR        Absolute path (required)
  --agent AGENT            Filter to specific agent
  --field FIELD            jq field path (e.g. .agents.specter.phase)

summary:
  --project-dir DIR        Absolute path (required)
EOF
    exit 1
}

NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# ── Parse command ──
[[ $# -lt 1 ]] && usage
COMMAND="$1"; shift

# ── Parse options ──
PROJECT_DIR=""
ENGAGEMENT_ID=""
PROJECT_NAME=""
HANDLE=""
PLATFORM=""
TARGET=""
TARGET_TYPE=""
AGENTS_CSV=""
AGENT=""
PHASE=""
STATUS=""
PROGRESS=""
FINDINGS_COUNT=""
CRITICAL_COUNT=""
HIGH_COUNT=""
NEXT_ACTION=""
BLOCKERS=()
REACHABILITY=""
NOTE=""
LAST_ACTION=""
COMPLETED_TESTS=()
PENDING_TESTS=()
DISCOVERED_TARGETS=()
FIELD=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --project-dir)      PROJECT_DIR="$2"; shift 2 ;;
        --engagement-id)    ENGAGEMENT_ID="$2"; shift 2 ;;
        --project-name)     PROJECT_NAME="$2"; shift 2 ;;
        --handle)           HANDLE="$2"; shift 2 ;;
        --platform)         PLATFORM="$2"; shift 2 ;;
        --target)           TARGET="$2"; shift 2 ;;
        --target-type)      TARGET_TYPE="$2"; shift 2 ;;
        --agents)           AGENTS_CSV="$2"; shift 2 ;;
        --agent)            AGENT="$2"; shift 2 ;;
        --phase)            PHASE="$2"; shift 2 ;;
        --status)           STATUS="$2"; shift 2 ;;
        --progress)         PROGRESS="$2"; shift 2 ;;
        --findings-count)   FINDINGS_COUNT="$2"; shift 2 ;;
        --critical-count)   CRITICAL_COUNT="$2"; shift 2 ;;
        --high-count)       HIGH_COUNT="$2"; shift 2 ;;
        --next-action)      NEXT_ACTION="$2"; shift 2 ;;
        --blocker)          BLOCKERS+=("$2"); shift 2 ;;
        --reachability)     REACHABILITY="$2"; shift 2 ;;
        --note)             NOTE="$2"; shift 2 ;;
        --last-action)      LAST_ACTION="$2"; shift 2 ;;
        --completed-test)   COMPLETED_TESTS+=("$2"); shift 2 ;;
        --pending-test)     PENDING_TESTS+=("$2"); shift 2 ;;
        --field)            FIELD="$2"; shift 2 ;;
        --help|-h)          usage ;;
        *)                  echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

[[ -z "$PROJECT_DIR" ]] && { echo "Error: --project-dir is required" >&2; exit 1; }
[[ "$PROJECT_DIR" != /* ]] && { echo "Error: --project-dir must be an absolute path" >&2; exit 1; }

STATE_FILE="$PROJECT_DIR/state.json"

json_array() {
    local arr=("$@")
    if [[ ${#arr[@]} -eq 0 ]]; then echo "[]"; return; fi
    printf '%s\n' "${arr[@]}" | jq -R . | jq -s .
}

# ── Derive overall status from agent statuses ──
derive_overall_status() {
    local state="$1"
    local assigned
    assigned=$(echo "$state" | jq -r '.assigned_agents // [] | .[]')
    [[ -z "$assigned" ]] && { echo "initializing"; return; }

    local any_active=false
    local any_blocked=false
    local all_completed=true
    local all_not_started=true

    for a in $assigned; do
        local astatus
        astatus=$(echo "$state" | jq -r ".agents.$a.status // \"not_started\"")
        [[ "$astatus" == "in_progress" ]] && any_active=true
        [[ "$astatus" == "blocked" ]] && any_blocked=true
        [[ "$astatus" != "completed" ]] && all_completed=false
        [[ "$astatus" != "not_started" ]] && all_not_started=false
    done

    local report_done
    report_done=$(echo "$state" | jq -r '.report_generated // false')

    # Precedence: finished > reporting > actively working > stalled-on-blocker > untouched.
    # A blocked engagement (something blocked, nothing actively in_progress) is its own overall
    # status -- previously it derived to "in_progress", so a parked engagement read as active
    # and a dashboard could never show it blocked.
    if [[ "$all_completed" == true && "$report_done" == "true" ]]; then
        echo "completed"
    elif [[ "$all_completed" == true ]]; then
        echo "reporting"
    elif [[ "$any_active" == true ]]; then
        echo "in_progress"
    elif [[ "$any_blocked" == true ]]; then
        echo "blocked"
    elif [[ "$all_not_started" == true ]]; then
        echo "initializing"
    else
        echo "in_progress"
    fi
}

case "$COMMAND" in
    init)
        [[ -z "$ENGAGEMENT_ID" ]] && { echo "Error: --engagement-id required" >&2; exit 1; }
        [[ -z "$PROJECT_NAME" ]] && { echo "Error: --project-name required" >&2; exit 1; }
        [[ -f "$STATE_FILE" ]] && { echo "Error: state.json already exists at $STATE_FILE. Use 'update' instead." >&2; exit 1; }

        mkdir -p "$PROJECT_DIR"

        # Build assigned agents array
        ASSIGNED="[]"
        if [[ -n "$AGENTS_CSV" ]]; then
            ASSIGNED=$(echo "$AGENTS_CSV" | tr ',' '\n' | jq -R . | jq -s .)
        fi

        # Build initial agent statuses
        AGENTS_OBJ='{}'
        for a in huginn specter artemis hunter nimbus nomad; do
            AGENTS_OBJ=$(echo "$AGENTS_OBJ" | jq --arg a "$a" '.[$a] = {"phase": "not_started", "status": "not_started", "progress": 0.0, "findings_count": 0, "critical_count": 0, "high_count": 0}')
        done

        # Build target object
        TARGET_OBJ='{}'
        [[ -n "$TARGET" ]] && TARGET_OBJ=$(echo "$TARGET_OBJ" | jq --arg v "$TARGET" '.primary = $v')
        [[ -n "$TARGET_TYPE" ]] && TARGET_OBJ=$(echo "$TARGET_OBJ" | jq --arg v "$TARGET_TYPE" '.type = $v')

        # Create state
        jq -n \
            --arg eid "$ENGAGEMENT_ID" \
            --arg pname "$PROJECT_NAME" \
            --arg handle "$HANDLE" \
            --arg platform "$PLATFORM" \
            --arg pdir "$PROJECT_DIR" \
            --arg ts "$NOW" \
            --argjson target "$TARGET_OBJ" \
            --argjson assigned "$ASSIGNED" \
            --argjson agents "$AGENTS_OBJ" \
            '{
                engagement_id: $eid,
                project_name: $pname,
                handle: $handle,
                platform: $platform,
                project_dir: $pdir,
                target: $target,
                created_at: $ts,
                updated_at: $ts,
                status: "initializing",
                assigned_agents: $assigned,
                agents: $agents,
                phase_history: [{
                    timestamp: $ts,
                    agent: "grimnir",
                    to_phase: "initialized",
                    to_status: "initializing",
                    note: "Engagement created"
                }],
                checkpoints: {},
                report_generated: false
            }' > "$STATE_FILE"

        echo "State initialized: $STATE_FILE"

        # Emit an event (optional — degrades gracefully)
        _emit engagement_started "$PROJECT_NAME" "$TARGET_TYPE" "$ENGAGEMENT_ID"
        # Register the engagement with any loaded sink. Canonical label = dir slug.
        _emit register_engagement "$(basename "$PROJECT_DIR")" "$PLATFORM" "$ENGAGEMENT_ID"
        ;;

    update)
        [[ -z "$AGENT" ]] && { echo "Error: --agent required" >&2; exit 1; }
        [[ ! -f "$STATE_FILE" ]] && { echo "Error: no state.json found at $STATE_FILE" >&2; exit 1; }

        STATE=$(cat "$STATE_FILE")

        # Read current values for history
        OLD_PHASE=$(echo "$STATE" | jq -r ".agents.$AGENT.phase // \"not_started\"")
        OLD_STATUS=$(echo "$STATE" | jq -r ".agents.$AGENT.status // \"not_started\"")
        # Engagement-level overall status BEFORE this update, to detect a transition to propagate.
        OLD_OVERALL=$(echo "$STATE" | jq -r '.status // "initializing"')
        OLD_REACH=$(echo "$STATE" | jq -r '.reachability // ""')

        # Optional engagement-level reachability (enum). Store + propagate; a bad value is
        # a no-op with a warning, never a hard failure (best-effort, like event emission itself).
        if [[ -n "$REACHABILITY" ]]; then
            case "$REACHABILITY" in
                open|account-gated|geo-gated|sandbox|unknown)
                    STATE=$(echo "$STATE" | jq --arg r "$REACHABILITY" '.reachability = $r') ;;
                *)
                    echo "Warning: --reachability '$REACHABILITY' not in open|account-gated|geo-gated|sandbox|unknown; ignored" >&2
                    REACHABILITY="" ;;
            esac
        fi

        NEW_PHASE="${PHASE:-$OLD_PHASE}"
        NEW_STATUS="${STATUS:-$OLD_STATUS}"

        # Update agent fields
        STATE=$(echo "$STATE" | jq --arg a "$AGENT" --arg p "$NEW_PHASE" --arg s "$NEW_STATUS" \
            '.agents[$a].phase = $p | .agents[$a].status = $s')

        [[ -n "$PROGRESS" ]] && STATE=$(echo "$STATE" | jq --arg a "$AGENT" --argjson p "$PROGRESS" '.agents[$a].progress = $p')
        [[ -n "$FINDINGS_COUNT" ]] && STATE=$(echo "$STATE" | jq --arg a "$AGENT" --argjson n "$FINDINGS_COUNT" '.agents[$a].findings_count = $n')
        [[ -n "$CRITICAL_COUNT" ]] && STATE=$(echo "$STATE" | jq --arg a "$AGENT" --argjson n "$CRITICAL_COUNT" '.agents[$a].critical_count = $n')
        [[ -n "$HIGH_COUNT" ]] && STATE=$(echo "$STATE" | jq --arg a "$AGENT" --argjson n "$HIGH_COUNT" '.agents[$a].high_count = $n')
        [[ -n "$NEXT_ACTION" ]] && STATE=$(echo "$STATE" | jq --arg a "$AGENT" --arg v "$NEXT_ACTION" '.agents[$a].next_action = $v')

        if [[ ${#BLOCKERS[@]} -gt 0 ]]; then
            STATE=$(echo "$STATE" | jq --arg a "$AGENT" --argjson b "$(json_array "${BLOCKERS[@]}")" '.agents[$a].blockers = $b')
        fi

        # Set started_at on first transition from not_started
        if [[ "$OLD_STATUS" == "not_started" && "$NEW_STATUS" != "not_started" ]]; then
            STATE=$(echo "$STATE" | jq --arg a "$AGENT" --arg ts "$NOW" '.agents[$a].started_at = $ts')
        fi

        # Set completed_at when completed
        if [[ "$NEW_STATUS" == "completed" && "$OLD_STATUS" != "completed" ]]; then
            STATE=$(echo "$STATE" | jq --arg a "$AGENT" --arg ts "$NOW" '.agents[$a].completed_at = $ts')
        fi

        # Add phase_history entry if phase or status changed
        if [[ "$NEW_PHASE" != "$OLD_PHASE" || "$NEW_STATUS" != "$OLD_STATUS" ]]; then
            HISTORY_ENTRY=$(jq -n \
                --arg ts "$NOW" \
                --arg agent "$AGENT" \
                --arg fp "$OLD_PHASE" \
                --arg tp "$NEW_PHASE" \
                --arg fs "$OLD_STATUS" \
                --arg ts2 "$NEW_STATUS" \
                --arg note "${NOTE:-}" \
                '{timestamp: $ts, agent: $agent, from_phase: $fp, to_phase: $tp, from_status: $fs, to_status: $ts2, note: $note}')
            STATE=$(echo "$STATE" | jq --argjson entry "$HISTORY_ENTRY" '.phase_history += [$entry]')
        fi

        # Update timestamp and derive overall status
        STATE=$(echo "$STATE" | jq --arg ts "$NOW" '.updated_at = $ts')
        OVERALL=$(derive_overall_status "$STATE")
        STATE=$(echo "$STATE" | jq --arg s "$OVERALL" '.status = $s')

        echo "$STATE" | jq . > "$STATE_FILE"
        echo "Updated $AGENT: phase=$NEW_PHASE status=$NEW_STATUS"

        # Emit an event (optional — degrades gracefully)
        _EMIT_ENG_ID="$(echo "$STATE" | jq -r '.engagement_id // "unknown"')"
        if [[ "$NEW_STATUS" == "completed" && "$OLD_STATUS" != "completed" ]]; then
            _emit agent_completed "$AGENT" "$_EMIT_ENG_ID" "$(echo "$STATE" | jq -r ".agents.$AGENT.findings_count // 0")"
            declare -F _activity_event >/dev/null 2>&1 && _activity_event "$PROJECT_DIR" handoff "$AGENT" \
                "$AGENT completed ($(echo "$STATE" | jq -r ".agents.$AGENT.findings_count // 0") findings)"
        elif [[ "$OLD_STATUS" == "not_started" && "$NEW_STATUS" != "not_started" ]]; then
            _emit agent_dispatched "$AGENT" "$_EMIT_ENG_ID" "$NEW_PHASE"
            declare -F _activity_event >/dev/null 2>&1 && _activity_event "$PROJECT_DIR" handoff \
                orchestrator "$AGENT dispatched (phase $NEW_PHASE)"
        elif [[ "$NEW_STATUS" == "blocked" && "$OLD_STATUS" != "blocked" ]]; then
            declare -F _activity_event >/dev/null 2>&1 && _activity_event "$PROJECT_DIR" blocked "$AGENT" \
                "$AGENT blocked (phase $NEW_PHASE)" --verdict blocked
        fi

        # Engagement-LEVEL propagation: when the overall status or reachability actually changes,
        # Tell any loaded sink about a park/block/reach-flip. Program name = the dir slug.
        # Best-effort; a sink failure never fails state.sh.
        if [[ "$OVERALL" != "$OLD_OVERALL" || ( -n "$REACHABILITY" && "$REACHABILITY" != "$OLD_REACH" ) ]]; then
            if declare -F _sink_engagement_status >/dev/null 2>&1; then
                _EMIT_PROGRAM="$(basename "$PROJECT_DIR")"
                _emit engagement_status "$_EMIT_PROGRAM" "$_EMIT_ENG_ID" "$OVERALL" "$REACHABILITY" "" || true
            fi
        fi
        ;;

    checkpoint)
        [[ -z "$AGENT" ]] && { echo "Error: --agent required" >&2; exit 1; }
        [[ ! -f "$STATE_FILE" ]] && { echo "Error: no state.json found" >&2; exit 1; }

        STATE=$(cat "$STATE_FILE")

        CP='{}'
        CP=$(echo "$CP" | jq --arg ts "$NOW" '.timestamp = $ts')
        [[ -n "$LAST_ACTION" ]] && CP=$(echo "$CP" | jq --arg v "$LAST_ACTION" '.last_completed_action = $v')

        if [[ ${#COMPLETED_TESTS[@]} -gt 0 ]]; then
            CP=$(echo "$CP" | jq --argjson arr "$(json_array "${COMPLETED_TESTS[@]}")" '.completed_tests = $arr')
        fi
        if [[ ${#PENDING_TESTS[@]} -gt 0 ]]; then
            CP=$(echo "$CP" | jq --argjson arr "$(json_array "${PENDING_TESTS[@]}")" '.pending_tests = $arr')
        fi
        if [[ ${#DISCOVERED_TARGETS[@]} -gt 0 ]]; then
            CP=$(echo "$CP" | jq --argjson arr "$(json_array "${DISCOVERED_TARGETS[@]}")" '.discovered_targets = $arr')
        fi

        STATE=$(echo "$STATE" | jq --arg a "$AGENT" --argjson cp "$CP" '.checkpoints[$a] = $cp')
        STATE=$(echo "$STATE" | jq --arg ts "$NOW" '.updated_at = $ts')

        echo "$STATE" | jq . > "$STATE_FILE"
        echo "Checkpoint saved for $AGENT"
        ;;

    get)
        [[ ! -f "$STATE_FILE" ]] && { echo "Error: no state.json found at $PROJECT_DIR" >&2; exit 1; }

        if [[ -n "$FIELD" ]]; then
            jq "$FIELD" "$STATE_FILE"
        elif [[ -n "$AGENT" ]]; then
            jq ".agents.$AGENT" "$STATE_FILE"
        else
            jq . "$STATE_FILE"
        fi
        ;;

    summary)
        [[ ! -f "$STATE_FILE" ]] && { echo "No state.json found at $PROJECT_DIR. Run /engage first." >&2; exit 1; }

        STATE=$(cat "$STATE_FILE")

        PNAME=$(echo "$STATE" | jq -r '.project_name')
        PDIR=$(echo "$STATE" | jq -r '.project_dir')
        TGT=$(echo "$STATE" | jq -r '.target.primary // "N/A"')
        TTYPE=$(echo "$STATE" | jq -r '.target.type // "N/A"')
        OVERALL=$(echo "$STATE" | jq -r '.status')
        REPORT=$(echo "$STATE" | jq -r '.report_generated')
        ASSIGNED=$(echo "$STATE" | jq -r '.assigned_agents // [] | join(", ")')

        echo "Project:        $PNAME"
        echo "Directory:      $PDIR"
        echo "Target:         $TGT"
        echo "Classification: $TTYPE"
        echo "Status:         $OVERALL"
        echo "Assigned:       $ASSIGNED"
        echo ""
        echo "Agent Status:"

        for a in huginn specter artemis hunter nimbus nomad; do
            IS_ASSIGNED=$(echo "$STATE" | jq -r --arg a "$a" '.assigned_agents // [] | index($a) // empty')
            [[ -z "$IS_ASSIGNED" ]] && continue

            APHASE=$(echo "$STATE" | jq -r ".agents.$a.phase")
            ASTATUS=$(echo "$STATE" | jq -r ".agents.$a.status")
            APROG=$(echo "$STATE" | jq -r ".agents.$a.progress")
            AFIND=$(echo "$STATE" | jq -r ".agents.$a.findings_count")
            ACRIT=$(echo "$STATE" | jq -r ".agents.$a.critical_count")
            AHIGH=$(echo "$STATE" | jq -r ".agents.$a.high_count")

            # Format status with padding
            LABEL=$(printf "%-8s" "$a")
            STATUS_TAG=$(printf "[%-11s]" "${ASTATUS^^}")
            PROG_PCT=$(echo "$APROG" | awk '{printf "%.0f%%", $1 * 100}')

            echo "  $LABEL $STATUS_TAG  phase=$APHASE  progress=$PROG_PCT  findings=$AFIND (crit=$ACRIT high=$AHIGH)"
        done

        echo ""
        if [[ "$REPORT" == "true" ]]; then
            RPATH=$(echo "$STATE" | jq -r '.report_path // "report.md"')
            echo "Report: Generated ($RPATH)"
        else
            echo "Report: Not yet generated"
        fi
        ;;

    *)
        echo "Unknown command: $COMMAND" >&2
        usage
        ;;
esac
