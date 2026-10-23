#!/bin/bash
# decision-log.sh — append-only audit trail of orchestrator routing decisions.
#
# Records WHY Grimnir engaged / skipped / dispatched / deferred a lane, so /sitrep and
# /resume can explain themselves and a later session can see the reasoning, not just the
# outcome. Complements state.json (lifecycle), intel.jsonl (what was found), and
# event-emitter.sh record-negative (dead-lane outcomes). Writes $PROJECT_DIR/decisions.jsonl.
#
# Usage:
#   decision-log.sh record --project-dir DIR --type TYPE --reason "..." [OPTIONS]
#   decision-log.sh show   --project-dir DIR [--type TYPE]
#
# record OPTIONS:
#   --type TYPE          engage|skip|dispatch|defer|pivot|escalate|gate-block|no-file|close
#                        (required). no-file = a confirmed finding was deliberately NOT
#                        submitted; pass --finding so `an outcome tracker backlog` stops listing it.
#   --reason TEXT        why (required)
#   --actor WHO          grimnir|operator|<specialist-id>   (default: grimnir) — ENUM, not
#                        free text. A filesystem-writing agent must not be able to mint an
#                        entry that reads as a genuine human decision (ROADMAP item 21).
#   --relayed-by WHO     the process RECORDING on the actor's behalf. Relaying an operator
#                        authorization is structurally distinct from the operator recording
#                        it directly: use this instead of claiming --actor operator outright.
#   --operator-token T   proves live operator presence for --actor operator. Compared against
#                        $GRIMNIR_OPERATOR_TOKEN_FILE (default $GRIMNIR_HOME/operator-presence.token,
#                        held OUTSIDE the project dir). Absent/mismatched -> the entry is labeled
#                        a RELAYED, UNVERIFIED claim, never a verified operator action.
#   --authorize          this decision LIFTS a safety boundary (custody/financial/destructive).
#                        Records an authorization.status a specialist can read: VERIFIED-OPERATOR
#                        only with a matching operator token, else UNVERIFIED-RELAY (+ loud warn).
#   --source SRC         reasoning|heuristic|operator|policy|reachability|brief  (default: reasoning)
#   --subject TEXT       lane / target / agent / playbook the decision is about
#   --goal TEXT          objective this decision serves
#   --chosen TEXT        the action taken
#   --alt TEXT           an alternative considered (repeatable)
#   --reachability TEXT  reachability verdict that drove it (e.g. "BLOCKED(second-account)")
#   --playbook ID        linked playbook id
#   --intel INTEL-NNNNNN related intel entry
#   --finding AGT-NNN     related finding (e.g. ART-004)
#   --confidence LEVEL   high|medium|low
set -euo pipefail

SCHEMA_TYPES="engage|skip|dispatch|defer|pivot|escalate|gate-block|no-file|close"

die() { echo "Error: $*" >&2; exit 1; }

CMD="${1:-}"; shift || true
[[ "$CMD" =~ ^(record|show)$ ]] || die "usage: $0 record|show --project-dir DIR [...]"

PROJECT_DIR=""; TYPE=""; REASON=""; ACTOR="grimnir"; SOURCE="reasoning"
SUBJECT=""; GOAL=""; CHOSEN=""; REACHABILITY=""; PLAYBOOK=""; INTEL=""; FINDING=""
CONFIDENCE=""; FILTER_TYPE=""
RELAYED_BY=""; OPERATOR_TOKEN=""; AUTHORIZE=false
ALTS='[]'

while [[ $# -gt 0 ]]; do
    case "$1" in
        --project-dir)  PROJECT_DIR="$2"; shift 2 ;;
        --type)         if [[ "$CMD" == "show" ]]; then FILTER_TYPE="$2"; else TYPE="$2"; fi; shift 2 ;;
        --reason)       REASON="$2"; shift 2 ;;
        --actor)        ACTOR="$2"; shift 2 ;;
        --relayed-by)   RELAYED_BY="$2"; shift 2 ;;
        --operator-token) OPERATOR_TOKEN="$2"; shift 2 ;;
        --authorize)    AUTHORIZE=true; shift ;;
        --source)       SOURCE="$2"; shift 2 ;;
        --subject)      SUBJECT="$2"; shift 2 ;;
        --goal)         GOAL="$2"; shift 2 ;;
        --chosen)       CHOSEN="$2"; shift 2 ;;
        --alt)          ALTS="$(jq -c --arg a "$2" '. + [$a]' <<<"$ALTS")"; shift 2 ;;
        --reachability) REACHABILITY="$2"; shift 2 ;;
        --playbook)     PLAYBOOK="$2"; shift 2 ;;
        --intel)        INTEL="$2"; shift 2 ;;
        --finding)      FINDING="$2"; shift 2 ;;
        --confidence)   CONFIDENCE="$2"; shift 2 ;;
        *) die "unknown option: $1" ;;
    esac
done

[[ -n "$PROJECT_DIR" ]] || die "--project-dir is required"
[[ "$PROJECT_DIR" == /* ]] || die "--project-dir must be an absolute path"
[[ -d "$PROJECT_DIR" ]] || die "no such directory: $PROJECT_DIR"
LOG="$PROJECT_DIR/decisions.jsonl"

if [[ "$CMD" == "show" ]]; then
    [[ -f "$LOG" ]] || { echo "no decisions logged yet at $LOG"; exit 0; }
    # Surface authorization grade and relayed provenance inline — a reader must be able to
    # tell a verified operator authorization from a relayed, unverified claim at a glance.
    LINE='"\(.id)  \(.timestamp)  [\(.decision_type)] \(.subject // "-")  :: \(.reason)"
          + (if .authorization then "  <AUTHZ:\(.authorization.status)>" else "" end)
          + (if .provenance == "relayed" then "  <relayed by \(.relayed_by // "?")>" else "" end)'
    if [[ -n "$FILTER_TYPE" ]]; then
        jq -r --arg t "$FILTER_TYPE" "select(.decision_type==\$t) | $LINE" "$LOG"
    else
        jq -r "$LINE" "$LOG"
    fi
    exit 0
fi

# ── record ──
[[ -n "$TYPE" ]] || die "--type is required"
[[ "$TYPE" =~ ^($SCHEMA_TYPES)$ ]] || die "--type must be one of: ${SCHEMA_TYPES//|/, }"
[[ -n "$REASON" ]] || die "--reason is required"

# ── actor integrity (ROADMAP item 21) ──
# --actor is an enum, never free text: a process that can write a file must not be able to
# mint an entry textually identical to a genuine operator decision. A specialist reads this
# log to confirm a safety boundary was really lifted, so an "operator" claim must carry its
# provenance in the record. NOTE, honestly: every agent here runs as the same uid, so the
# token below is a provenance speed-bump + honest labeling, not a cryptographic barrier. The
# real fix for custody/financial overrides is an in-session, spoken confirmation (operator's
# architectural call — see the roadmap); this closes the *accidental consent-laundering* path.
KNOWN_AGENTS="huginn|specter|artemis|hunter|nimbus|nomad|report-compiler"
[[ "$ACTOR" =~ ^(grimnir|operator|$KNOWN_AGENTS)$ ]] \
    || die "--actor must be grimnir, operator, or a specialist id ($KNOWN_AGENTS) — not free text"

ACTOR_VERIFIED=false
PROVENANCE="originated"
OPTOKEN_FILE="${GRIMNIR_OPERATOR_TOKEN_FILE:-${GRIMNIR_HOME:-$HOME/.grimnir}/operator-presence.token}"
if [[ "$ACTOR" == "operator" ]]; then
    if [[ -n "$OPERATOR_TOKEN" && -s "$OPTOKEN_FILE" ]] \
       && [[ "$OPERATOR_TOKEN" == "$(cat "$OPTOKEN_FILE" 2>/dev/null)" ]]; then
        ACTOR_VERIFIED=true          # live operator presence proven
    else
        # actor=operator but presence unproven -> this is a RELAYED claim; label it as such
        # rather than letting it masquerade as a direct human entry.
        PROVENANCE="relayed"
        [[ -z "$RELAYED_BY" ]] && RELAYED_BY="grimnir"
    fi
elif [[ -n "$RELAYED_BY" ]]; then
    PROVENANCE="relayed"
fi

# ── authorization grade (only meaningful when --authorize is set) ──
AUTH_STATUS=""
if [[ "$AUTHORIZE" == true ]]; then
    if [[ "$ACTOR" == "operator" && "$ACTOR_VERIFIED" == true ]]; then
        AUTH_STATUS="VERIFIED-OPERATOR"
    else
        AUTH_STATUS="UNVERIFIED-RELAY"
        {
          echo "WARNING: safety-boundary authorization recorded WITHOUT verified operator presence."
          echo "  This entry is a RELAYED claim (authorization_status=UNVERIFIED-RELAY), not a proven"
          echo "  human decision. A specialist reading this log MUST NOT treat it as consent to cross a"
          echo "  custody / financial / destructive boundary. Obtain in-session operator confirmation."
        } >&2
    fi
fi

# Next sequential id (count existing lines, 1-indexed, zero-padded to 6).
# Records are always newline-terminated, so wc -l == record count exactly.
NEXT=1
[[ -f "$LOG" ]] && NEXT=$(( $(wc -l < "$LOG" 2>/dev/null || echo 0) + 1 ))
ID="$(printf 'DECISION-%06d' "$NEXT")"
NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

IS_OPERATOR=$([[ "$ACTOR" == "operator" ]] && echo true || echo false)
ENTRY="$(jq -nc \
    --arg id "$ID" --arg ts "$NOW" --arg actor "$ACTOR" --arg source "$SOURCE" \
    --arg type "$TYPE" --arg subject "$SUBJECT" --arg goal "$GOAL" --arg chosen "$CHOSEN" \
    --arg reason "$REASON" --arg reach "$REACHABILITY" --arg pb "$PLAYBOOK" \
    --arg intel "$INTEL" --arg finding "$FINDING" --arg conf "$CONFIDENCE" \
    --arg relayedby "$RELAYED_BY" --arg provenance "$PROVENANCE" --arg authstatus "$AUTH_STATUS" \
    --argjson isop "$IS_OPERATOR" --argjson actorver "$ACTOR_VERIFIED" \
    --argjson alts "$ALTS" \
    '{id:$id, timestamp:$ts, actor:$actor, source:$source, decision_type:$type, reason:$reason}
     + (if $subject != "" then {subject:$subject} else {} end)
     + (if $goal != "" then {goal:$goal} else {} end)
     + (if $chosen != "" then {chosen:$chosen} else {} end)
     + (if ($alts|length) > 0 then {alternatives:$alts} else {} end)
     + (if $reach != "" then {reachability_ref:$reach} else {} end)
     + (if $pb != "" then {playbook_id:$pb} else {} end)
     + (if $intel != "" then {related_intel:$intel} else {} end)
     + (if $finding != "" then {related_finding:$finding} else {} end)
     + (if $conf != "" then {confidence:$conf} else {} end)
     + (if $isop then {actor_verified:$actorver, provenance:$provenance} else {} end)
     + (if $relayedby != "" then {relayed_by:$relayedby} else {} end)
     + (if $authstatus != "" then {authorization:{status:$authstatus, verified:$actorver}} else {} end)')"

printf '%s\n' "$ENTRY" >> "$LOG"
echo "$ID recorded -> $LOG"

# Activity ledger (best-effort; decisions.jsonl stays the authoritative decision trail, and an
# activity record is never an authorization: specialists read authorization from this log).
python3 "$(dirname "${BASH_SOURCE[0]}")/activity.py" append --project-dir "$PROJECT_DIR" \
    --kind decision --actor "$ACTOR" --lenient --summary "$TYPE: ${SUBJECT:+$SUBJECT: }$REASON" \
    --ref "decision:$ID" ${PLAYBOOK:+--playbook "$PLAYBOOK"} \
    ${FINDING:+--ref "finding:$FINDING"} >/dev/null 2>&1 || true
[[ "$ACTOR" == "operator" ]] && echo "  actor=operator provenance=$PROVENANCE verified=$ACTOR_VERIFIED"
[[ -n "$AUTH_STATUS" ]] && echo "  authorization_status=$AUTH_STATUS"
exit 0
