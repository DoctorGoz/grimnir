#!/bin/bash
# Grimnir event hooks: the activity ledger funnel and the dead-lane (record-negative) writer.
#
# Source this file in any script that records engagement events, then call the generic hook:
#   source "${REPO:-.}/scripts/event-emitter.sh"
#   _emit finding_created ID ENG_ID SEVERITY AGENT TITLE
# `_emit TYPE ARGS...` forwards to an optional event sink (a `_sink_TYPE` function) when one is
# loaded, and is a silent no-op otherwise. Tools NEVER fail because of event emission.
#
# CLI:  bash scripts/event-emitter.sh record-negative --lane L [--class C] [--surface S] ...

set -euo pipefail

# ── Activity ledger funnel ───────────────────────────────────────────────────
# Event sinks are optional and fire-and-forget; the activity ledger is the durable,
# per-engagement record ($PROJECT_DIR/activity.jsonl, via scripts/activity.py, which owns the
# schema, ids, and token redaction). Every emitter that knows its project dir calls this too.
# Best-effort: a missing dir, bad value, or python error is swallowed, never fails the caller.
# Usage: _activity_event PROJECT_DIR KIND ACTOR SUMMARY [activity.py append flags...]
_GRIMNIR_EMITTER_DIR="${_GRIMNIR_EMITTER_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)}"
export _GRIMNIR_EMITTER_DIR

_activity_event() {
    local pd="${1:-}" kind="${2:-}" actor="${3:-}" summary="${4:-}"
    [[ -n "$pd" && -d "$pd" && -n "$kind" && -n "$summary" ]] || return 0
    shift 4
    python3 "${_GRIMNIR_EMITTER_DIR}/activity.py" append --project-dir "$pd" \
        --kind "$kind" --actor "${actor:-orchestrator}" --summary "$summary" --lenient "$@" \
        >/dev/null 2>&1 || true
}

# ── Generic event hook ───────────────────────────────────────────────────────
# Usage: _emit TYPE ARGS...   Output of the sink (if any) is passed through, so lookups such as
# `_emit engagement_id_for PROGRAM` work; with no sink loaded nothing is printed.
_emit() {
    local t="${1:-}"; shift || true
    if declare -F "_sink_${t}" >/dev/null 2>&1; then "_sink_${t}" "$@"; fi
    return 0
}
# Optional sinks: any `*-client.sh` beside this file is loaded when present.
for _sink_file in "${_GRIMNIR_EMITTER_DIR}"/*-client.sh; do
    # shellcheck source=/dev/null
    [[ -f "$_sink_file" ]] && source "$_sink_file"
done
unset _sink_file
export -f _activity_event _emit

# ── CLI entrypoint (so agents can: bash scripts/event-emitter.sh record-negative ...) ──
# Only runs when executed directly, never when sourced.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    sub="${1:-}"; shift || true
    case "$sub" in
        record-negative)
            program=""; lane=""; surface=""; reason=""; agent=""; klass=""; pdir=""
            while [[ $# -gt 0 ]]; do case "$1" in
                --project-dir) pdir="$2"; shift 2 ;;
                --program) program="$2"; shift 2 ;;
                --lane)    lane="$2"; shift 2 ;;
                --class)   klass="$2"; shift 2 ;;
                --surface) surface="$2"; shift 2 ;;
                --reason)  reason="$2"; shift 2 ;;
                --agent)   agent="$2"; shift 2 ;;
                *) echo "unknown arg: $1" >&2; exit 2 ;;
            esac; done
            [[ -z "$lane" ]] && { echo "record-negative: --lane is required" >&2; exit 1; }
            data="$(python3 -c 'import json,sys; k=["program","lane","class","surface","reason","agent"]; print(json.dumps(dict(zip(k,sys.argv[1:7]))))' "$program" "$lane" "$klass" "$surface" "$reason" "$agent" 2>/dev/null)"
            [[ -z "$data" ]] && { echo "record-negative: failed to build payload" >&2; exit 1; }
            # Durable local record FIRST. Event sinks are optional and fire-and-forget;
            # relying on one alone would print success and record nothing, while coverage.py
            # reads the journal below as a tested-corpus source. Producer and consumer must agree.
            journal="${GRIMNIR_TEST_JOURNAL:-$HOME/.grimnir/tests/test-journal.jsonl}"
            if ! mkdir -p "$(dirname "$journal")" 2>/dev/null; then
                echo "record-negative: cannot create $(dirname "$journal")" >&2; exit 1
            fi
            if ! python3 -c 'import json,sys,datetime
rec=json.loads(sys.argv[1])
rec["ts"]=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
with open(sys.argv[2],"a") as fh:
    fh.write(json.dumps(rec)+"\n")' "$data" "$journal" 2>/dev/null; then
                echo "record-negative: failed to append to $journal" >&2; exit 1
            fi
            _emit negative_result "$data"
            # Per-engagement activity ledger: explicit --project-dir, else the program's
            # engagement dir under $GRIMNIR_WORKSPACE when it exists.
            [[ -z "$pdir" && -n "$program" ]] && pdir="${GRIMNIR_WORKSPACE:-$HOME/workspace}/$program"
            [[ -n "$program" || -z "$pdir" ]] || program="$(basename "$pdir")"
            _activity_event "$pdir" negative "${agent:-orchestrator}" \
                "${lane}${reason:+: $reason}" --verdict negative \
                ${klass:+--lane-class "$klass"} ${surface:+--target "$surface"}
            echo "recorded negative: ${lane}${surface:+ on $surface}${reason:+ — $reason} -> $journal"
            # Pivot signal (Rule 22), fertility-modulated (module #3): a HOT surface
            # RAISES the threshold (negatives there mean "not found yet" — keep digging);
            # WARM raises slightly; UNKNOWN leaves it (absence of disclosure is not
            # evidence of dead, so we never pivot EARLIER on weak data). Best-effort.
            _emit pivot_signal "$program" "${klass:-$lane}" "$lane"
            ;;
        ""|-h|--help)
            echo "usage: event-emitter.sh record-negative --lane L [--class C] [--surface S] [--reason R] [--program P] [--project-dir DIR] [--agent A]" >&2 ;;
        *) echo "unknown subcommand: $sub" >&2; exit 2 ;;
    esac
fi
