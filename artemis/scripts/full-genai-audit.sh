#!/usr/bin/env bash
# full-genai-audit.sh — Orchestrate a complete GenAI security audit
# Usage: bash scripts/full-genai-audit.sh <TARGET_URL> [API_KEY] [ENGAGEMENT_ID]
#
# Runs all automated testing phases sequentially, compiling results into
# the engagement directory.

set -euo pipefail

TARGET="${1:?Usage: full-genai-audit.sh <TARGET_URL> [API_KEY] [ENGAGEMENT_ID]}"
API_KEY="${2:-}"
ENGAGEMENT_ID="${3:-ENG-$(date +%Y%m%d)}"
SCRIPTS_DIR="$(dirname "$0")"
OUTPUT_DIR="engagements/$ENGAGEMENT_ID"

mkdir -p "$OUTPUT_DIR"

echo "============================================="
echo "  ARTEMIS — Full GenAI Security Audit"
echo "============================================="
echo ""
echo "Target:        $TARGET"
echo "Engagement ID: $ENGAGEMENT_ID"
echo "Output:        $OUTPUT_DIR"
echo "Started:       $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo ""
echo "============================================="

AUDIT_LOG="$OUTPUT_DIR/audit-log.txt"
echo "ARTEMIS Full Audit Log" > "$AUDIT_LOG"
echo "Target: $TARGET" >> "$AUDIT_LOG"
echo "Started: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$AUDIT_LOG"
echo "" >> "$AUDIT_LOG"

run_phase() {
    local PHASE_NUM="$1"
    local PHASE_NAME="$2"
    local SCRIPT="$3"
    shift 3

    echo ""
    echo "--- Phase $PHASE_NUM: $PHASE_NAME ---"
    echo "[$(date +%H:%M:%S)] Phase $PHASE_NUM: $PHASE_NAME" >> "$AUDIT_LOG"

    if bash "$SCRIPT" "$@" >> "$AUDIT_LOG" 2>&1; then
        echo "  [DONE] $PHASE_NAME completed"
        echo "  [DONE] Phase $PHASE_NUM completed" >> "$AUDIT_LOG"
    else
        echo "  [WARN] $PHASE_NAME had errors (see audit log)"
        echo "  [WARN] Phase $PHASE_NUM had errors" >> "$AUDIT_LOG"
    fi
    echo "" >> "$AUDIT_LOG"
}

# Phase 1: Reconnaissance
run_phase 1 "Reconnaissance" \
    "$SCRIPTS_DIR/llm-recon.sh" "$TARGET" "$API_KEY" "$OUTPUT_DIR/recon"

# Phase 1.5: garak Baseline Scan (optional — skipped if GARAK_SKIP=1 or model info not provided)
# ⚠️ TOKEN WARNING: garak generates many API calls. Set GARAK_MODEL_TYPE and GARAK_MODEL_NAME
# to enable, or skip with GARAK_SKIP=1. Default probe set: ~300-1000 API calls.
if [[ "${GARAK_SKIP:-0}" != "1" ]] && [[ -n "${GARAK_MODEL_TYPE:-}" ]] && [[ -n "${GARAK_MODEL_NAME:-}" ]]; then
    echo ""
    echo "--- Phase 1.5: garak Baseline Scan ---"
    echo "  ⚠️  This will generate ~300-1000 API calls with default probes"
    echo "[$(date +%H:%M:%S)] Phase 1.5: garak Baseline Scan" >> "$AUDIT_LOG"

    GARAK_ARGS=(
        "$SCRIPTS_DIR/garak-baseline.sh"
        "$GARAK_MODEL_TYPE"
        "$GARAK_MODEL_NAME"
        --output-dir "$OUTPUT_DIR/garak"
    )
    [[ -n "${GARAK_RATE_LIMIT:-}" ]] && GARAK_ARGS+=(--rate-limit "$GARAK_RATE_LIMIT")
    [[ -n "${GARAK_PROBES:-}" ]] && GARAK_ARGS+=(--probes "$GARAK_PROBES")

    if bash "${GARAK_ARGS[@]}" >> "$AUDIT_LOG" 2>&1; then
        echo "  [DONE] garak baseline completed"
        echo "  [DONE] Phase 1.5 completed" >> "$AUDIT_LOG"
    else
        echo "  [WARN] garak baseline had errors (see audit log)"
        echo "  [WARN] Phase 1.5 had errors" >> "$AUDIT_LOG"
    fi
    echo "" >> "$AUDIT_LOG"
else
    echo ""
    echo "--- Phase 1.5: garak Baseline Scan [SKIPPED] ---"
    if [[ "${GARAK_SKIP:-0}" == "1" ]]; then
        echo "  Skipped: GARAK_SKIP=1"
    else
        echo "  Skipped: Set GARAK_MODEL_TYPE and GARAK_MODEL_NAME to enable"
        echo "  Example: GARAK_MODEL_TYPE=openai GARAK_MODEL_NAME=gpt-4 bash $0 ..."
    fi
fi

# Phase 2: System Prompt Extraction
run_phase 2 "System Prompt Extraction" \
    "$SCRIPTS_DIR/system-prompt-extract.sh" "$TARGET" "$API_KEY" "$OUTPUT_DIR/sysprompt"

# Phase 3: Prompt Injection Testing
run_phase 3 "Prompt Injection Spray" \
    "$SCRIPTS_DIR/prompt-injection-spray.sh" "$TARGET" "$API_KEY" "$OUTPUT_DIR/prompt-injection"

# Phase 4: Guardrail Assessment
run_phase 4 "Guardrail Assessment" \
    "$SCRIPTS_DIR/guardrail-probe.sh" "$TARGET" "$API_KEY" "$OUTPUT_DIR/guardrails"

# Phase 5: Agent Tool Enumeration
run_phase 5 "Agent Tool Enumeration" \
    "$SCRIPTS_DIR/agent-tool-enum.sh" "$TARGET" "$API_KEY" "$OUTPUT_DIR/agent-tools"

# Phase 6: Output XSS Testing
run_phase 6 "Output Handling XSS" \
    "$SCRIPTS_DIR/output-xss-test.sh" "$TARGET" "$API_KEY" "$OUTPUT_DIR/output-xss"

echo ""
echo "============================================="
echo "  Audit Complete"
echo "============================================="
echo ""
echo "Finished: $(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "$AUDIT_LOG"
echo ""
echo "Results directory: $OUTPUT_DIR/"
echo ""
echo "Phase results:"
for DIR in recon garak sysprompt prompt-injection guardrails agent-tools output-xss; do
    if [[ -d "$OUTPUT_DIR/$DIR" ]]; then
        FILE_COUNT=$(find "$OUTPUT_DIR/$DIR" -type f | wc -l)
        echo "  $DIR/: $FILE_COUNT files"
    fi
done
echo ""
echo "Next steps:"
echo "  1. Review results in each phase directory"
echo "  2. Create findings: bash scripts/new-finding.sh 'Title' 'Category' 'Severity'"
echo "  3. Run interactive assessment: /assess [category]"
echo "  4. Generate report: /report"
