#!/usr/bin/env bash
# garak-baseline.sh — Run garak LLM vulnerability baseline scan
# Usage: bash scripts/garak-baseline.sh <MODEL_TYPE> <MODEL_NAME> [OPTIONS]
#
# Runs a targeted garak scan with conservative defaults to minimize
# API token consumption and respect rate limits.
#
# Model types: openai, huggingface, rest (custom REST API)
# For custom REST APIs, set GARAK_REST_ENDPOINT and GARAK_REST_API_KEY env vars.
#
# Examples:
#   bash scripts/garak-baseline.sh openai gpt-4
#   bash scripts/garak-baseline.sh rest custom-target
#   bash scripts/garak-baseline.sh rest custom-target --probes encoding,knownbadsignatures
#
# ⚠️  TOKEN/COST WARNING: garak generates many API calls per probe.
# The default probe set below is curated to balance coverage with cost.
# A full "all probes" scan can consume 10,000+ API calls.
# Always use --probes to limit scope, or accept the defaults below.

set -euo pipefail

MODEL_TYPE="${1:?Usage: garak-baseline.sh <MODEL_TYPE> <MODEL_NAME> [OPTIONS]}"
MODEL_NAME="${2:?Usage: garak-baseline.sh <MODEL_TYPE> <MODEL_NAME> [OPTIONS]}"
shift 2

# --- Defaults ---
PROJECT_DIR="${PROJECT_DIR:-$(pwd)}"
OUTPUT_DIR="${PROJECT_DIR}/artemis/recon/garak"
REPORT_DIR="${PROJECT_DIR}/artemis/reports"
PROBES=""
GENERATIONS=5          # Matches ARTEMIS "minimum 5 attempts" rule
RATE_LIMIT="0.5"       # Seconds between requests (2 req/sec max)
PARALLEL=1             # Sequential by default — safest for rate limiting
EXTRA_ARGS=()

# --- Parse optional args ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --probes)       PROBES="$2"; shift 2 ;;
        --generations)  GENERATIONS="$2"; shift 2 ;;
        --rate-limit)   RATE_LIMIT="$2"; shift 2 ;;
        --parallel)     PARALLEL="$2"; shift 2 ;;
        --output-dir)   OUTPUT_DIR="$2"; shift 2 ;;
        *)              EXTRA_ARGS+=("$1"); shift ;;
    esac
done

# --- Default probe set (high-signal, low-token-cost) ---
# These probes cover the most critical LLM vulnerability classes
# without burning excessive tokens. Add more with --probes as needed.
if [[ -z "$PROBES" ]]; then
    PROBES="promptinject,encoding,dan,goodside,leakreplay,snowball,exploitation"
    # promptinject     → LLM01 Prompt Injection (core risk)
    # encoding         → LLM01 Encoding-based bypasses (base64, rot13, hex, braille, etc.)
    # dan              → LLM01 DAN/jailbreak attempts (guardrail bypass)
    # goodside         → LLM01 Benign-framed prompt injection
    # leakreplay       → LLM02/LLM07 Training data & system prompt leakage
    # snowball         → LLM09 Hallucination/misinformation testing
    # exploitation     → LLM05 Output handling exploitation
    #
    # Additional probes (add with --probes for deeper coverage):
    #   suffix          → Adversarial suffix attacks (GCG-style)
    #   tap             → Tree of Attacks with Pruning
    #   latentinjection → Indirect/latent prompt injection
    #   smuggling       → Token smuggling bypasses
    #   packagehallucination → Package hallucination (supply chain)
    #   web_injection   → Web-based injection via LLM output
    #   apikey          → API key leakage
    #   dra             → Direct Request Attack
    #   glitch          → Glitch token attacks
fi

mkdir -p "$OUTPUT_DIR" "$REPORT_DIR"

echo "============================================="
echo "  ARTEMIS — garak Baseline Scan"
echo "============================================="
echo ""
echo "  Model:        $MODEL_TYPE / $MODEL_NAME"
echo "  Probes:       $PROBES"
echo "  Generations:  $GENERATIONS per probe"
echo "  Rate limit:   ${RATE_LIMIT}s between requests"
echo "  Parallelism:  $PARALLEL"
echo "  Output:       $OUTPUT_DIR"
echo ""
echo "  ⚠️  Estimated API calls: ~$((GENERATIONS * $(echo "$PROBES" | tr ',' '\n' | wc -l) * 10))-$((GENERATIONS * $(echo "$PROBES" | tr ',' '\n' | wc -l) * 50))"
echo "  ⚠️  Monitor token usage during scan"
echo ""
echo "============================================="
echo ""

# --- Build garak command ---
GARAK_CMD=(
    garak
    --model_type "$MODEL_TYPE"
    --model_name "$MODEL_NAME"
    --probes "$PROBES"
    --generations "$GENERATIONS"
    --report_prefix "$OUTPUT_DIR/baseline"
)

# Add rate limiting via environment (garak respects these)
export GARAK_RATE_LIMIT="$RATE_LIMIT"

# Add REST API config if applicable
if [[ "$MODEL_TYPE" == "rest" ]]; then
    if [[ -n "${GARAK_REST_ENDPOINT:-}" ]]; then
        GARAK_CMD+=(--model_name "$GARAK_REST_ENDPOINT")
    fi
fi

# Add any extra args
if [[ ${#EXTRA_ARGS[@]} -gt 0 ]]; then
    GARAK_CMD+=("${EXTRA_ARGS[@]}")
fi

# --- Activate venv ---
if [[ -f "$HOME/venv/bin/activate" ]]; then
    source "$HOME/venv/bin/activate"
fi

# --- Run scan ---
SCAN_START=$(date -u +%Y-%m-%dT%H:%M:%SZ)
echo "[$(date +%H:%M:%S)] Starting garak scan..."
echo ""

if "${GARAK_CMD[@]}" 2>&1 | tee "$OUTPUT_DIR/garak-scan.log"; then
    SCAN_STATUS="completed"
    echo ""
    echo "[$(date +%H:%M:%S)] Scan completed successfully"
else
    SCAN_STATUS="completed_with_errors"
    echo ""
    echo "[$(date +%H:%M:%S)] Scan completed with errors (check log)"
fi

SCAN_END=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# --- Generate summary ---
SUMMARY_FILE="$OUTPUT_DIR/baseline-summary.md"
cat > "$SUMMARY_FILE" << EOF
# garak Baseline Scan Summary

- **Model**: $MODEL_TYPE / $MODEL_NAME
- **Probes**: $PROBES
- **Generations**: $GENERATIONS
- **Rate limit**: ${RATE_LIMIT}s
- **Status**: $SCAN_STATUS
- **Started**: $SCAN_START
- **Finished**: $SCAN_END
- **Log**: garak-scan.log

## Results

$(if ls "$OUTPUT_DIR"/baseline*.json 2>/dev/null; then
    echo "JSON report files generated — parse with jq for detailed results."
    echo ""
    echo "Quick stats:"
    for f in "$OUTPUT_DIR"/baseline*.json; do
        echo "  - $(basename "$f")"
    done
else
    echo "No JSON reports found — check garak-scan.log for errors."
fi)

## Next Steps

1. Review failed probes for confirmed vulnerabilities
2. Use findings to prioritize manual ARTEMIS testing phases
3. Create findings for confirmed issues: \`bash scripts/finding.sh ...\`

## Probe Coverage → OWASP Mapping

| Probe | OWASP Category |
|-------|---------------|
| promptinject | LLM01 Prompt Injection |
| knownbadsignatures | LLM01/LLM05 |
| encoding | LLM01 (bypass techniques) |
| dan | LLM01 (jailbreak variant) |
| gcg | LLM01 (adversarial suffix) |
| xss | LLM05 Improper Output Handling |
| snowball | LLM09 Misinformation |
EOF

echo ""
echo "Summary written to: $SUMMARY_FILE"
echo ""
echo "============================================="
echo "  Baseline scan complete"
echo "  Review: $OUTPUT_DIR/garak-scan.log"
echo "  Summary: $SUMMARY_FILE"
echo "============================================="
