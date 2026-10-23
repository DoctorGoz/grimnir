#!/usr/bin/env bash
# promptfoo-wrapper.sh — Run promptfoo adversarial evaluation against an LLM target
# Usage: bash scripts/promptfoo-wrapper.sh <TARGET_URL> [CONFIG] [API_KEY] [--project-dir DIR]
#
# Generates a promptfoo config from templates, runs eval, and writes results.
# Supports configs: rag (default), chat, or path to custom YAML.
# Integrates with engagement directory structure via --project-dir.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROMPTFOO_DIR="$SCRIPT_DIR"

TARGET="${1:?Usage: promptfoo-wrapper.sh <TARGET_URL> [rag|chat|CONFIG_PATH] [API_KEY] [--project-dir DIR]}"
CONFIG="${2:-rag}"
API_KEY="${3:-}"
PROJECT_DIR=""

# Parse --project-dir
shift 2>/dev/null || true
while [[ $# -gt 0 ]]; do
    case "$1" in
        --project-dir)
            PROJECT_DIR="${2:-}"
            shift 2
            ;;
        *)
            if [[ -z "$API_KEY" || "$API_KEY" == "--project-dir" ]]; then
                API_KEY="${1:-}"
            fi
            shift
            ;;
    esac
done

# Resolve config template
case "$CONFIG" in
    rag)
        CONFIG_TEMPLATE="$PROMPTFOO_DIR/configs/rag-eval-config.yaml.template"
        ;;
    chat)
        CONFIG_TEMPLATE="$PROMPTFOO_DIR/configs/chat-eval-config.yaml.template"
        ;;
    *.yaml|*.yml)
        CONFIG_TEMPLATE="$CONFIG"
        ;;
    *)
        echo "ERROR: Unknown config '$CONFIG'. Use 'rag', 'chat', or path to YAML."
        exit 1
        ;;
esac

if [[ ! -f "$CONFIG_TEMPLATE" ]]; then
    echo "ERROR: Config template not found: $CONFIG_TEMPLATE"
    exit 1
fi

# Set output directory
if [[ -n "$PROJECT_DIR" ]]; then
    OUTPUT_DIR="$PROJECT_DIR/artemis/recon/promptfoo-$(date +%Y%m%d-%H%M%S)"
else
    OUTPUT_DIR="${PROMPTFOO_DIR}/output/$(date +%Y%m%d-%H%M%S)"
fi
mkdir -p "$OUTPUT_DIR"

# Generate config from template
EVAL_CONFIG="$OUTPUT_DIR/eval-config.yaml"
TARGET_NAME="${TARGET#https://}"
TARGET_NAME="${TARGET_NAME%%/*}"

echo "=== ARTEMIS promptfoo Evaluation ==="
echo "Target:     $TARGET"
echo "Config:     $CONFIG"
echo "Output:     $OUTPUT_DIR"
echo "Started:    $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo ""

# Check promptfoo availability
if ! npx --no-install promptfoo --version >/dev/null 2>&1; then
    echo "[!] promptfoo not installed locally. Installing..."
    cd "$PROMPTFOO_DIR"
    npm install --no-audit --no-fund 2>&1 | tail -3
    echo "[+] promptfoo installed"
fi

# Build env vars for template substitution
export PROMPTFOO_TARGET_URL="$TARGET"
export PROMPTFOO_API_KEY="${API_KEY:-}"
export TARGET_NAME="$TARGET_NAME"
export OUTPUT_DIR="$OUTPUT_DIR"

# Copy template and substitute env vars
cp "$CONFIG_TEMPLATE" "$EVAL_CONFIG"

# Simple env var substitution in the config ({{VAR}} -> value)
# Preserve the template for sections that promptfoo handles natively
sed -i "s|{{PROMPTFOO_TARGET_URL}}|$PROMPTFOO_TARGET_URL|g" "$EVAL_CONFIG"
sed -i "s|{{PROMPTFOO_API_KEY}}|$PROMPTFOO_API_KEY|g" "$EVAL_CONFIG"
sed -i "s|{{TARGET_NAME}}|$TARGET_NAME|g" "$EVAL_CONFIG"
sed -i "s|{{OUTPUT_DIR}}|$OUTPUT_DIR|g" "$EVAL_CONFIG"

echo "[+] Config generated: $EVAL_CONFIG"
echo ""

# Run promptfoo eval
echo "=== Running Evaluation ==="
cd "$PROMPTFOO_DIR"

EVAL_EXIT=0
npx promptfoo eval \
    --config "$EVAL_CONFIG" \
    --output "$OUTPUT_DIR/promptfoo-results.json" \
    --max-concurrency 2 \
    --delay 1000 \
    2>&1 || EVAL_EXIT=$?

echo ""
echo "=== Evaluation Complete (exit: $EVAL_EXIT) ==="
echo "Results: $OUTPUT_DIR/promptfoo-results.json"
echo "Config:  $EVAL_CONFIG"
echo ""

# Summary
if [[ -f "$OUTPUT_DIR/promptfoo-results.json" ]]; then
    TOTAL_TESTS=$(python3 -c "
import json
with open('$OUTPUT_DIR/promptfoo-results.json') as f:
    data = json.load(f)
results = data.get('results', [])
total = len(results)
passed = sum(1 for r in results if r.get('success', False))
failed = total - passed
print(f'{total}')
" 2>/dev/null || echo "?")
    echo "Tests run: $TOTAL_TESTS"
    echo ""
    echo "View interactive report:"
    echo "  cd $(dirname "$0") && npx promptfoo view -o $OUTPUT_DIR/promptfoo-results.json"
fi

if [[ $EVAL_EXIT -ne 0 ]]; then
    echo ""
    echo "[!] Some evaluations failed or promptfoo exited with code $EVAL_EXIT."
    echo "    Review results at $OUTPUT_DIR/promptfoo-results.json"
fi
