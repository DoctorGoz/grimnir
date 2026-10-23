#!/usr/bin/env bash
# init-engagement.sh — Initialize a new GenAI Red Team engagement workspace
#
# Usage: ./scripts/init-engagement.sh <engagement_id> [target_name]
# Example: ./scripts/init-engagement.sh ENG-2025-042 "AcmeChatbot"

set -euo pipefail

ENGAGEMENT_ID="${1:?Usage: $0 <engagement_id> [target_name]}"
TARGET_NAME="${2:-unnamed-target}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SKILL_DIR="$(dirname "$SCRIPT_DIR")"
WORKSPACE="${SKILL_DIR}/engagements/${ENGAGEMENT_ID}"

if [[ -d "$WORKSPACE" ]]; then
    echo "ERROR: Engagement workspace already exists at $WORKSPACE"
    echo "Use a different ID or remove the existing workspace."
    exit 1
fi

echo "🛡️  Initializing GenAI Red Team Engagement: ${ENGAGEMENT_ID}"
echo "    Target: ${TARGET_NAME}"
echo "    Workspace: ${WORKSPACE}"
echo ""

# Create directory structure
mkdir -p "${WORKSPACE}"/{findings,evidence,payloads,recon}

# Copy templates
cp "${SKILL_DIR}/templates/scope-template.md" "${WORKSPACE}/scope.md"
cp "${SKILL_DIR}/templates/test-plan-template.md" "${WORKSPACE}/test-plan.md"
cp "${SKILL_DIR}/templates/report-template.md" "${WORKSPACE}/report.md"

# Replace placeholders in scope document
sed -i "s/ENG-YYYY-NNN/${ENGAGEMENT_ID}/g" "${WORKSPACE}/scope.md"
sed -i "s/\[System Name\]/${TARGET_NAME}/g" "${WORKSPACE}/scope.md"

# Replace placeholders in report
sed -i "s/ENG-YYYY-NNN/${ENGAGEMENT_ID}/g" "${WORKSPACE}/report.md"
sed -i "s/\[System Name\]/${TARGET_NAME}/g" "${WORKSPACE}/report.md"

# Replace placeholders in test plan
sed -i "s/ENG-YYYY-NNN/${ENGAGEMENT_ID}/g" "${WORKSPACE}/test-plan.md"
sed -i "s/\[System Name\]/${TARGET_NAME}/g" "${WORKSPACE}/test-plan.md"

# Create empty recon notes
cat > "${WORKSPACE}/recon/recon-notes.md" << 'RECON'
# Reconnaissance Notes

## Target Information
- **System Name**: [TBD]
- **Model Provider**: [TBD]
- **Model Version**: [TBD]
- **Framework**: [TBD]
- **Deployment**: [TBD]

## Endpoints Discovered
- [List endpoints]

## Guardrails / Filters Observed
- [List observed safety mechanisms]

## API Surface
- [Describe API endpoints, parameters, rate limits]

## Tools / Plugins Available
- [For agentic systems: enumerate available tools]

## Observations
- [General observations during recon]
RECON

# Create engagement log
cat > "${WORKSPACE}/engagement-log.md" << LOG
# Engagement Log — ${ENGAGEMENT_ID}

## ${TARGET_NAME}

### $(date '+%Y-%m-%d %H:%M') — Engagement Initialized
- Workspace created at ${WORKSPACE}
- Templates deployed
- Ready for scoping phase

---

LOG

# Create findings index
cat > "${WORKSPACE}/findings/INDEX.md" << INDEX
# Findings Index — ${ENGAGEMENT_ID}

| ID | Title | OWASP Cat | Severity | Status |
|----|-------|-----------|----------|--------|
| _(none yet)_ | | | | |

**Total Findings**: 0
**Critical**: 0 | **High**: 0 | **Medium**: 0 | **Low**: 0 | **Info**: 0
INDEX

echo "✅ Engagement workspace initialized successfully!"
echo ""
echo "📁 Workspace structure:"
find "${WORKSPACE}" -type f | sort | sed "s|${WORKSPACE}/|    |"
echo ""
echo "📋 Next steps:"
echo "   1. Complete the scope document: ${WORKSPACE}/scope.md"
echo "   2. Begin reconnaissance: ${WORKSPACE}/recon/recon-notes.md"
echo "   3. Finalize test plan: ${WORKSPACE}/test-plan.md"
echo "   4. Start assessment using /assess commands"
