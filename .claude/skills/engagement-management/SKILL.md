---
name: engagement-management
description: Engagement lifecycle management — creating, tracking, and closing penetration testing engagements across multiple specialist agents.
allowed-tools: Read, Grep, Glob, Bash
---

# Engagement Management Skill

## When to Use
- Creating new engagements
- Tracking progress across agents
- Merging and deduplicating findings
- Closing engagements and archiving

## Create Engagement

All engagement data lives under `$GRIMNIR_WORKSPACE/$PROJECT/` (default `~/workspace/$PROJECT/`),
always as absolute paths. Resolve the root once, then pass the resolved value.

```bash
PROJECT_DIR="${GRIMNIR_WORKSPACE:-$HOME/workspace}/$PROJECT_NAME"
mkdir -p "$PROJECT_DIR"/{recon,findings,evidence,reports,logs}
mkdir -p "$PROJECT_DIR"/specter/{recon,findings,reports}
mkdir -p "$PROJECT_DIR"/artemis/{recon,findings,reports}
mkdir -p "$PROJECT_DIR"/hunter/{recon,findings,reports}
mkdir -p "$PROJECT_DIR"/nimbus/{recon,findings,reports}
mkdir -p "$PROJECT_DIR"/nomad/{recon,findings,reports}

# Initialize engagement state
bash scripts/state.sh init \
  --project-dir "$PROJECT_DIR" \
  --engagement-id "ENG-$(date +%Y%m%d)-$PROJECT_NAME" \
  --project-name "$PROJECT_NAME" \
  --target "https://target.example.com" \
  --agents "specter,artemis"

# Create intel feed
touch "$PROJECT_DIR/intel.jsonl"
```

## Track Progress

**Preferred: Use state.sh** (if `state.json` exists):
```bash
bash scripts/state.sh summary --project-dir "$PROJECT_DIR"
bash scripts/intel.sh summary --project-dir "$PROJECT_DIR"
```

**Fallback: File counting** (legacy engagements):
```bash
for a in hunter specter artemis nimbus nomad; do
  printf '%s: ' "$a"; ls "$PROJECT_DIR"/$a/findings/*.md 2>/dev/null | wc -l
done
test -f "$PROJECT_DIR/report.md" && echo "Report complete" || echo "No report yet"
```

## Create Findings

Use `scripts/finding.sh` to create structured JSON findings:
```bash
bash scripts/finding.sh \
  --project-dir "$PROJECT_DIR" \
  --agent specter \
  --severity high \
  --title "Finding Title" \
  --description "Description" \
  --category API1 \
  --step "Step 1" --step "Step 2" \
  --remediation "Fix recommendation"
```

Claim-split verification (optional): seed claims with `--claim "kind|severity|text|control"`
(repeatable; one `base`, any `escalation`) and scaffold an operator repro with `--repro`
(`$PROJECT_DIR/repro/<ID>.sh`). Settle claims with
`validate-finding.sh ... --claim-verdict C2=refuted`; confirming requires the base claim
`survived` and records `floor_severity`. `python3 scripts/finding_state.py show --project-dir
"$PROJECT_DIR" --id SPE-001` prints claims and floor; `python3 scripts/fresh-eyes.py
--project-dir "$PROJECT_DIR" --id SPE-001` launches a context-free reviewer (never blocks
filing); `check-report-hygiene.sh --finding F.json report.md` warns if severity exceeds the
floor. File at the floor (hunting Rule 35).

## Intel Feed

Log cross-agent discoveries:
```bash
# Add intel
bash scripts/intel.sh add --project-dir "$PROJECT_DIR" --agent hunter \
  --type service --confidence confirmed \
  --host 10.10.10.50 --port 443 --protocol tcp \
  --tag needs-specter

# Route intel to agents
bash scripts/intel.sh route --project-dir "$PROJECT_DIR" --for-agent specter
```

## Merge Findings
When agents complete:
1. Copy all findings to `$PROJECT_DIR/findings/` (unified directory)
2. Deduplicate (same vuln from different angles = one finding, combined evidence)
3. Ids are AGT-NNN (agent prefix + 3 digits); finding.sh assigns them, do not hand-number
4. Sort by severity: Critical > High > Medium > Low > Info

## Cross-Domain Chains to Watch For
- API auth bypass > LLM access > system prompt leak > targeted injection
- Prompt injection > agent SSRF > internal API access > data exfil
- System prompt reveals internal endpoints > Specter finds BOLA on them
- XSS via LLM output > steal session > API access with stolen token
- Network credential reuse (Hunter) > API access (Specter) > LLM manipulation (ARTEMIS)

## Close Engagement
1. Verify all phases complete for assigned agents. Run the coverage reconciler and account for every gap before wind-down:
   ```bash
   python3 scripts/coverage.py --project-dir "$PROJECT_DIR" --gate
   ```
   Any **REACHABLE + UNTOUCHED** item must reach a terminal state before shelving/closing: test it, or log a conscious skip with a reason (`scripts/decision-log.sh record --project-dir "$PROJECT_DIR" --type skip --reason ...`). This is the recon-side analog of the evidence gate — it blocks a *silent* wind-down, not the testing (Rule 25).

   The gate also fails when `scope.md` is missing or yields no parseable in-scope assets. Zero reconciled items is not a clean sheet — it means the surface was never enumerated, so there is nothing to be untouched. Fix the intake and re-run rather than closing on a vacuous pass.
2. Generate unified report (`/report`)
3. Update state:
   ```bash
   jq '.report_generated = true | .report_path = "report.md"' \
     "$PROJECT_DIR/state.json" > tmp.$$.json && mv tmp.$$.json "$PROJECT_DIR/state.json"
   ```
4. **Write down what you learned.** Keep the lesson in your own notes (operator memory), generalised so a later session that never saw this program can use it. Record what would make the engagement worth re-opening.
5. Archive: `tar czf "$PROJECT_NAME.tar.gz" -C "${GRIMNIR_WORKSPACE:-$HOME/workspace}" "$PROJECT_NAME/"`
