Show engagement status across all agents

## Steps
1. Identify the project directory `$PROJECT_DIR` for the current or specified engagement
2. **If `state.json` exists**, use the structured state system:
   ```bash
   bash scripts/state.sh summary --project-dir "$PROJECT_DIR"
   ```
   Then show intel routing queue:
   ```bash
   bash scripts/intel.sh summary --project-dir "$PROJECT_DIR"
   ```
   Then run the coverage reconciler to surface untouched high-value surface:
   ```bash
   python3 scripts/coverage.py --project-dir "$PROJECT_DIR"
   ```
   Highlight any **REACHABLE + UNTOUCHED** items — in-scope assets / high-value intel that recon found but nothing has tested, consciously skipped, or gated yet (Rule 25).
   Then check for proof that is already on disk but not yet promoted:
   ```bash
   bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --scan
   ```
   Anything listed here is a finished lane that has not been filed. A confirmed artifact
   sitting beside a `theoretical` finding is the cheapest win available and the easiest
   to lose -- duplicates are decided in hours (hunting Rule 29). Promote each with
   `--from-evidence` before opening anything new. If a bare legacy id reports AMBIGUOUS,
   two findings share it; read the artifact's reproducer to see which one it belongs to.


3. **If `state.json` does NOT exist** (legacy engagement), fall back to file counting:
   - Read `$PROJECT_DIR/scope.md` for engagement context
   - Read `$PROJECT_DIR/classification.md` for target type
   - Count findings in `$PROJECT_DIR/specter/findings/`, `$PROJECT_DIR/artemis/findings/`, and `$PROJECT_DIR/hunter/findings/`
   - Check for `$PROJECT_DIR/report.md` (completed?)

4. Display status summary and suggest next action:
   - If agents are still in progress → suggest checking specific agent status
   - If all agents complete but no report → suggest `/report`
   - If intel items need routing → highlight unprocessed intel count
