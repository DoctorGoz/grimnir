Generate unified engagement report

Delegates to report-compiler agent.

## Steps
1. Identify the project directory `$PROJECT_DIR` for the current or specified engagement
2. Collect all findings from `$PROJECT_DIR/specter/findings/`, `$PROJECT_DIR/artemis/findings/`, `$PROJECT_DIR/hunter/findings/`, `$PROJECT_DIR/nimbus/findings/`, and `$PROJECT_DIR/nomad/findings/`
3. **Coverage advisory (SOFT gate)** — run the recon-coverage reconciler before compiling:
   ```bash
   python3 scripts/coverage.py --project-dir "$PROJECT_DIR" --gate
   ```
   A non-zero exit lists in-scope assets / high-value intel that reached no terminal state (untested, not consciously skipped, not gated). Like the 7-Question gate this is advisory — it does NOT block the report. For each item: either test it, or log a skip-decision with a reason (`scripts/decision-log.sh record --project-dir "$PROJECT_DIR" --type skip --reason ...`), then note the residual coverage in the report's scope/limitations section so a reader knows what was and was not covered (Rule 25).
4. **Promote what is already proven (HARD-ish gate — do this BEFORE compiling)**:
   ```bash
   bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --scan
   ```
   Every finding listed here has a confirmed artifact from `scripts/confirm/` on disk and
   a `validation.state` that is not yet `confirmed` — which means the validation gate in
   step 5 will drop it from the report body even though the proof exists. Promote each
   with `--from-evidence` before compiling, or the report understates the engagement by
   exactly the work that was hardest to do:
   ```bash
   bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent <owner> --id <ID> --from-evidence
   ```
   If a bare legacy id reports AMBIGUOUS, two findings share it — read the artifact's
   reproducer to decide which one owns it, and pass that agent explicitly.

5. Delegate to report-compiler agent with the absolute `$PROJECT_DIR` path for:
   - Validation gate (exclude `theoretical`/`refuted` findings from the body; only `confirmed`/`validated` are reported)
   - Finding deduplication
   - Cross-domain attack chain identification
   - Unified severity classification
   - Multi-framework compliance mapping (include only the frameworks relevant to the agents in scope: OWASP API + WSTG for Specter, LLM + Agentic + MITRE ATLAS for ARTEMIS, MITRE ATT&CK + PTES for Hunter, CIS Benchmarks + ATT&CK Cloud for Nimbus, OWASP MASVS for Nomad)
   - Remediation roadmap
6. Generate report from templates/combined-report.md
7. Save to `$PROJECT_DIR/report.md`
8. **Update engagement state** (if `state.json` exists):
   ```bash
   # Mark report as generated
   jq --arg path "report.md" '.report_generated = true | .report_path = $path' \
     "$PROJECT_DIR/state.json" > tmp.$$.json && mv tmp.$$.json "$PROJECT_DIR/state.json"
   ```

Optional arguments:
- `executive` — generate executive summary only
- Project name — specify which project to report on (e.g., `withg.ai`)
