Generate GenAI security assessment report for current engagement

Delegates to report-generator agent.

## Steps
1. Read all findings from engagement/findings/ directory
2. Read recon-notes.md and scope.md for context
3. Deduplicate findings and verify evidence completeness
4. Classify by OWASP category and assign final severity
5. Generate report from templates/report-template.md
6. Include:
   - Executive summary with risk rating (A-F)
   - Findings organized by severity
   - Attack narratives for chained findings
   - OWASP LLM Top 10 coverage matrix
   - OWASP Agentic Top 10 coverage matrix (if applicable)
   - Remediation roadmap (immediate, short-term, long-term)
   - Framework compliance summary

Save to engagement/report.md

Optional: /report executive — generate executive summary only
