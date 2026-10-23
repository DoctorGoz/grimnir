---
name: graphql-audit
description: GraphQL API security audit covering introspection, authorization bypass, batching attacks, injection, and IDOR.
allowed-tools: Read, Grep, Glob, Bash
---
# GraphQL Security Audit Skill

## Testing Sequence
1. Confirm GraphQL with __typename query
2. Fingerprint engine: graphw00f -t ENDPOINT
3. Introspection: graphqlmap -u ENDPOINT, then dump_new
4. If disabled: specter/scripts/graphql-probe.py ENDPOINT [--token T] [--depth 2] [--delay 0.2] (field-suggestion oracle; writes schema.json; read-only + budget/pace-bounded)
5. Test unauthenticated access to all queries/mutations
6. IDOR via variable ID manipulation
7. Nested authorization bypass through relationships
8. Alias-based batching (rate limit bypass)
9. Array-based batching
10. Query depth limits (DoS)
11. Injection through query arguments
12. Mutation mass assignment (role, isAdmin, credits)
13. CSRF on mutations
14. Error message verbosity

## Tools
graphqlmap, graphw00f, graphql-probe.py (introspection-off schema recovery), CrackQL, GraphQL Cop, InQL

## Validate & Promote

Findings from this skill are born `theoretical` (see the validation layer in the repo-root `CLAUDE.md`). They do NOT enter a report or external submission until promoted to `confirmed` with `scripts/validate-finding.sh`, after the independent check below.

- **Independent check for this class:** For cross-user/authz issues, use the BOLA negative control (distinguishable victim data + owner positive control). For introspection/DoS, show the actual data or cost impact, not just that the query ran.
- Only `confirmed` findings ship. `validated` = reproduced but not independently confirmed.

```bash
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent specter \
  --id SPE-NNN --state confirmed --method negative-control \
  --negative-control "<what you proved, and the control result>" --by specter
```
