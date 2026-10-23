Run GraphQL security audit against $ARGUMENTS

Delegate to graphql-tester subagent:

## Enumeration
1. Confirm endpoint with __typename query
2. Fingerprint engine with graphw00f
3. Attempt introspection (if disabled, recover the schema with specter/scripts/graphql-probe.py — the field-suggestion oracle; graphql-enum.sh auto-runs it)

## Authorization
1. Test queries/mutations without auth
2. Test nested query auth bypass
3. Test IDOR via ID manipulation
4. Test node/nodes interface

## Batching and DoS
1. Array batching and alias batching
2. Query depth limits
3. Response time degradation

## Injection and Mass Assignment
1. SQLi through resolver arguments
2. NoSQLi with MongoDB operators
3. CSRF on mutations
4. Unauthorized fields in mutation inputs

Save to reports/graphql-audit.md
