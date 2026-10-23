Run agentic AI abuse testing against $ARGUMENTS

Delegates to agent-abuse-tester agent for ASI01-ASI10 assessment.

## Test Categories
1. Goal hijacking (ASI01): objective override, gradual drift, conflicting goals
2. Tool misuse (ASI02): parameter injection, tool chaining, unauthorized access
3. Privilege escalation (ASI03): permission escalation, identity impersonation, cross-tenant
4. Uncontrolled actions (ASI04): missing confirmations, recursive behavior, irreversible actions
5. Multi-agent attacks (ASI05): cross-agent injection, orchestrator manipulation
6. Memory attacks (ASI06): memory injection, extraction, manipulation
7. Communication (ASI07): unencrypted channels, message tampering
8. Cascading failures (ASI08): error propagation, single points of failure
9. Trust exploitation (ASI09): social engineering via agent, authority impersonation
10. Rogue agents (ASI10): unauthorized operation, shadow actions

## Automated Testing
- Tool enumeration: bash scripts/agent-tool-enum.sh $ARGUMENTS
- Tool names: wordlists/agent-tool-names.txt

Save findings with: bash scripts/new-finding.sh "TITLE" "ASI0X" "SEVERITY"
