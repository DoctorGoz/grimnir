Define or review engagement scope for $ARGUMENTS

## Steps
1. If the project directory `$PROJECT_DIR` exists, read existing scope.md
2. If new, interview the operator or parse provided details:
   - Target URL(s) and endpoints
   - Target type classification
   - Authentication credentials (user A, user B for auth testing)
   - In-scope and out-of-scope boundaries
   - Rate limit requirements
   - Proxy configuration (if any)
   - Testing window and deadline
   - Special considerations (production vs staging, data sensitivity)
3. Confirm authorization status
4. Save scope document to `$PROJECT_DIR/scope.md`
5. Generate or update the test plan based on scope, save to `$PROJECT_DIR/test-plan.md`
