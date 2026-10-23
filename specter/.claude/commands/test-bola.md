Test for BOLA/IDOR on $ARGUMENTS

Requires two user sessions (user_a and user_b tokens).

## Steps
1. Request endpoint as User A with User A object ID
2. Replay with User B token but User A object ID
3. If User B sees User A data = BOLA confirmed
4. Test bidirectionally
5. Test across HTTP methods (GET, PUT, PATCH, DELETE)
6. Test sequential IDs and encoded IDs
7. For GraphQL: change ID variables in queries/mutations

## Output per finding
Endpoint, method, object ID, both request/response pairs, data exposed, severity.
