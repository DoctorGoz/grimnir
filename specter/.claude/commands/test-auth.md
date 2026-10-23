Run authentication and authorization testing against $ARGUMENTS

Delegate to the auth-tester subagent:

## JWT Testing
1. Decode and analyze token structure
2. Run jwt_tool attacks: alg none, key confusion, null sig, JWKS injection
3. Brute-force HMAC secret with wordlists/jwt-secrets.txt
4. Test claim manipulation (role escalation, user ID swap)

## OAuth Testing
1. Fetch /.well-known/openid-configuration
2. Test redirect_uri, state, scope, PKCE

## BOLA/IDOR Testing
1. Identify endpoints with object IDs
2. Test horizontal and vertical access
3. Test across HTTP methods

## BFLA Testing
1. Map admin vs user endpoints
2. Attempt admin functions with user tokens

Save to reports/auth-findings.md
