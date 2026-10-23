Analyze and attack JWT token: $ARGUMENTS

## Analysis
1. Decode: python3 jwt_tool.py $ARGUMENTS
2. Check algorithm, expiration, issuer, audience, custom claims

## Attack Suite
1. Algorithm none: python3 jwt_tool.py $ARGUMENTS -X a
2. Null signature: python3 jwt_tool.py $ARGUMENTS -X n
3. Key confusion: python3 jwt_tool.py $ARGUMENTS -X k -pk public.pem
4. JWKS injection: python3 jwt_tool.py $ARGUMENTS -X i
5. Brute-force: python3 jwt_tool.py $ARGUMENTS -C -d wordlists/jwt-secrets.txt
6. kid injection: python3 jwt_tool.py $ARGUMENTS -I -hc kid -hv "../../dev/null" -S hs256 -p ""
7. Claim tampering: elevate role/permissions claims

Summarize token structure, successful attacks, and recommendations.
