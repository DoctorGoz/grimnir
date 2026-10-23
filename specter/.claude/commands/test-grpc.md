Run gRPC security testing against $ARGUMENTS (host:port)

Delegate to grpc-tester subagent:

## Discovery
1. Test reflection: grpcurl -plaintext $ARGUMENTS list
2. Enumerate all services and methods
3. Describe request/response types

## Security Testing
1. Plaintext vs TLS enforcement
2. Auth bypass on each RPC (no token, expired, wrong role)
3. Injection through RPC fields (SQLi, command injection)
4. Metadata header injection (x-user-role, x-user-id)
5. Large message payloads for resource exhaustion

Save to reports/grpc-audit.md
