---
name: bola-testing
description: Test for Broken Object Level Authorization (BOLA/IDOR) - OWASP API1:2023. Use when testing any endpoint with object identifiers for unauthorized access.
allowed-tools: Read, Grep, Glob, Bash
---

# BOLA/IDOR Testing Skill (API1:2023)

BOLA is the number 1 most common API vulnerability, present in ~40% of API attacks.

## Prerequisites
- Two authenticated user contexts (User A and User B) at same privilege level
- One admin context for vertical testing (if available)

## Methodology

### Step 1: Identify Object References

**Where the reference hides.** Paths, query params, JSON bodies, form-data, headers,
cookies, JWT claims, GraphQL arguments, WebSocket frames, gRPC messages. A reference in
the body or a header is the one most often missed, because the URL looks clean.

**What a reference looks like.** Integers; UUID/ULID/CUID; Snowflake; slugs; composite
keys (`{orgId}:{userId}`); opaque base64/hex blobs. Decode the opaque ones before
assuming they are unguessable -- base64 of a sequential integer is a sequential integer.

**Relationship params are references too**: `parentId`, `ownerId`, `accountId`,
`tenantId`, `organization`, `teamId`, `projectId`, `subscriptionId`. These often skip the
object-level check entirely because the handler validates the child and trusts the parent.

**Expansion / projection knobs widen the surface** and are frequently unauthorized
because the check runs on the route, not the resolver or serializer:
`fields`, `include`, `expand`, `projection`, `with`, `select`, `populate`.

**Find the parameters that are not documented.** Hidden filters like `?include_deleted=1`,
`?as_user=`, `?owner_id=` are exactly the ones with no authorization behind them:

```bash
arjun -u 'https://TARGET/api/v1/orders' --headers "Authorization: Bearer $TOKEN_A"
arjun -u 'https://TARGET/api/v1/orders' -m POST --headers "Authorization: Bearer $TOKEN_A"
```

**Seed victim ids from the endpoints that hand them out.** List/search/suggest/export
endpoints, activity feeds, notifications, and error messages leak object ids belonging to
other tenants; that is usually easier than guessing. Time-ordered ids (UUIDv1, ULID,
Snowflake) are guessable within a window once you know one timestamp.

**High-value objects**, roughly in yield order: exports and reports (CSV/PDF/ZIP),
invoices / payment methods / transactions, messages and mailboxes, audit logs, file and
object-storage keys (including signed URLs and share links), background-job and
import/export ids, impersonation and session-management endpoints, admin/staff tooling.

### Step 1b: Vary the reference, not just its value
Before concluding an endpoint is scoped, try the mutations that defeat a naive check:

- **Type juggling** -- `{"id":123}` vs `{"id":"123"}`, scalar vs `[123]` vs `{"id":{"$ne":null}}`
- **Parameter pollution** -- `?id=OWN&id=VICTIM` and the reverse; JSON duplicate keys
  `{"id":"OWN","id":"VICTIM"}`. Front-end and back-end often disagree on which wins, and
  the check runs on one while the query runs on the other
- **Case and alias** -- `userId` / `userid` / `USER_ID` / `user_id`, plus alternates like
  `resourceId`, `targetId`, `account`
- **Edge values** -- `null`, empty, `0`, `-1`, `MAX_INT`, scientific notation
- **Wrapped paths in virtual filesystems** -- `/files/user_123/../../user_456/report.csv`

A hit from any of these is still only a candidate. It goes through the same negative
control below -- a parser quirk that returns a differently-shaped error is not a bypass.

### Step 2: Horizontal BOLA (same privilege level)
For EACH endpoint with an object ID:
1. As User A, request User A resource -> capture response
2. As User A, request User B resource ID -> capture response
3. If User A receives User B data -> BOLA **candidate** (not yet confirmed)

> Identical-looking responses are NOT proof. Before confirming, run the negative
> control in "Validate & Promote" below: User B's data must be *distinguishable*,
> and a non-existent ID must behave differently from a real victim ID. Many APIs
> return the same shaped object (empty/placeholder) regardless of authorization.

### Step 3: Cross-Method Testing
Test same object ID across GET, PUT, PATCH, DELETE, POST.
Auth may be enforced on GET but not on DELETE.

### Step 4: Vertical BOLA (privilege escalation)
Access admin-only resources with regular user token.

### Step 5: ID Enumeration
Sequential integers: iterate range. UUIDs: check for leaks in other responses.

## Common BOLA Locations
User profiles, orders, documents, messages, settings, invoices, reports

## Evidence Format
Document: endpoint, user tokens, request/response pairs, impact assessment.

## Validate & Promote

Findings from this skill are born `theoretical` (see the validation layer in the repo-root `CLAUDE.md`). They do NOT enter a report or external submission until promoted to `confirmed` with `scripts/validate-finding.sh`, after the independent check below.

- **Independent check for this class:** A non-existent ID must return 404/empty while the victim ID returns the victim's DISTINGUISHABLE data; include an owner positive control. Identical-shaped responses are not proof.
- Only `confirmed` findings ship. `validated` = reproduced but not independently confirmed.

**Produce the proof with the harness, then promote from it.** The primitive writes
`$PROJECT_DIR/evidence/<id>/*.json`; `--from-evidence` reads that record and promotes
only if it says `confirmed`, carrying the class, control and method across:

```bash
# 1. record the class up front so the evidence gate arms itself
bash scripts/finding.sh --project-dir "$PROJECT_DIR" --agent specter --severity high \
  --title '<what you proved>' --description '<...>' --impact '<...>' --class bola

# 2. produce the proof
python3 scripts/confirm/authz-confirm.py --finding-id SPE-NNN --project-dir "$PROJECT_DIR" \
  --url 'https://TARGET/api/orders/{id}' -H "Authorization: Bearer $TOKEN_A" \
  --own-id OWN --victim-id VICTIM --nonexistent-id 999999999 --victim-marker 'VICTIM_NAME'

# 3. promote from the artifact
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent specter \
  --id SPE-NNN --from-evidence
```

Promoting by hand (below) is the fallback for when the harness cannot reach the target.

```bash
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent specter \
  --id SPE-NNN --state confirmed --method negative-control \
  --negative-control "<what you proved, and the control result>" --by specter
```
