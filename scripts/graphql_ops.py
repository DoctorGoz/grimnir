#!/usr/bin/env python3
"""graphql_ops.py — is this GraphQL request a read? Shared by the crawler, the traffic export, lane
synthesis, and the confirm oracles, so a request is judged the same way everywhere.

GraphQL sends reads and writes to the same POST endpoint, so the method says nothing. The body does:

  query text      `{"query": "query X {...}"}` or a bare `{...}`  ->  query (a read, definitive)
                  `mutation ...` / `subscription ...`               ->  mutation / subscription
  name only       `{"operation": "X"}`, `{"operationName": "X", "extensions": {"persistedQuery": ...}}`,
                  `{"id": "..."}`: the server holds the text, so only the name is known. A name reads
                  as a read only when it has a read shape (Get..., ...Info, ...Settings, ...Queue) AND
                  none of its words is a write verb; anything else is `write-likely` or `unknown`.

`is_read()` is the gate: True only for `query` and `read-likely`. A name-only verdict is a heuristic,
so callers that act on it (the crawler letting a request out) do so only when the operator opts in.

  graphql_ops.py classify '<json body>'
  graphql_ops.py selftest
"""
from __future__ import annotations

import json
import re
import sys

# Words that make an operation a write wherever they appear in its name (CamelCase or snake_case).
WRITE_WORDS = frozenset("""
create update delete remove set add approve ban unban mute unmute lock unlock send submit post report
join leave subscribe unsubscribe follow unfollow block unblock store enroll expose mark save unsave
hide unhide vote upvote downvote award gild invite accept decline reject edit upload request toggle
enable disable reset revoke claim redeem purchase pay buy checkout transfer withdraw move rename
archive unarchive pin unpin sticky distinguish flair assign unassign grant promote demote kick
dismiss resolve snooze ignore restore undo cancel confirm verify register login logout signup
track record increment decrement clear sync publish unpublish schedule mutate modify write insert
upsert replace import trigger execute run start stop complete finish close open acknowledge ack
""".split())
# A read shape: the name starts with a read verb or ends with a noun that names what it fetches.
READ_PREFIX = re.compile(r"^(get|fetch|list|search|query|load|read|find|lookup|view|show|check|count|"
                         r"describe|browse|resolve_?read)", re.I)
READ_SUFFIX = re.compile(r"(info|infos|details?|list|items?|feed|settings|config|configs|count|counts|"
                         r"status|stats|insights|queue|queues|log|logs|rules|members|moderators|users?|"
                         r"profiles?|search|query|data|summary|overview|metadata|preferences|permissions|"
                         r"categories|achievements|styles|redditors|posts|comments|messages|"
                         r"conversations|notifications|history|reasons|tags|types|options|templates|"
                         r"eligibility|panel|widgets?|chart|traffic|requests_?list)$", re.I)


def words(name: str) -> list[str]:
    """CamelCase / snake_case / kebab words, lowercased: 'ModQueueItems' -> [mod, queue, items]."""
    parts = re.findall(r"[A-Z]+(?=[A-Z][a-z]|\d|\b|_)|[A-Z]?[a-z]+|[A-Z]+|\d+", name or "")
    return [p.lower() for p in parts]


def _operations(doc) -> list[dict]:
    if isinstance(doc, list):
        return [d for d in doc if isinstance(d, dict)]
    return [doc] if isinstance(doc, dict) else []


def op_name(op: dict) -> str:
    return str(op.get("operationName") or op.get("operation") or op.get("op") or "")


def classify_op(op: dict) -> tuple[str, str]:
    """(kind, why) for one operation object."""
    q = op.get("query")
    if isinstance(q, str) and q.strip():
        body = re.sub(r"#[^\n]*", "", q).lstrip()
        m = re.match(r"(query|mutation|subscription)\b", body)
        if m:
            return m.group(1), f"query text is a {m.group(1)}"
        if body.startswith("{"):
            return "query", "query text is an anonymous query"
        if body.startswith("fragment"):
            # Fragments first, then the operation: find the first operation keyword.
            m = re.search(r"(?m)^\s*(query|mutation|subscription)\b", body)
            if m:
                return m.group(1), f"query text is a {m.group(1)}"
        return "unknown", "query text has no operation keyword"
    name = op_name(op)
    if not name:
        return "unknown", "no query text and no operation name"
    ws = words(name)
    hit = [w for w in ws if w in WRITE_WORDS]
    if hit:
        return "write-likely", f"operation name {name} has the write word '{hit[0]}'"
    # "SubredditInfoByName", "PostsForUser": the noun before a By/For/In/With clause is what it fetches.
    core = re.sub(r"(?<=[a-z0-9])(By|For|In|With|From|Of)[A-Z0-9]\w*$", "", name)
    if READ_PREFIX.match(name) or READ_SUFFIX.search(core):
        return "read-likely", f"operation name {name} has a read shape and no write word"
    return "unknown", f"operation name {name} has no read shape"


def classify(body) -> tuple[str, str]:
    """(kind, why) for a request body (str/bytes/parsed). A batch is a read only if every operation
    is; its kind is the least safe member's."""
    if isinstance(body, (bytes, bytearray)):
        body = body.decode("utf-8", "replace")
    if isinstance(body, str):
        try:
            body = json.loads(body)
        except json.JSONDecodeError:
            return "unknown", "body is not JSON"
    ops = _operations(body)
    if not ops:
        return "unknown", "body holds no operation"
    rank = {"query": 0, "read-likely": 1, "unknown": 2, "write-likely": 3, "subscription": 4, "mutation": 5}
    worst = max((classify_op(o) for o in ops), key=lambda kv: rank.get(kv[0], 2))
    return worst


def is_read(body) -> bool:
    return classify(body)[0] in ("query", "read-likely")


def is_graphql(url: str, body) -> bool:
    """A request worth classifying: a graphql-named path, or a JSON body shaped like an operation."""
    if "graphql" in (url or "").lower() or "/gql" in (url or "").lower():
        return True
    if isinstance(body, (bytes, bytearray)):
        body = body.decode("utf-8", "replace")
    if isinstance(body, str):
        try:
            body = json.loads(body)
        except json.JSONDecodeError:
            return False
    return any(("query" in o and isinstance(o.get("query"), str)) or "operationName" in o
               for o in _operations(body))


def names(body) -> list[str]:
    if isinstance(body, (bytes, bytearray)):
        body = body.decode("utf-8", "replace")
    if isinstance(body, str):
        try:
            body = json.loads(body)
        except json.JSONDecodeError:
            return []
    return [op_name(o) or "(anonymous)" for o in _operations(body)]


def selftest() -> int:
    cases = [
        ('{"query": "query Me { me { id } }"}', "query"),
        ('{"query": "{ me { id } }"}', "query"),
        ('{"query": "mutation M { del(id: 1) }"}', "mutation"),
        ('{"query": "fragment F on U { id }\\nquery Q { me { ...F } }"}', "query"),
        ('{"operation": "TrophyCategories", "variables": {}}', "read-likely"),
        ('{"operation": "ModQueueItems", "variables": {}}', "read-likely"),
        ('{"operation": "CreateAvatar", "variables": {}}', "write-likely"),
        ('{"operation": "DeleteAchievementNotifications"}', "write-likely"),
        ('{"operation": "ExposeVariant"}', "write-likely"),
        ('{"operation": "StoreUxtargetingAction"}', "write-likely"),
        ('{"operation": "ModerationAction"}', "unknown"),
        ('{"operation": "SubredditModLog"}', "read-likely"),
        ('{"operation": "SubredditInfoByName"}', "read-likely"),
        ('{"operation": "LogEvent"}', "unknown"),
        ('{"operationName": "GetUser", "extensions": {"persistedQuery": {"sha256Hash": "ab"}}}', "read-likely"),
        ('[{"operation": "SubredditRules"}, {"operation": "BanUser"}]', "write-likely"),
        ("not json", "unknown"),
    ]
    fails = 0
    for body, want in cases:
        got = classify(body)[0]
        ok = got == want
        fails += not ok
        print(f"  [{'PASS' if ok else 'FAIL'}] {want:<12} {body[:60]}" + ("" if ok else f"  (got {got})"))
    print(f"graphql_ops selftest: {'ALL PASS' if not fails else str(fails) + ' FAIL'}")
    return 1 if fails else 0


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "selftest":
        sys.exit(selftest())
    if len(sys.argv) >= 3 and sys.argv[1] == "classify":
        print(json.dumps(dict(zip(("kind", "why"), classify(sys.argv[2])))))
        sys.exit(0)
    print(__doc__)
    sys.exit(2)
