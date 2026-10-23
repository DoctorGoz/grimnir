# Grimnir lab demos

These labs drive Grimnir end to end against deliberately vulnerable applications, from
`/engage` to a `confirmed` finding whose evidence a triager could replay. They are the fastest
way to see the confirmation harness and the "findings are born theoretical" gate do real work.

| Lab | App | Exercises | Shipped playbooks / tools |
|-----|-----|-----------|---------------------------|
| [crapi.md](crapi.md) | OWASP crAPI | BOLA, mass assignment, missing-auth replay | `bola-cross-tenant`, `mass-assignment-bopla`, `missing-auth-replay` |
| [juice-shop.md](juice-shop.md) | OWASP Juice Shop | SQL injection, reflected XSS | `sqli-inband`, `xss-reflected` |
| [dvga.md](dvga.md) | Damn Vulnerable GraphQL App | introspection, GraphQL authz | `specter/scripts/graphql-probe.py`, `authz-confirm.py` |
| [mcp.md](mcp.md) | a vulnerable MCP server | tool poisoning, shadowing, tool-call authz | `artemis/scripts/mcp-*`, `scripts/confirm/mcp-confirm.py` |

## Before you start

- **Run every lab on the same isolated host as Grimnir.** These apps are intentionally
  exploitable. Use a dedicated VM, container, or disposable VPS, never your workstation, and
  bind the lab's ports to `localhost` so nothing is reachable off-box. See `SECURITY.md`.
- **You have authorization for these targets.** They are yours, running on your host. The same
  is not true of anything else, so the authorization statement in every engagement applies.
- Each lab assumes Docker and a cloned, launchable Grimnir (`cd grimnir && claude`). The test
  gate is optional for the labs but recommended once: `python3 -m pytest -q`.

## How to read a lab guide

Each guide has four parts:

1. **Start the lab** — the exact Docker command and the URL it serves.
2. **Engage** — `/engage`, `/recon`, and `playbook.py match`, the same opening every
   engagement uses.
3. **Confirm** — run the confirmation primitive, create the finding, and promote it only when
   the verdict says `confirmed`.
4. **What you should see** — the shape of a successful run.

> The "what you should see" sections describe expected behavior so you can tell a successful
> run from a stuck one. They are illustrative, not captured transcripts: the exact endpoints,
> object ids, and tokens come from your own recon against the lab you just started, which is
> why the commands use `{PLACEHOLDER}` fields the way `playbook.py plan` does. Fill them from
> HUGINN's `asset-map.json` and your own browsing.

## The pattern every lab shares

```bash
/engage <lab>                                           # classify, scope, plan, reachability gate
/recon  <lab>                                           # HUGINN Phase 0 -> asset-map.json + intel.jsonl
python3 scripts/playbook.py match --project-dir "$PROJECT_DIR"      # rank lanes REACHABLE-first
python3 scripts/playbook.py plan  <playbook-id> --project-dir "$PROJECT_DIR"   # runnable commands
# run the rendered confirm primitive, then:
bash scripts/finding.sh ...                             # record the structured finding
bash scripts/validate-finding.sh --from-evidence ...    # promote ONLY if the verdict is confirmed
```

`$PROJECT_DIR` is the resolved engagement directory, `~/workspace/<lab>/` by default.
