# Lab: Damn Vulnerable GraphQL Application (introspection, GraphQL authz)

[DVGA](https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application) is a deliberately
vulnerable GraphQL server. It is the right lab for Grimnir's GraphQL recon tool,
`specter/scripts/graphql-probe.py`, and for the authz follow-up it feeds.

## 1. Start the lab

```bash
docker run -t --rm -p 127.0.0.1:5013:5013 -e WEB_HOST=0.0.0.0 dolevf/dvga
```

The UI is at `http://localhost:5013` and the GraphQL endpoint is `http://localhost:5013/graphql`.
DVGA has a difficulty switch in its UI: **Easy** leaves introspection on, **Hard** turns it
off. Set it to **Hard** for the interesting demo below, then come back.

## 2. Engage

```bash
cd ~/workspace/grimnir && claude
```

```
/engage dvga
```

Describe it as "DVGA, a GraphQL API at http://localhost:5013/graphql, authorized local lab."
Grimnir classifies it as a GraphQL API (Specter lead). For a local lab, leave `GRIMNIR_PROXY`
unset so the tools connect directly; it is only set when a program requires a specific egress.

```
/recon dvga
```

## 3. Recover the schema with introspection off

With DVGA in Hard mode, a normal introspection query is refused. `graphql-probe.py` recovers
the schema anyway, from the server's own validation errors: an invalid field triggers a "Did
you mean ...?" hint naming real neighbouring fields, a real object field asked without a
subselection reveals its return type, and a required argument announces itself. Every probe is
a read-only `query`, bounded and paced.

```bash
PROJECT_DIR=~/workspace/dvga
python3 specter/scripts/graphql-probe.py http://localhost:5013/graphql \
  --max-requests 300 --depth 2 --delay 0.2 --out "$PROJECT_DIR/specter/reports/graphql-probe"
```

It writes `schema.json` and prints a summary of the types and fields it reconstructed. Turn
DVGA back to Easy and compare: the recovered schema should line up with the real one, which is
the point. Introspection being off is not the control you thought it was.

## 4. The authz follow-up

The recovered `schema.json` feeds Specter's `graphql-audit` skill, which reads the schema for
object-by-id queries and privilege-sensitive mutations, then replays them as different
privilege levels. For an object fetched by id that should be access-controlled (DVGA's private
pastes are the classic case), the differential is the same 4-way shape the REST BOLA lane uses:
own object, another owner's object, a nonexistent id, a malformed id. A private object that
returns to the wrong requester, with a marker that is unmistakably not theirs, is the confirm;
a uniform response is not.

Because the id travels in the GraphQL POST body rather than a URL path, drive the replay
through the `caido-mode` skill (which preserves the original request and lets you edit one
field) or a hand-built request, and record the differential as the finding's negative control.
Create and promote exactly as in the other labs:

```bash
bash scripts/finding.sh --project-dir "$PROJECT_DIR" --agent specter --class bola \
  --title "Private paste readable across owners (GraphQL IDOR)" --severity high
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent specter --id SPE-001 --state confirmed
```

## What you should see

- In Hard mode, a raw `{__schema{types{name}}}` query is rejected, but `graphql-probe.py` still
  prints a reconstructed type/field list and writes `schema.json`. A run that recovers nothing
  usually means the engine strips "Did you mean" hints; the tool records what the errors
  actually said rather than guessing.
- The authz replay distinguishes a private object that leaks across owners from one that is
  correctly scoped. Only the former, with a distinguishing marker, is a confirm.

## Tear down

Stop the container (Ctrl-C). `--rm` removes it.
