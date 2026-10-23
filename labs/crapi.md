# Lab: OWASP crAPI (BOLA, mass assignment, missing-auth replay)

[crAPI](https://github.com/OWASP/crAPI) ("completely ridiculous API") is OWASP's intentionally
vulnerable API, built around the OWASP API Security Top 10. It is the best match for Grimnir's
three canonical authorization playbooks.

## 1. Start the lab

Run on an isolated host. The default compose binds to all interfaces, so use a VM or VPS whose
ports are not reachable from anywhere but you.

```bash
mkdir -p ~/labs/crapi && cd ~/labs/crapi
curl -o docker-compose.yml https://raw.githubusercontent.com/OWASP/crAPI/main/deploy/docker/docker-compose.yml
docker compose pull
docker compose -f docker-compose.yml --compatibility up -d
```

crAPI's web UI comes up at `http://localhost:8888`. The mail server (MailHog) is at
`http://localhost:8025`, where you read the signup confirmation and OTP mails.

**Register two accounts** so the cross-tenant differential has a victim to reach. On a default
deploy the auth endpoints are:

```bash
BASE=http://localhost:8888
# attacker
curl -s "$BASE/identity/api/auth/signup" -H 'Content-Type: application/json' \
  -d '{"name":"att","email":"attacker@example.com","number":"4917600000001","password":"Passw0rd!1"}'
# victim
curl -s "$BASE/identity/api/auth/signup" -H 'Content-Type: application/json' \
  -d '{"name":"vic","email":"victim@example.com","number":"4917600000002","password":"Passw0rd!2"}'
# log in -> each returns a JWT in {"token": "..."}
curl -s "$BASE/identity/api/auth/login" -H 'Content-Type: application/json' \
  -d '{"email":"attacker@example.com","password":"Passw0rd!1"}'
```

Give each account a vehicle (crAPI mails a verification code to the account; read it in MailHog
and claim the vehicle in the UI). Note both vehicle ids: the attacker's is `--own-id`, the
victim's is the `--victim-id` you should not be able to read.

**Record the accounts** so Grimnir keeps the sessions straight. Create
`~/workspace/crapi/credentials.jsonl`, one JSON object per account:

```json
{"identity":"attacker@example.com","role":"user","token":"<attacker-jwt>","owns":{"vehicle_id":"<att-vehicle>"}}
{"identity":"victim@example.com","role":"user","token":"<victim-jwt>","owns":{"vehicle_id":"<vic-vehicle>"}}
```

## 2. Engage

```bash
cd ~/workspace/grimnir && claude
```

```
/engage crapi
```

Describe it as "OWASP crAPI, a REST API running at http://localhost:8888, authorized local
lab, two test accounts in credentials.jsonl." Grimnir classifies it as a REST API (Specter
lead), writes `scope.md` and a test plan, and runs the reachability gate.

```
/recon crapi
```

HUGINN maps the endpoints into `asset-map.json`. Then rank the playbooks:

```bash
PROJECT_DIR=~/workspace/crapi
python3 scripts/playbook.py match --project-dir "$PROJECT_DIR"
```

`bola-cross-tenant`, `mass-assignment-bopla`, and `missing-auth-replay` should all rank
REACHABLE: you hold two accounts and the API is live.

## 3. Confirm a BOLA

crAPI's signature bug is reading another user's vehicle location. Render the chain to get the
exact command for your deploy:

```bash
python3 scripts/playbook.py plan bola-cross-tenant --project-dir "$PROJECT_DIR"
```

It renders `authz-confirm.py` with the fields you must fill. The 4-way differential (own /
cross / nonexistent / malformed) confirms only when the cross request returns the victim's
distinguishable data, and it records the negative control the evidence gate requires:

```bash
python3 scripts/confirm/authz-confirm.py --finding-id SPE-001 --project-dir "$PROJECT_DIR" \
  --url 'http://localhost:8888/identity/api/v2/vehicle/{VICTIM_VEHICLE_ID}/location' \
  -H 'Authorization: Bearer {ATTACKER_JWT}' \
  --own-id '{ATT_VEHICLE_ID}' --victim-id '{VICTIM_VEHICLE_ID}' \
  --nonexistent-id '00000000-0000-0000-0000-000000000000' \
  --victim-marker '{VICTIM_LATITUDE_OR_VIN}'
```

`--victim-marker` is a string that appears only in the victim's data (a VIN, a latitude). A
cross-tenant 200 without a marker is `bola-likely`, not confirmed: enrich and re-test.

Record and promote:

```bash
bash scripts/finding.sh --project-dir "$PROJECT_DIR" --agent specter --class bola \
  --title "BOLA: any user reads another user's vehicle location" --severity high
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent specter \
  --id SPE-001 --from-evidence
python3 scripts/confirm/poc-export.py --finding-id SPE-001 --project-dir "$PROJECT_DIR"
```

## 4. The other two lanes

- **Mass assignment** (`mass-assignment-bopla`): crAPI lets a user set fields the server should
  own (for example an order or coupon field). `playbook.py plan mass-assignment-bopla` renders
  `bopla-confirm.py`, which writes the unexpected field, confirms it stuck, then writes the
  baseline value back so the lab is left as it was.
- **Missing-auth replay** (`missing-auth-replay`): replay a session-only route with no session.
  `playbook.py plan missing-auth-replay` renders `authn-confirm.py`, which confirms the route
  answers without credentials and that a garbage token is not what let it through.

## What you should see

- `playbook.py match` lists the three lanes REACHABLE with a short "why" for each.
- `authz-confirm.py` writes `evidence/SPE-001/authz.json` with `verdict: confirmed` and the
  four labeled responses (own 200, cross 200 carrying the marker, nonexistent 404, malformed
  4xx). A cross response that matches your own, or that lacks the marker, is not a confirm.
- `validate-finding.sh --from-evidence` flips the finding to `confirmed` and refuses if the
  verdict is anything else.
- `poc-export.py` leaves `evidence/SPE-001/poc/{poc.md, repro.sh}` a triager could replay.

## Tear down

```bash
cd ~/labs/crapi && docker compose down -v
```
