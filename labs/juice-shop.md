# Lab: OWASP Juice Shop (SQL injection, reflected XSS)

[OWASP Juice Shop](https://github.com/juice-shop/juice-shop) is the most-used deliberately
insecure web app. It exercises two of Grimnir's in-band confirmers: `sqli-inband` and
`xss-reflected`.

## 1. Start the lab

```bash
docker run --rm -p 127.0.0.1:3000:3000 bkimminich/juice-shop
```

Binding to `127.0.0.1` keeps it on-box. The app serves at `http://localhost:3000`.

## 2. Engage

```bash
cd ~/workspace/grimnir && claude
```

```
/engage juice-shop
```

Describe it as "OWASP Juice Shop, a web app at http://localhost:3000, authorized local lab."
Grimnir classifies it as a web application (Specter lead) and plans accordingly.

```
/recon juice-shop
```

Then rank the playbooks:

```bash
PROJECT_DIR=~/workspace/juice-shop
python3 scripts/playbook.py match --project-dir "$PROJECT_DIR"
python3 scripts/playbook.py plan sqli-inband --project-dir "$PROJECT_DIR"
python3 scripts/playbook.py plan xss-reflected --project-dir "$PROJECT_DIR"
```

## 3. Confirm the SQL injection

Juice Shop's product search (`GET /rest/products/search?q=`) is injectable. `sqli-confirm.py`
runs two read-only proofs against a baseline: a single quote must raise a database error the
baseline lacks and a doubled quote must clear it, or a TRUE/FALSE boolean pair must move the
response in two rounds with fresh literals. It never uses OR, stacked statements, or time
delays.

```bash
python3 scripts/confirm/sqli-confirm.py --finding-id SPE-001 --project-dir "$PROJECT_DIR" \
  --method GET --url 'http://localhost:3000/rest/products/search?q=apple' --param q
```

Record and promote:

```bash
bash scripts/finding.sh --project-dir "$PROJECT_DIR" --agent specter --class sqli \
  --title "SQL injection in product search (q parameter)" --severity high
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent specter \
  --id SPE-001 --from-evidence
```

## 4. Confirm the reflected / DOM XSS

Juice Shop reflects the search term into the DOM (the search bar at the `#/search?q=` route).
`render-confirm.py` loads it in headless Chromium and confirms execution only when the payload
sets a value no page content could set. Render the chain for the exact invocation, then:

```bash
playwright install chromium          # one-time, if not already installed
python3 scripts/confirm/render-confirm.py --finding-id SPE-002 --project-dir "$PROJECT_DIR" \
  --url 'http://localhost:3000/#/search?q=<iframe src="javascript:window.__grimnir_xss=1337">'
```

For a server-reflected context (payload in a normal query parameter rather than a hash route),
`xss-confirm.py --param q` maps the reflection first and picks the payload the context allows.
Either way, `confirmed` means the harness value was read back, with a screenshot in
`evidence/SPE-002/render.png`.

```bash
bash scripts/finding.sh --project-dir "$PROJECT_DIR" --agent specter --class xss \
  --title "Reflected/DOM XSS in search" --severity medium
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent specter \
  --id SPE-002 --from-evidence
```

## What you should see

- `sqli-confirm.py` writes `evidence/SPE-001/verdict.json` with `verdict: confirmed` and the
  error/boolean evidence (about ten requests on a negative, fewer on a confirm). A search that
  only ever returns the same product list, quote or no quote, is not injectable here.
- `render-confirm.py` writes `render.json` (`executed: true`) and `render.png`. A payload that
  comes back as text but does not run is `xss-likely`, not confirmed, which is the correct
  verdict when a CSP or Angular's sanitizer blocks it.
- `validate-finding.sh --from-evidence` promotes each only on `verdict: confirmed`.

## Tear down

Stop the container (Ctrl-C, or `docker stop` the `juice-shop` container). `--rm` removes it.
