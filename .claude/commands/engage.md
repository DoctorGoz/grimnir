Start a new penetration testing engagement for $ARGUMENTS

## Steps

1. **Determine project name** from the target (e.g., `acme-corp`, `megacorp`, `demo-target`):
   - Use the company/product name, not the engagement ID
   - Keep it short, lowercase, hyphenated

2. **Create project directory** (absolute path, under `$GRIMNIR_WORKSPACE`, default `~/workspace/`):
   ```bash
   PROJECT_DIR="${GRIMNIR_WORKSPACE:-$HOME/workspace}/$PROJECT_NAME"
   mkdir -p "$PROJECT_DIR"/{recon,findings,evidence,reports,logs}
   mkdir -p "$PROJECT_DIR"/huginn/{recon,logs}
   mkdir -p "$PROJECT_DIR"/specter/{recon,findings,reports}
   mkdir -p "$PROJECT_DIR"/artemis/{recon,findings,reports}
   mkdir -p "$PROJECT_DIR"/hunter/{recon,findings,reports}
   ```


3. **Auto-detect existing project data** — check for files in `$PROJECT_DIR` before asking the user:

   **Intake file** (`project.md`):
   - If `$PROJECT_DIR/project.md` exists → read it, extract target info, credentials, scope, priorities
   - If not → ask the user for target details, or suggest they create one from the template (`templates/project.md`)

   **Existing artifacts** — skip steps that are already done:
   - If `$PROJECT_DIR/classification.md` exists → read it, skip classification (step 5)
   - If `$PROJECT_DIR/scope.md` exists → read it, skip scoping (step 6)
   - If `$PROJECT_DIR/test-plan.md` exists → read it, skip planning (step 7)
   - If `$PROJECT_DIR/state.json` exists → read it, show current state, offer to resume instead

   Tell the user which files were found and which steps are being skipped.

4. **Initialize engagement state** (if `state.json` doesn't already exist):
   ```bash
   bash scripts/state.sh init \
     --project-dir "$PROJECT_DIR" \
     --engagement-id "ENG-$(date +%Y%m%d)-$PROJECT_NAME" \
     --project-name "$PROJECT_NAME" \
     --handle "${PROGRAM_HANDLE:-}" \
     --platform "${PROGRAM_PLATFORM:-}" \
     --target "https://target.example.com" \
     --agents "huginn,specter,artemis,hunter"
   ```
   HUGINN is ALWAYS included. Only include specialist agents that are actually assigned (e.g., `--agents "huginn,specter"` for API-only).

   **Capture the canonical program handle, bug-bounty programs only.** `--handle` is the
   platform program slug (e.g. `acme-corp-bbp`). It frequently differs from `$PROJECT_NAME` (the
   short dir slug, e.g. `acme-corp`), and recording it here ends that mismatch. For a **pentest or
   directly-supplied target there is no platform handle: leave `--handle`/`--platform` empty**
   and the dir slug stays the identity.

   **Create empty intel feed** (if it doesn't exist):
   ```bash
   touch "$PROJECT_DIR/intel.jsonl"
   ```

5. **Classify the target** (skip if `classification.md` exists):
   - Use info from `project.md` if available
   - Is it an API? Web app? LLM chatbot? RAG system? Agentic system? Network? Cloud account/storage? Mobile app? Combination?
   - Save classification to `$PROJECT_DIR/classification.md`

6. **Determine agent assignment** (HUGINN always runs Phase 0 recon):
   - API/Web only → HUGINN + Specter
   - GenAI/LLM only → HUGINN + ARTEMIS
   - Network/Infrastructure only → HUGINN + Hunter
   - Both API + AI layers → HUGINN + Specter + ARTEMIS
   - Infrastructure + Web → HUGINN + Hunter + Specter
   - Cloud account / storage / serverless / Kubernetes → HUGINN + Nimbus (+ Specter for hosted apps/APIs)
   - Mobile app (APK/IPA) → HUGINN + Nomad (+ Specter for its backend API)
   - Full stack (infra + app + AI + cloud + mobile) → HUGINN + all applicable specialists

7. **Scope the engagement** (skip if `scope.md` exists):
   - Use info from `project.md` if available
   - Define in-scope and out-of-scope targets
   - Confirm authorization
   - Identify auth credentials (tokens, API keys)
   - Set rate limits and proxy configuration
   - Save to `$PROJECT_DIR/scope.md`

8. **Reachability pre-check** (intelligence-layer LANE gate — run before planning/dispatch):
   ```bash
   bash scripts/reachability.sh init --project-dir "$PROJECT_DIR"
   ```
   Reads the intake's **Account Capabilities** and scaffolds
   `$PROJECT_DIR/reachability.{md,json}`: a matrix labeling each high-value lane
   REACHABLE / GATED(gate) / UNKNOWN against the gate taxonomy (kyc, funded-balance,
   second-account, device, paid-tier, geo-egress, browser-interactive, otp-2fa,
   approval-role). It pre-fills what you HOLD and any stack-known gates and auto-verdicts
   the cross-account authz lane; YOU complete the remaining lane rows from `classification.md`.
   - Surface GATED high-value lanes to the operator NOW, before effort is spent (a gated
     cross-tenant/BOLA lane with only one account is the #1 documented waste).
   - The test plan (next step) must lead with REACHABLE lanes + the program focus areas
     (Rule 21) and deprioritize GATED ones. Do not plan a primary lane you cannot reach.

   Then synthesize the **Engagement Intelligence Brief** (fuses reachability + fertility +
   focus areas into one spend/skip/gated prior):
   ```bash
   bash scripts/brief.sh init --project-dir "$PROJECT_DIR"
   ```
   Complete its **Synthesis** section. The test plan below is built FROM the brief.

9. **Generate test plan** (skip if `test-plan.md` exists):
   - Prioritize OWASP categories based on target type
   - Assign phases to specialist agents
   - Set timeline
   - Save to `$PROJECT_DIR/test-plan.md`

10. **Capture the authenticated surface** (the step people skip). HUGINN's static recon leaves `endpoints[]` thin, so authenticated testing has little to aim at until the logged-in surface is captured. Record the test accounts in `$PROJECT_DIR/credentials.jsonl` (one JSON object per account: identity, token or cookie, role, and the object ids it owns), keep their sessions live with `scripts/session.py`, then pick one:
   ```bash
   # web/app: capture one authed request per account via the caido-mode skill, then crawl READ-ONLY
   python3 scripts/authed-crawl.py --project-dir "$PROJECT_DIR" --session-source caido
   # API target with a published spec (preferred, enumerates routes organic traffic never hits):
   python3 scripts/openapi-to-assetmap.py --spec <url|file> --project-dir "$PROJECT_DIR"
   ```
   Then rank the applicable attack playbooks and lead the test plan with the REACHABLE ones:
   ```bash
   python3 scripts/playbook.py match --project-dir "$PROJECT_DIR"
   ```
   Confirmation primitives (`scripts/confirm/`) are fired by hand or by a specialist; nothing is ever submitted automatically.

11. **Report next steps**: tell the operator which commands to run:
   - `/full-audit $PROJECT_NAME` for all applicable agents (interactive specialist pass)
   - `/api-audit $PROJECT_NAME` for Specter testing only
   - `/genai-audit $PROJECT_NAME` for ARTEMIS testing only
   - `/net-audit $PROJECT_NAME` for Hunter testing only

**IMPORTANT**: All subsequent agent delegations MUST include `"project_dir": "$PROJECT_DIR"` in the handoff payload.
