#!/bin/bash
set -euo pipefail

# Grimnir Finding Validator
# Promotes (or downgrades) a finding's validation state — the "evidence strength"
# dimension that is orthogonal to triage status. New findings are created as

# Source the event hooks (optional — degrades gracefully)
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -f "$REPO/scripts/event-emitter.sh" ]]; then
    source "$REPO/scripts/event-emitter.sh"
fi
declare -F _emit >/dev/null 2>&1 || _emit() { :; }
# `theoretical`; only `confirmed` findings may ship in a report or external
# submission. This tool records HOW a finding was proven (method, negative
# control, screenshot) so the discipline lives in the data, not in memory.

usage() {
    cat <<'EOF'
Usage: validate-finding.sh --project-dir DIR --agent AGENT --id AGT-NNN --state STATE [OPTIONS]

Required:
  --project-dir DIR     Absolute path to project directory
  --agent AGENT         huginn | specter | artemis | hunter | nimbus | nomad
  --id AGT-NNN          Finding ID to update (e.g. SPE-003). Legacy FINDING-003 accepted.
  --state STATE         theoretical | validated | confirmed | refuted

Options:
  --method M            How it was proven: manual-repro | negative-control |
                        screenshot | second-opinion | tool-output | out-of-band
                        (repeatable)
  --negative-control T  What the control was and its result. Strongly expected for
                        authz findings (BOLA/IDOR/BFLA) — distinguishes a real bypass
                        from identical-looking responses.
  --screenshot PATH     Screenshot (relative to $PROJECT_DIR) that visually confirms
                        the vulnerability manifested.
  --victim-data yes|no  Does the evidence contain a SECOND party's real data (read or
                        mutated), or only our own capability against our own account?
                        Capability-only proofs consistently fail to earn, at any severity
                        (hunting Rule 28). For access-control classes this drives the Q2
                        impact verdict, so record it.
  --class CLASS         Vulnerability class the evidence gate enforces against:
                        ssrf|injection|sqli|ssti|rce|imds|xxe (needs a confirmed verdict.json:
                        OOB for most, ssti-confirm.py in-band for ssti),
                        bola|idor|bfla|authz (needs a negative control),
                        xss|dom|redirect|csrf (needs a render proof / screenshot).
                        Usually unnecessary: the class recorded by `finding.sh --class`
                        is re-derived from the finding, and the gate arms itself from it.
  --claim-verdict C=V   Settle one claim of a claim-split finding (repeatable), e.g.
                        C2=refuted. V = untested | survived | refuted. Confirming refuses
                        unless the base claim is `survived`; on confirm the floor severity
                        (highest severity whose claims all survived) is printed and stored
                        as floor_severity. File at the floor; add escalations as comments.
  --by WHO              Who promoted it: operator | grimnir | agent name
  --note TEXT           Free-form validation note

Promote from harness evidence (preferred over retyping the proof):
  --from-evidence       Read evidence/<id>/*.json, and promote to `confirmed` only if a
                        scripts/confirm/ primitive recorded verdict=confirmed. Class,
                        negative control, screenshot and method all come from the same
                        artifact that proved it. Refuses on inconclusive/negative/absent
                        evidence and leaves the finding untouched.
  --scan                List findings whose evidence is confirmed on disk but whose state
                        is not yet `confirmed`, with the command to promote each. Run it
                        before opening a new lane — hunting Rule 29.

Promotion guidance:
  confirmed  => reproducible PoC AND an independent check (negative control for authz,
               screenshot/vision confirm for UI/DOM bugs, or out-of-band for SSRF).
  validated  => reproduced at least once, not yet independently confirmed.
  refuted    => proven false; record why in --note (kept for the audit trail).

7-Question Gate (pre-report / pre-submission lint):
  --gate                Run the 7-question gate. Requires --state confirmed|validated.
                        Verdict is one of PASS | KILL | DOWNGRADE | CHAIN_REQUIRED.
                        KILL auto-sets state=refuted; DOWNGRADE drops severity one level
                        and state confirmed->validated; CHAIN_REQUIRED flags weak impact.
  --gate-dry-run        Advisory: compute + print the verdict, write nothing. Use this
                        from report-compiler to surface verdicts without mutating findings.
  --gate-verdict FILE   Write the verdict as JSON to FILE.
  --gate-note TEXT      Extra note recorded with the gate result.
  --skip-gate-questions Q1,Q5   Skip specific questions (operator override).

  The 7 questions: Q1 exploitability, Q2 impact, Q3 evidence reproducibility,
  Q4 scope, Q5 never-submit (reads rules/never-submit.md GATE-TRIGGERS), Q6 severity
  vs CVSS, Q7 adversarial review. Q1/Q2/Q5 are KILL-capable; Q3/Q6/Q7 DOWNGRADE.

Updates <ID>.json and patches <ID>.md (except --gate-dry-run, which is read-only).
EOF
    exit 1
}

PROJECT_DIR=""
AGENT=""
ID=""
STATE=""
NEGATIVE_CONTROL=""
SCREENSHOT=""
VULN_CLASS=""
CHANNEL_RUNG=""
VICTIM_DATA=""
BY=""
NOTE=""
METHODS=()
CLAIM_VERDICTS=()
GATE=false
GATE_VERDICT_FILE=""
GATE_NOTE=""
SKIP_QUESTIONS=""
GATE_CHAIN_ID=""
GATE_DRY_RUN=false
FORCE=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --project-dir)      PROJECT_DIR="$2"; shift 2 ;;
        --agent)            AGENT="$2"; shift 2 ;;
        --id)               ID="$2"; shift 2 ;;
        --state)            STATE="$2"; shift 2 ;;
        --method)           METHODS+=("$2"); shift 2 ;;
        --negative-control) NEGATIVE_CONTROL="$2"; shift 2 ;;
        --screenshot)       SCREENSHOT="$2"; shift 2 ;;
        --class)            VULN_CLASS="$2"; shift 2 ;;
        --channel-rung)     CHANNEL_RUNG="$2"; shift 2 ;;
        --victim-data)      VICTIM_DATA="$2"; shift 2 ;;
        --claim-verdict)    CLAIM_VERDICTS+=("$2"); shift 2 ;;
        --by)               BY="$2"; shift 2 ;;
        --note)             NOTE="$2"; shift 2 ;;
        --gate)             GATE=true; shift ;;
        --gate-dry-run)     GATE=true; GATE_DRY_RUN=true; shift ;;
        --gate-verdict)     GATE_VERDICT_FILE="$2"; shift 2 ;;
        --gate-note)        GATE_NOTE="$2"; shift 2 ;;
        --skip-gate-questions) SKIP_QUESTIONS="$2"; shift 2 ;;
        --gate-chain-id)    GATE_CHAIN_ID="$2"; shift 2 ;;
        --from-evidence)    FROM_EVIDENCE=true; shift ;;
        --scan)             SCAN=true; shift ;;
        --force)            FORCE=true; shift ;;
        --help|-h)          usage ;;
        *)                  echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# ── --from-evidence / --scan: read the artifact the harness already wrote ────────
# Every scripts/confirm/ primitive emits the same contract -- a JSON record carrying
# {vuln_class, verdict} plus, where the class needs it, negative_control or screenshot.
# So promotion can be derived from the artifact instead of retyped after it, which is
# where it used to get dropped: the primitive wrote proof and stopped, and promotion
# was a separate command. Findings sat proven-but-unpromoted on disk (hunting Rule 29).
#
# This stays in validate-finding.sh on purpose. scripts/confirm/README.md fixes the
# mechanism/policy split: primitives are non-interactive (args in, JSON out) and policy
# lives in the gate. Teaching each primitive to promote would put policy in five places.

# Strongest confirmed record for a finding id, or empty. Reads any *.json under
# evidence/<id>/ that carries a "verdict" key -- not just the three original filenames,
# so a new primitive is picked up without editing this.
evidence_record() {
    local id="$1" d="$PROJECT_DIR/evidence/$1" f
    [[ -d "$d" ]] || return 1
    for f in "$d"/*.json; do
        [[ -f "$f" ]] || continue
        jq -e 'has("verdict") and .verdict == "confirmed"' "$f" >/dev/null 2>&1 || continue
        cat "$f"; return 0
    done
    return 1
}

if [[ "${SCAN:-false}" == true ]]; then
    [[ -z "$PROJECT_DIR" ]] && { echo "Error: --scan needs --project-dir" >&2; exit 1; }
    found=0
    while IFS= read -r evdir; do
        id=$(basename "$evdir")
        rec=$(evidence_record "$id") || continue
        # Find the owning finding file. A bare legacy FINDING-NNN can name a DIFFERENT
        # finding under each agent -- that is the entire reason AGT-NNN exists -- and
        # --scan takes no --agent to disambiguate with. Picking the first match silently
        # attaches evidence to the wrong finding: on a real engagement this paired an
        # SSRF verdict with an unrelated missing-authorization finding because `hunter`
        # sorts before `specter`. Report the ambiguity; let the operator resolve it.
        mapfile -t _owners < <(ls "$PROJECT_DIR"/*/findings/"$id".json 2>/dev/null)
        if [[ "${#_owners[@]}" -gt 1 ]]; then
            [[ "$found" -eq 0 ]] && printf 'Proven on disk but NOT promoted (hunting Rule 29):\n\n'
            found=1
            printf '  %-12s %-10s AMBIGUOUS: %d findings share this legacy id\n' "$id" \
                "$(jq -r '.vuln_class // "?"' <<<"$rec")" "${#_owners[@]}"
            for _o in "${_owners[@]}"; do
                printf '  %-12s   - %-8s %s\n' "" \
                    "$(basename "$(dirname "$(dirname "$_o")")")" "$(jq -r '.title // ""' "$_o")"
            done
            printf '  %-12s   evidence: %s\n' "" "$(jq -r '.reproducer // .why // .note // "(see the record)"' <<<"$rec")"
            printf '  %-12s   -> re-run with --agent <owner> --id %s --from-evidence once you\n' "" "$id"
            printf '  %-12s      have confirmed which finding this evidence belongs to.\n' ""
            continue
        fi
        fj="${_owners[0]:-}"
        [[ -n "$fj" ]] || continue
        [[ "$(jq -r '.validation.state // "theoretical"' "$fj")" == confirmed ]] && continue
        [[ "$found" -eq 0 ]] && printf 'Proven on disk but NOT promoted (hunting Rule 29):\n\n'
        found=1
        printf '  %-12s %-10s %s\n' "$id" \
            "$(jq -r '.vuln_class // "?"' <<<"$rec")" \
            "$(jq -r '.title // ""' "$fj")"
        printf '  %-12s %s\n' "" "-> bash scripts/validate-finding.sh --project-dir $PROJECT_DIR --agent $(basename "$(dirname "$(dirname "$fj")")") --id $id --from-evidence"
    done < <(find "$PROJECT_DIR/evidence" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort)
    [[ "$found" -eq 0 ]] && echo "Nothing proven-but-unpromoted. (Every confirmed artifact has a confirmed finding.)"
    exit 0
fi

if [[ "${FROM_EVIDENCE:-false}" == true ]]; then
    [[ -z "$PROJECT_DIR" ]] && { echo "Error: --from-evidence needs --project-dir" >&2; exit 1; }
    [[ -z "$ID" ]] && { echo "Error: --from-evidence needs --id" >&2; exit 1; }
    if ! REC=$(evidence_record "$ID"); then
        echo "Error: no confirmed artifact under $PROJECT_DIR/evidence/$ID/." >&2
        echo "       --from-evidence promotes only what a scripts/confirm/ primitive proved." >&2
        if [[ -d "$PROJECT_DIR/evidence/$ID" ]]; then
            echo "       Artifacts present, none confirmed:" >&2
            for f in "$PROJECT_DIR/evidence/$ID"/*.json; do
                [[ -f "$f" ]] || continue
                printf '         %s -> verdict=%s %s\n' "$(basename "$f")" \
                    "$(jq -r '.verdict // "none"' "$f")" "$(jq -r '.why // .note // ""' "$f")" >&2
            done
        fi
        exit 1
    fi
    # Derive what the gate will ask for from the same record that proved it.
    STATE="confirmed"
    [[ -z "$VULN_CLASS" ]] && VULN_CLASS=$(jq -r '.vuln_class // ""' <<<"$REC")
    _nc=$(jq -r '.negative_control // ""' <<<"$REC")
    [[ -n "$_nc" && -z "$NEGATIVE_CONTROL" ]] && NEGATIVE_CONTROL="$_nc"
    _shot=$(jq -r '.screenshot // ""' <<<"$REC")
    [[ -n "$_shot" && -z "$SCREENSHOT" ]] && SCREENSHOT="${_shot#"$PROJECT_DIR"/}"
    # Method reflects how it was proven, so the report shows the actual technique.
    case "$(printf '%s' "$VULN_CLASS" | tr '[:upper:]' '[:lower:]')" in
        # In-band differentials (the harness's own control request), not a callback.
        bola|idor|bfla|authz|authn|tier|race|ssti|sqli|infoleak|jwt|bopla) METHODS+=("negative-control") ;;
        xss|dom|redirect|csrf)        METHODS+=("screenshot") ;;
        *)                            METHODS+=("out-of-band") ;;
    esac
    [[ -z "$BY" ]] && BY="confirm-harness"
    [[ -z "$NOTE" ]] && NOTE="promoted from evidence/$ID/ ($(jq -r '.why // .note // "harness verdict: confirmed"' <<<"$REC"))"
fi

# ── Validate required fields ──
[[ -z "$PROJECT_DIR" ]] && { echo "Error: --project-dir is required" >&2; exit 1; }
[[ "$PROJECT_DIR" != /* ]] && { echo "Error: --project-dir must be an absolute path" >&2; exit 1; }
[[ -z "$AGENT" ]] && { echo "Error: --agent is required" >&2; exit 1; }
[[ "$AGENT" =~ ^(huginn|specter|artemis|hunter|nimbus|nomad)$ ]] || { echo "Error: --agent must be huginn, specter, artemis, hunter, nimbus, or nomad" >&2; exit 1; }
[[ -z "$ID" ]] && { echo "Error: --id is required" >&2; exit 1; }
# AGT-NNN is the convention; FINDING-NNN is accepted for pre-existing findings.
[[ "$ID" =~ ^([A-Z]{3}|FINDING)-[0-9]{3}$ ]] || { echo "Error: --id must look like SPE-003 (or a legacy FINDING-003)" >&2; exit 1; }
if [[ "$ID" =~ ^[A-Z]{3}- ]]; then
    case "$AGENT" in
        huginn) _want=HUG ;; specter) _want=SPE ;; artemis) _want=ART ;;
        hunter) _want=HUN ;; nimbus)  _want=NIM ;; nomad)   _want=NOM ;;
    esac
    [[ "${ID%%-*}" == "$_want" ]] || { echo "Error: --id $ID does not match --agent $AGENT (expected ${_want}-NNN)" >&2; exit 1; }
fi
[[ -z "$STATE" ]] && { echo "Error: --state is required" >&2; exit 1; }
[[ "$STATE" =~ ^(theoretical|validated|confirmed|refuted)$ ]] || { echo "Error: --state must be theoretical, validated, confirmed, or refuted" >&2; exit 1; }
[[ -z "$VICTIM_DATA" || "$VICTIM_DATA" =~ ^(yes|no)$ ]] || { echo "Error: --victim-data must be yes or no" >&2; exit 1; }

FINDINGS_DIR="$PROJECT_DIR/$AGENT/findings"
JSON_PATH="$FINDINGS_DIR/$ID.json"
MD_PATH="$FINDINGS_DIR/$ID.md"

# Gate helper for warnings (avoid stomping existing functions)
gate_warn() { printf 'WARNING: %s\n' "$*" >&2; }
[[ -f "$JSON_PATH" ]] || { echo "Error: $JSON_PATH not found" >&2; exit 1; }

# No-downgrade guard: a finding promoted to `confirmed` was independently proven, so an
# inconclusive re-check must not silently overturn it. This blocks only the BARE manual
# path (a careless or automated `--state theoretical|validated`); the 7-question gate
# (--gate) and evidence promotion (--from-evidence) are deliberate re-checks and pass
# through. A genuine refutation is deliberate too -- use `--state refuted`.
if [[ "$GATE" != true && "${FROM_EVIDENCE:-false}" != true ]]; then
    CUR_STATE=$(jq -r '.validation.state // "theoretical"' "$JSON_PATH" 2>/dev/null)
    if [[ "$CUR_STATE" == confirmed && ( "$STATE" == theoretical || "$STATE" == validated ) && "$FORCE" != true ]]; then
        echo "Error: refusing to downgrade $ID from confirmed -> $STATE without --force." >&2
        echo "       A confirmed finding was independently proven; an inconclusive re-check must not" >&2
        echo "       silently overturn it. Use --state refuted for a deliberate refutation, or --force" >&2
        echo "       to override this downgrade." >&2
        exit 1
    fi
    [[ "$CUR_STATE" == confirmed && ( "$STATE" == theoretical || "$STATE" == validated ) ]] && \
        gate_warn "forced downgrade of $ID from confirmed to $STATE"
fi

TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# ── Claim split ─────────────────────────────────────────────────────────────────
# Settle the requested verdicts on a working copy, then judge promotion on that copy: a
# confirm that also refutes an escalation must see the refutation, and a refused confirm
# must leave the file untouched. Promotion needs the BASE claim survived; a refuted or
# untested escalation never blocks it, it just lowers the floor.
SRC_JSON=$(cat "$JSON_PATH")
for _cv in ${CLAIM_VERDICTS[@]+"${CLAIM_VERDICTS[@]}"}; do
    _cid="${_cv%%=*}"; _ver="${_cv#*=}"
    [[ "$_cv" == *=* && "$_ver" =~ ^(untested|survived|refuted)$ ]] || { echo "Error: --claim-verdict wants CLAIM=untested|survived|refuted (got '$_cv')" >&2; exit 1; }
    jq -e --arg c "$_cid" '(.claims // []) | any(.id == $c)' <<<"$SRC_JSON" >/dev/null || { echo "Error: $ID has no claim '$_cid'" >&2; exit 1; }
    SRC_JSON=$(jq --arg c "$_cid" --arg v "$_ver" '(.claims[] | select(.id == $c) | .verdict) = $v' <<<"$SRC_JSON")
done
if [[ "$STATE" == "confirmed" ]] && jq -e '(.claims // []) | length > 0' <<<"$SRC_JSON" >/dev/null; then
    if ! jq -e '[.claims[] | select(.kind == "base")] | length == 1 and .[0].verdict == "survived"' <<<"$SRC_JSON" >/dev/null; then
        echo "Error: refusing to confirm $ID: its base claim has not survived. Settle it with --claim-verdict (see: python3 scripts/finding_state.py show --project-dir $PROJECT_DIR --id $ID)" >&2
        exit 1
    fi
fi

# Evidence already recorded on the finding counts as supplied. Without this, every
# re-check (notably report-compiler's --gate-dry-run) would warn and block on findings
# whose proof is sitting right there in validation.negative_control.
[[ -z "$NEGATIVE_CONTROL" ]] && NEGATIVE_CONTROL=$(jq -r '.validation.negative_control // ""' "$JSON_PATH" 2>/dev/null)
[[ -z "$SCREENSHOT" ]] && SCREENSHOT=$(jq -r '.validation.screenshot // ""' "$JSON_PATH" 2>/dev/null)

# Nudge toward rigor without blocking: confirming an authz-style finding without a
# negative control is the classic rubber-stamp.
if [[ "$STATE" == "confirmed" && -z "$NEGATIVE_CONTROL" ]]; then
    printf 'WARNING: confirming %s without a --negative-control. For BOLA/IDOR/BFLA this is the rubber-stamp trap.\n' "$ID" >&2
fi
if [[ -n "$SCREENSHOT" && ! -f "$PROJECT_DIR/$SCREENSHOT" ]]; then
    printf 'WARNING: screenshot %s not found under project dir.\n' "$PROJECT_DIR/$SCREENSHOT" >&2
fi

# ── Confirmation-harness evidence gate ──────────────────────────────────────────
# Promotion to `confirmed` must carry the class-appropriate proof produced by
# scripts/confirm/* (OOB verdict.json, negative control, or render proof).
# Decision 2026-06-24: HARD-block for high/critical, WARN for low/medium.
# Backward-compatible: only enforces when --class is supplied (selftest/legacy unaffected).
# Escape hatch: GRIMNIR_EVIDENCE_GATE=warn (warn only) or =off (disable). See
# ROADMAP-confirmation-harness.md §5. Mechanism/policy split: this is the POLICY layer;
# the same verdict.json drives a future autonomous validator unchanged (§8).
# ── Response-channel rung (hunting Rule 32) ───────────────────────────────────
# blind -> partial -> full -> credential -> execution. Resolution order: the flag on this
# invocation, then what was recorded at creation, then what the harness artifact says,
# then `blind`. Reported honestly, a blind primitive is a Medium; asserted as a Critical
# it dies on the first triage question, so the gate makes the claim carry its evidence.
resolve_rung() {
    local r="$CHANNEL_RUNG"
    [[ -z "$r" ]] && r=$(jq -r '.validation.channel_rung // ""' "$JSON_PATH" 2>/dev/null)
    [[ -z "$r" ]] && r=$(jq -r '.channel_rung // ""' "$PROJECT_DIR/evidence/$ID/verdict.json" 2>/dev/null)
    printf '%s' "$(printf '%s' "${r:-blind}" | tr '[:upper:]' '[:lower:]')"
}

rung_gate() {
    local sev="$1" cls="$2" rung need_rung
    rung=$(resolve_rung)
    case "$rung" in
        blind|partial|full|credential|execution) : ;;
        *) printf 'Error: --channel-rung %s is not a rung. Use blind|partial|full|credential|execution.\n' "$rung" >&2
           return 1 ;;
    esac
    case "$sev" in
        critical) need_rung="credential or execution"
                  [[ "$rung" == credential || "$rung" == execution ]] && return 0 ;;
        high)     need_rung="full, credential or execution"
                  [[ "$rung" == full || "$rung" == credential || "$rung" == execution ]] && return 0 ;;
        *)        return 0 ;;
    esac
    local msg="confirmed $cls finding $ID claims $sev severity on response channel '$rung'; $sev needs $need_rung"
    if [[ "$GATE_DRY_RUN" == true || "${GRIMNIR_EVIDENCE_GATE:-enforce}" == "warn" ]]; then
        gate_warn "$msg"; return 0
    fi
    printf 'Error: %s. A request that fires but returns nothing is the floor of its class (hunting Rule 32).\n' "$msg" >&2
    printf '       Either climb the channel and record it with --channel-rung, or file at the severity the channel supports.\n' >&2
    printf '       Override with GRIMNIR_EVIDENCE_GATE=warn if the rung genuinely understates the impact.\n' >&2
    return 1
}

evidence_gate() {
    [[ "$STATE" == "confirmed" ]] || return 0
    # Fall back to the class recorded on the finding (finding.sh --class, or a previous
    # promotion). Reading only the flag on THIS invocation meant the ordinary call --
    # `validate-finding.sh --state confirmed`, no --class -- waived the proof requirement
    # entirely, including on a high-severity authz finding with nothing behind it. The
    # class is a property of the finding, not of the command that happens to promote it.
    local _cls="$VULN_CLASS"
    [[ -z "$_cls" ]] && _cls=$(jq -r '.validation.vuln_class // ""' "$JSON_PATH" 2>/dev/null)
    [[ -n "$_cls" ]] || return 0
    local mode="${GRIMNIR_EVIDENCE_GATE:-enforce}"
    [[ "$mode" == "off" ]] && return 0
    # A read-only pass must never exit non-zero: report-compiler runs --gate-dry-run
    # across every finding and a hard exit there aborts the whole report.
    [[ "$GATE_DRY_RUN" == true ]] && mode="warn"
    local cls sev verdictf need=""
    cls=$(printf '%s' "$_cls" | tr '[:upper:]' '[:lower:]')
    sev=$(jq -r '.severity // "medium"' "$JSON_PATH" 2>/dev/null | tr '[:upper:]' '[:lower:]')
    verdictf="$PROJECT_DIR/evidence/$ID/verdict.json"
    case "$cls" in
        ssrf|injection|sqli|ssti|rce|imds|xxe)
            if [[ -f "$verdictf" && "$(jq -r '.verdict // ""' "$verdictf" 2>/dev/null)" == "confirmed" ]]; then
                # The verdict proves the request FIRED. For a server-side-request class that
                # is the floor of the class, not its impact: the same primitive is a Medium
                # or a Critical depending on whether the response came back (hunting Rule 32).
                # So above Medium the recorded response-channel rung has to justify the
                # severity. An absent rung resolves to `blind`, which BLOCKS the over-claim
                # rather than waiving the check -- the safe direction for a field an agent
                # may forget, unlike vuln_class where forgetting disarmed the gate entirely.
                case "$cls" in
                    ssrf|imds) rung_gate "$sev" "$cls" && return 0 || exit 1 ;;
                    *) return 0 ;;
                esac
            fi
            if [[ "$cls" == ssti ]]; then
                need="a confirmed evidence/$ID/verdict.json (scripts/confirm/ssti-confirm.py, in-band evaluation)"
            else
                need="an OOB verdict (scripts/confirm/oob-client.py verdict <nonce> $ID $cls)"
            fi ;;
        bola|idor|bfla|authz)
            [[ -n "$NEGATIVE_CONTROL" ]] && return 0
            [[ -f "$PROJECT_DIR/evidence/$ID/authz.json" && "$(jq -r '.verdict // ""' "$PROJECT_DIR/evidence/$ID/authz.json" 2>/dev/null)" == "confirmed" ]] && return 0
            need="a --negative-control or a confirmed evidence/$ID/authz.json (authz-confirm.py 4-way differential)" ;;
        tier)
            [[ -n "$NEGATIVE_CONTROL" ]] && return 0
            [[ -f "$PROJECT_DIR/evidence/$ID/tier.json" && "$(jq -r '.verdict // ""' "$PROJECT_DIR/evidence/$ID/tier.json" 2>/dev/null)" == "confirmed" ]] && return 0
            need="a --negative-control or a confirmed evidence/$ID/tier.json (tier-confirm.py tier differential)" ;;
        infoleak|jwt|bopla)
            [[ -n "$NEGATIVE_CONTROL" ]] && return 0
            [[ -f "$PROJECT_DIR/evidence/$ID/$cls.json" && "$(jq -r '.verdict // ""' "$PROJECT_DIR/evidence/$ID/$cls.json" 2>/dev/null)" == "confirmed" ]] && return 0
            need="a --negative-control or a confirmed evidence/$ID/$cls.json ($cls-confirm.py)" ;;
        authn|missing-auth)
            [[ -n "$NEGATIVE_CONTROL" ]] && return 0
            [[ -f "$PROJECT_DIR/evidence/$ID/authn.json" && "$(jq -r '.verdict // ""' "$PROJECT_DIR/evidence/$ID/authn.json" 2>/dev/null)" == "confirmed" ]] && return 0
            need="a --negative-control or a confirmed evidence/$ID/authn.json (authn-confirm.py credential-stripped replay)" ;;
        race)
            [[ -n "$NEGATIVE_CONTROL" ]] && return 0
            [[ -f "$PROJECT_DIR/evidence/$ID/race.json" && "$(jq -r '.verdict // ""' "$PROJECT_DIR/evidence/$ID/race.json" 2>/dev/null)" == "confirmed" ]] && return 0
            need="a --negative-control or a confirmed evidence/$ID/race.json (race-confirm.py concurrent-burst overrun)" ;;
        xss|dom|redirect|csrf)
            [[ -n "$SCREENSHOT" && -f "$PROJECT_DIR/$SCREENSHOT" ]] && return 0
            [[ -f "$PROJECT_DIR/evidence/$ID/render.json" && "$(jq -r '.verdict // ""' "$PROJECT_DIR/evidence/$ID/render.json" 2>/dev/null)" == "confirmed" ]] && return 0
            need="a render proof (--screenshot FILE or a confirmed evidence/$ID/render.json from render-confirm.py)" ;;
        *)
            return 0 ;;  # unrecognized class -> no new enforcement
    esac
    local msg="confirmed $cls finding $ID is missing $need"
    if [[ "$mode" == "warn" ]]; then gate_warn "$msg"; return 0; fi
    case "$sev" in
        critical|high)
            printf 'Error: %s. Evidence gate is HARD at %s severity. Produce the proof, or set GRIMNIR_EVIDENCE_GATE=warn to override.\n' "$msg" "$sev" >&2
            exit 1 ;;
        *)
            gate_warn "$msg (warn-only at $sev severity)" ;;
    esac
}
evidence_gate

# ═══════════════════════════════════════════════════════════════
# 7-Question Validation Gate (--gate mode)
# ═══════════════════════════════════════════════════════════════

gate_q1_exploitability() {
    local json="$1"
    # Q1: Is this actually exploitable (not just theoretical)?
    local steps
    steps=$(echo "$json" | jq -r '.reproduction_steps | length' 2>/dev/null || echo 0)
    local evidence_count
    evidence_count=$(echo "$json" | jq -r '.evidence | length' 2>/dev/null || echo 0)
    local has_method=false
    echo "$json" | jq -e '.validation.method | length > 0' >/dev/null 2>&1 && has_method=true
    if [[ "$steps" -gt 0 || "$evidence_count" -gt 0 || "$has_method" == true ]]; then
        return 0
    fi
    return 1
}

# Classes whose whole claim is "an unauthorized caller reached X". For these the
# impact question is not "is the prose long enough" but "whose data is in the
# evidence" — and prose length cannot answer that.
ACCESS_CONTROL_CLASSES='^(bola|idor|bfla|authz|tier|access-control|privesc|agentic|llm|mcp)$'

# Effective class / victim-data: a flag passed on THIS invocation wins, otherwise use
# what the finding already records. Needed because --gate-dry-run writes nothing, so
# reading these back off the JSON would ignore the very flags the caller just supplied.
eff_vuln_class() {
    local v="$VULN_CLASS"
    [[ -z "$v" ]] && v=$(echo "$1" | jq -r '.validation.vuln_class // ""' 2>/dev/null)
    printf '%s' "$v" | tr '[:upper:]' '[:lower:]'
}
eff_victim_data() {  # -> true | false | unset
    case "$VICTIM_DATA" in
        yes) printf 'true'; return ;;
        no)  printf 'false'; return ;;
    esac
    echo "$1" | jq -r 'if .validation | has("victim_data") then (.validation.victim_data|tostring) else "unset" end' 2>/dev/null
}

# `impact` is an OBJECT in schemas/finding.schema.json ({summary, confidentiality,
# integrity, availability, business}) and that is what finding.sh writes. A bare
# `jq -r .impact` on an object pretty-prints the JSON, so the gates below were
# measuring brace-and-quote syntax instead of prose: an empty summary still scored
# ~19 characters, which silently shifted the Q2 thresholds by that much and
# effectively disabled the short-impact KILL. Flatten to the human text instead,
# and still accept a bare string for hand-written / legacy findings.
impact_text() {
    echo "$1" | jq -r '
        (.impact // "") as $i
        | if ($i | type) == "object"
          then ([$i.summary?, $i.confidentiality?, $i.integrity?, $i.availability?, $i.business?]
                | map(select(type == "string" and . != "")) | join(" "))
          elif ($i | type) == "string" then $i
          else "" end' 2>/dev/null
}

gate_q2_impact() {
    local json="$1"
    # Q2: Does it have demonstrable impact?
    local impact
    impact=$(impact_text "$json")
    [[ -z "$impact" ]] && impact=$(echo "$json" | jq -r '.description // ""' 2>/dev/null)
    local len=${#impact}
    if [[ -z "$impact" || "$len" -lt 20 ]]; then
        return 1  # KILL
    fi

    # Capability vs harm. In submission-outcome data, findings proving only the
    # researcher's own capability against their own account consistently fail to earn,
    # including ones filed as Critical, while payouts put a second party's real data in
    # the evidence. A long impact paragraph is an ARGUMENT; victim data is EVIDENCE,
    # and programs close arguments as "working as designed". So for the classes whose
    # claim is reachability, an explicit `victim_data: false` (or an unanswered one)
    # is the marginal case, regardless of how well the impact section reads.
    # (See rules/hunting.md Rule 28 for the discipline.)
    local cls victim
    cls=$(eff_vuln_class "$json")
    victim=$(eff_victim_data "$json")
    if [[ "$cls" =~ $ACCESS_CONTROL_CLASSES && "$victim" != "true" ]]; then
        return 2  # CHAIN_REQUIRED — needs a chain to a second party's data to be payable
    fi

    if [[ "$len" -lt 50 ]]; then
        return 2  # CHAIN_REQUIRED (marginal)
    fi
    return 0  # PASS
}

gate_q3_evidence() {
    local json="$1"
    # Q3: Is the evidence reproducible (not one-off)?
    local vstate
    vstate=$(echo "$json" | jq -r '.validation.state // "theoretical"' 2>/dev/null)
    case "$vstate" in
        theoretical) return 1 ;;  # DOWNGRADE
        validated|confirmed) ;;
        *) return 1 ;;
    esac
    # For artemis findings: check success rate attempts
    local agent
    agent=$(echo "$json" | jq -r '.agent // ""' 2>/dev/null)
    if [[ "$agent" == "artemis" ]]; then
        local attempts
        attempts=$(echo "$json" | jq -r '.artemis_ext.success_rate' 2>/dev/null | grep -oE '[0-9]+' | head -1 || echo 0)
        if [[ "${attempts:-0}" -le 1 ]]; then
            return 1  # One-off: DOWNGRADE
        fi
    fi
    return 0
}

gate_q4_scope() {
    local json="$1"
    # Q4: Is the finding within scope?
    local scope_file="$PROJECT_DIR/scope.md"
    [[ ! -f "$scope_file" ]] && { gate_warn "Q4: no scope.md found — cannot verify"; return 0; }
    # finding.sh writes affected_targets[]; older/hand-written findings may carry a scalar
    # .target. Check both, or this gate silently never matches and warns on every finding.
    # Targets are often full URLs while scope.md lists bare hosts, so try the host too.
    local target host
    while IFS= read -r target; do
        [[ -z "$target" ]] && continue
        if grep -qiF "$target" "$scope_file" 2>/dev/null; then
            return 0
        fi
        host="${target#*://}"; host="${host%%/*}"; host="${host%%:*}"
        if [[ -n "$host" ]] && grep -qiF "$host" "$scope_file" 2>/dev/null; then
            return 0
        fi
    done < <(echo "$json" | jq -r '(.affected_targets // []) + [.target // ""] | .[] | select(. != "")' 2>/dev/null)
    # Check specter_ext endpoint
    local endpoint
    endpoint=$(echo "$json" | jq -r '.specter_ext.endpoint // ""' 2>/dev/null)
    if [[ -n "$endpoint" ]]; then
        if grep -qi "$endpoint" "$scope_file" 2>/dev/null; then
            return 0
        fi
    fi
    # Check hunter_ext host
    local host
    host=$(echo "$json" | jq -r '.hunter_ext.host // ""' 2>/dev/null)
    if [[ -n "$host" ]]; then
        if grep -qi "$host" "$scope_file" 2>/dev/null; then
            return 0
        fi
    fi
    gate_warn "Q4: target not matched in scope.md"
    return 0  # Soft warning — scope should have been caught earlier
}

gate_q5_never_submit() {
    local json="$1"
    # Q5: Does the finding match a never-submit pattern?
    # Parses the machine-readable GATE-TRIGGERS table in rules/never-submit.md.
    # Each line: pattern-id | trigger-regex | uplift-regex
    # KILL if title+description matches trigger AND does NOT match uplift.
    # Uplift of "-" means no uplift (always kill on trigger).
    local never_file="rules/never-submit.md"
    [[ ! -f "$never_file" ]] && never_file="$(dirname "$0")/../rules/never-submit.md"
    [[ ! -f "$never_file" ]] && { gate_warn "Q5: rules/never-submit.md not found — cannot check"; return 0; }
    local title desc combined
    title=$(echo "$json" | jq -r '.title // ""' 2>/dev/null)
    desc=$(echo "$json" | jq -r '.description // ""' 2>/dev/null)
    # Also fold in impact — uplift markers ("exfiltrated PII") often live there
    local impact
    impact=$(impact_text "$json")
    combined="$title $desc $impact"

    # Extract the trigger table (lines between the GATE-TRIGGERS markers that contain |)
    local table
    table=$(sed -n '/GATE-TRIGGERS/,/GATE-TRIGGERS/p' "$never_file" 2>/dev/null | grep '|' || true)
    [[ -z "$table" ]] && { gate_warn "Q5: no GATE-TRIGGERS table found — cannot check"; return 0; }

    # Split on " | " (space pipe space), NOT on a bare "|". Every trigger and uplift is an
    # ERE full of alternations, so `IFS='|' read` chopped each regex at its first alternation:
    # `(tls|ssl)...` became the trigger `(tls`, an unbalanced group that grep rejects, and the
    # 2>/dev/null below swallowed the error. Five of ten patterns could never fire and three
    # more had the remainder of their trigger appended to the uplift, which then matched almost
    # anything. The table read as an enforcement layer while enforcing nearly nothing.
    local pid trig uplift rest row
    while IFS= read -r row; do
        [[ "$row" != *" | "* || "$row" =~ GATE-TRIGGERS ]] && continue
        pid="${row%% | *}"
        rest="${row#* | }"
        if [[ "$rest" == *" | "* ]]; then
            trig="${rest%% | *}"
            uplift="${rest##* | }"
        else
            trig="$rest"
            uplift="-"
        fi
        pid=$(echo "$pid" | xargs 2>/dev/null)
        trig=$(echo "$trig" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        uplift=$(echo "$uplift" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        [[ -z "$trig" || "$pid" =~ ^# ]] && continue
        # A regex that will not compile must be LOUD. grep exits 2 on a bad pattern and 1 on a
        # clean miss, and the 2>/dev/null below cannot tell them apart -- which is exactly how
        # the split bug stayed invisible: every broken pattern looked like "no match".
        local _re_rc=0
        printf '' | grep -qE "$trig" 2>/dev/null || _re_rc=$?
        if [[ $_re_rc -ge 2 ]]; then
            gate_warn "Q5: never-submit pattern '$pid' has an invalid trigger regex; skipping it"
            continue
        fi
        if echo "$combined" | grep -qiE "$trig" 2>/dev/null; then
            # Trigger matched. Check uplift (the submittable version).
            if [[ "$uplift" != "-" && -n "$uplift" ]] && echo "$combined" | grep -qiE "$uplift" 2>/dev/null; then
                continue  # uplift present → real impact → submittable, do not kill
            fi
            GATE_Q5_PATTERN="$pid"
            return 1  # KILL
        fi
    done <<< "$table"
    return 0
}

gate_q6_severity() {
    local json="$1"
    # Q6: Is severity correct?
    local sev cvss
    sev=$(echo "$json" | jq -r '.severity // ""' 2>/dev/null | tr '[:upper:]' '[:lower:]')
    cvss=$(echo "$json" | jq -r '.cvss_score // "0"' 2>/dev/null)
    [[ -z "$cvss" || "$cvss" == "null" ]] && cvss=0
    # CVSS-severity band check
    local expected=""
    if   (( $(echo "$cvss >= 9.0" | bc -l 2>/dev/null || echo 0) )); then expected="critical"
    elif (( $(echo "$cvss >= 7.0" | bc -l 2>/dev/null || echo 0) )); then expected="high"
    elif (( $(echo "$cvss >= 4.0" | bc -l 2>/dev/null || echo 0) )); then expected="medium"
    elif (( $(echo "$cvss > 0.0"  | bc -l 2>/dev/null || echo 0) )); then expected="low"
    fi
    if [[ -n "$expected" && "$sev" != "$expected" ]]; then
        return 1  # DOWNGRADE: severity/cvss mismatch
    fi
    [[ "$cvss" == "0" || -z "$cvss" ]] && return 1  # Missing CVSS
    return 0
}

gate_q7_adversarial() {
    local json="$1"
    # Q7: Would a triager kill this in 30 seconds?
    local flags=0
    local desc_len
    desc_len=$(echo "$json" | jq -r '.description // ""' 2>/dev/null | wc -c)
    [[ "$desc_len" -lt 100 ]] && flags=$((flags + 1))
    local evidence_count
    evidence_count=$(echo "$json" | jq -r '.evidence | length' 2>/dev/null || echo 0)
    [[ "$evidence_count" -eq 0 ]] && flags=$((flags + 1))
    local sev cvss
    sev=$(echo "$json" | jq -r '.severity // ""' 2>/dev/null)
    cvss=$(echo "$json" | jq -r '.cvss_score // "0"' 2>/dev/null)
    if [[ "$sev" == "critical" ]]; then
        if (( $(echo "${cvss:-0} < 7.0" | bc -l 2>/dev/null || echo 0) )); then
            flags=$((flags + 1))
        fi
    fi
    # Check for OOS indicators in title/description
    local combined
    combined=$(echo "$json" | jq -r '.title + " " + .description' 2>/dev/null | tr '[:upper:]' '[:lower:]')
    if echo "$combined" | grep -qE '(out.of.scope|third.party|not.in.scope|external.widget)' 2>/dev/null; then
        flags=$((flags + 1))
    fi
    [[ "$flags" -ge 2 ]] && return 1
    return 0
}

# ── Gate runner ──
run_gate() {
    local json_path="$1"
    local json
    json=$(cat "$json_path")

    local verdict="PASS"
    local kill_reason=""
    local downgrade_reason=""
    local chain_required=false
    local chain_reason=""

    # Q1: Exploitability — hard KILL
    if ! echo "$SKIP_QUESTIONS" | grep -q "Q1" 2>/dev/null; then
        if ! gate_q1_exploitability "$json"; then
            verdict="KILL"
            kill_reason="Q1 (Exploitability): No reproduction steps, tool output, or evidence found"
        fi
    fi

    # Q2: Impact — hard KILL (ret 1) or CHAIN_REQUIRED (ret 2)
    if ! echo "$SKIP_QUESTIONS" | grep -q "Q2" 2>/dev/null; then
        local q2_rc
        set +e; gate_q2_impact "$json"; q2_rc=$?; set -e
        case "$q2_rc" in
            1) if [[ "$verdict" != "KILL" ]]; then verdict="KILL"; fi
               kill_reason="${kill_reason:+$kill_reason; }Q2 (Impact): No demonstrable impact — summary empty or missing" ;;
            2) chain_required=true
               local q2_cls q2_victim
               q2_cls=$(eff_vuln_class "$json")
               q2_victim=$(eff_victim_data "$json")
               if [[ "$q2_cls" =~ $ACCESS_CONTROL_CLASSES && "$q2_victim" != "true" ]]; then
                   if [[ "$q2_victim" == "unset" ]]; then
                       chain_reason="Q2 (Impact): $q2_cls finding does not record whether the evidence contains a second party's data — set --victim-data yes|no"
                   else
                       chain_reason="Q2 (Impact): capability-only $q2_cls finding (victim_data=false). Capability-only proofs consistently fail to earn, including ones filed Critical (hunting Rule 28). Chain it to a second party's data before submitting"
                   fi
               else
                   chain_reason="Q2 (Impact): impact summary is thin"
               fi ;;
        esac
    fi

    # Q3: Evidence — DOWNGRADE on fail
    if ! echo "$SKIP_QUESTIONS" | grep -q "Q3" 2>/dev/null; then
        if ! gate_q3_evidence "$json"; then
            if [[ "$verdict" == "PASS" ]]; then verdict="DOWNGRADE"; fi
            downgrade_reason="${downgrade_reason:+$downgrade_reason; }Q3 (Evidence): Not reproducible or one-off result"
        fi
    fi

    # Q4: Scope — WARNING only (not a hard gate)
    if ! echo "$SKIP_QUESTIONS" | grep -q "Q4" 2>/dev/null; then
        gate_q4_scope "$json" || true
    fi

    # Q5: Never-Submit — hard KILL
    if ! echo "$SKIP_QUESTIONS" | grep -q "Q5" 2>/dev/null; then
        GATE_Q5_PATTERN=""
        if ! gate_q5_never_submit "$json"; then
            if [[ "$verdict" != "KILL" ]]; then verdict="KILL"; fi
            kill_reason="${kill_reason:+$kill_reason; }Q5 (Never-Submit): matches never-submit pattern '${GATE_Q5_PATTERN:-unknown}'"
        fi
    fi

    # Q6: Severity — DOWNGRADE on fail
    if ! echo "$SKIP_QUESTIONS" | grep -q "Q6" 2>/dev/null; then
        if ! gate_q6_severity "$json"; then
            if [[ "$verdict" == "PASS" ]]; then verdict="DOWNGRADE"; fi
            downgrade_reason="${downgrade_reason:+$downgrade_reason; }Q6 (Severity): CVSS/severity mismatch or missing score"
        fi
    fi

    # Q7: Adversarial Review — DOWNGRADE on fail
    if ! echo "$SKIP_QUESTIONS" | grep -q "Q7" 2>/dev/null; then
        if ! gate_q7_adversarial "$json"; then
            if [[ "$verdict" == "PASS" ]]; then verdict="DOWNGRADE"; fi
            downgrade_reason="${downgrade_reason:+$downgrade_reason; }Q7 (Adversarial): Would not survive triager review"
        fi
    fi

    # ── Execute verdict ──
    # CHAIN_REQUIRED is reported even when a KILL/DOWNGRADE outranks it. It answers a
    # different question -- "is this payable as it stands" vs "is the evidence sound"
    # -- and burying it behind an unrelated Q6 severity nit is how the one signal that
    # separates paid findings from unpaid ones gets lost.
    if [[ "$chain_required" == true && "$verdict" != "PASS" ]]; then
        printf 'ALSO CHAIN_REQUIRED: %s\n' \
            "${chain_reason:-Weak impact — consider chaining with another finding via --chain-id}"
    fi

    case "$verdict" in
        KILL)
            printf 'GATE VERDICT: KILL\n'
            printf 'Reason: %s\n' "$kill_reason"
            # Auto-set state to refuted
            STATE="refuted"
            if [[ -z "$NOTE" ]]; then NOTE="GATE KILL: $kill_reason"; fi
            ;;
        DOWNGRADE)
            printf 'GATE VERDICT: DOWNGRADE\n'
            printf 'Reason: %s\n' "$downgrade_reason"
            # Downgrade state: confirmed → validated
            if [[ "$STATE" == "confirmed" ]]; then STATE="validated"; fi
            # Downgrade severity one level
            local cur_sev
            cur_sev=$(echo "$json" | jq -r '.severity // "medium"' 2>/dev/null)
            case "$cur_sev" in
                critical) NEW_SEV="high" ;;
                high)     NEW_SEV="medium" ;;
                medium)   NEW_SEV="low" ;;
                low)      NEW_SEV="info" ;;
                *)        NEW_SEV="$cur_sev" ;;
            esac
            if [[ -z "$NOTE" ]]; then NOTE="GATE DOWNGRADE: $downgrade_reason"; fi
            if [[ "$cur_sev" != "$NEW_SEV" ]]; then NOTE="$NOTE (severity $cur_sev → $NEW_SEV)"; fi
            CUR_SEV="$NEW_SEV"
            export CUR_SEV
            ;;
        *)
            if [[ "$chain_required" == true ]]; then
                printf 'GATE VERDICT: CHAIN_REQUIRED\n'
                printf '%s\n' "${chain_reason:-Weak impact — consider chaining with another finding via --chain-id}"
                if [[ -z "$NOTE" ]]; then NOTE="GATE CHAIN_REQUIRED: ${chain_reason:-impact is marginal, chaining needed}"; fi
                if [[ "$STATE" == "confirmed" ]]; then STATE="validated"; fi
            else
                printf 'GATE VERDICT: PASS\n'
            fi
            ;;
    esac

    # Write gate verdict JSON if requested
    if [[ -n "$GATE_VERDICT_FILE" ]]; then
        jq -n --arg verdict "$verdict" \
              --arg reason "${kill_reason}${downgrade_reason}${chain_reason}" \
              --argjson chain "$chain_required" \
              '{verdict: $verdict, reason: $reason, chain_required: $chain}' > "$GATE_VERDICT_FILE"
    fi

    # Apply severity downgrade to JSON if CUR_SEV was set (skip in dry-run)
    if [[ -n "${CUR_SEV:-}" && "$GATE_DRY_RUN" != true ]]; then
        local tmp_json
        tmp_json=$(echo "$json" | jq --arg s "$CUR_SEV" '.severity = $s')
        echo "$tmp_json" | jq . > "$json_path"
        json=$(cat "$json_path")
        printf '  Severity downgraded: %s → %s\n' "$cur_sev" "$CUR_SEV"
    fi
}

# ── Gate call ──
if [[ "$GATE" == true ]]; then
    if [[ "$STATE" != "confirmed" && "$STATE" != "validated" ]]; then
        echo "Error: --gate requires --state confirmed or validated" >&2
        exit 1
    fi
    run_gate "$JSON_PATH"
    # Dry-run (advisory): print verdict only, mutate nothing, do not persist state.
    if [[ "$GATE_DRY_RUN" == true ]]; then
        printf '(advisory dry-run — no changes written to %s)\n' "$ID"
        exit 0
    fi
fi

# ── Helper: JSON array from bash array ──
json_array() {
    local arr=("$@")
    if [[ ${#arr[@]} -eq 0 ]]; then echo "[]"; return; fi
    printf '%s\n' "${arr[@]}" | jq -R . | jq -s .
}

# ── Update JSON ──
UPDATED=$(jq \
    --arg state "$STATE" \
    --arg ts "$TIMESTAMP" \
    '.validation = (.validation // {})
     | .validation.state = $state
     | .validation.checked_at = $ts
     | .updated_at = $ts' <<<"$SRC_JSON")

if [[ ${#METHODS[@]} -gt 0 ]]; then
    UPDATED=$(echo "$UPDATED" | jq --argjson m "$(json_array "${METHODS[@]}")" '.validation.method = $m')
fi
[[ -n "$NEGATIVE_CONTROL" ]] && UPDATED=$(echo "$UPDATED" | jq --arg v "$NEGATIVE_CONTROL" '.validation.negative_control = $v')
[[ -n "$SCREENSHOT" ]] && UPDATED=$(echo "$UPDATED" | jq --arg v "$SCREENSHOT" '.validation.screenshot = $v')
# Persist the class so a later --gate-dry-run (report-compiler) can re-derive the same
# verdicts without the caller re-supplying what was already known at promotion time.
[[ -n "$VULN_CLASS" ]] && UPDATED=$(echo "$UPDATED" | jq --arg v "$VULN_CLASS" '.validation.vuln_class = $v')
[[ -n "$VICTIM_DATA" ]] && UPDATED=$(echo "$UPDATED" | jq --argjson v "$([[ "$VICTIM_DATA" == yes ]] && echo true || echo false)" '.validation.victim_data = $v')
[[ -n "$BY" ]] && UPDATED=$(echo "$UPDATED" | jq --arg v "$BY" '.validation.checked_by = $v')
[[ -n "$NOTE" ]] && UPDATED=$(echo "$UPDATED" | jq --arg v "$NOTE" '.validation.notes = $v')

echo "$UPDATED" | jq . > "$JSON_PATH"

# On confirm, record the severity the finding can be filed at. Computed from the file just
# written so it sees the final state (the 7-question gate may have lowered severity).
if [[ "$STATE" == "confirmed" ]]; then
    FLOOR=$(python3 "$REPO/scripts/finding_state.py" floor --file "$JSON_PATH")
    jq --arg f "$FLOOR" '.floor_severity = (if $f == "" then null else $f end)' "$JSON_PATH" > "$JSON_PATH.tmp" && mv "$JSON_PATH.tmp" "$JSON_PATH"
    echo "floor severity: ${FLOOR:-none} (file at the floor; add escalations as comments)"
fi

# ── Patch companion markdown ──
if [[ -f "$MD_PATH" ]]; then
    TMP=$(mktemp)
    # 1) Update or insert the Validation row in the summary table
    if grep -qE '^\| \*\*Validation\*\* \|' "$MD_PATH"; then
        awk -v st="$STATE" '/^\| \*\*Validation\*\* \|/ { print "| **Validation** | " st " |"; next } { print }' "$MD_PATH" > "$TMP" && mv "$TMP" "$MD_PATH"
    else
        awk -v st="$STATE" '{ print } /^\| \*\*Status\*\* \|/ { print "| **Validation** | " st " |" }' "$MD_PATH" > "$TMP" && mv "$TMP" "$MD_PATH"
    fi
    # 2) Strip any existing "## Validation" section
    TMP=$(mktemp)
    awk '/^## Validation$/ { skip=1; next } skip && /^## / { skip=0 } !skip { print }' "$MD_PATH" > "$TMP" && mv "$TMP" "$MD_PATH"
    # 3) Append a fresh "## Validation" section
    {
        echo ""
        echo "## Validation"
        echo ""
        echo "- **State**: $STATE"
        [[ ${#METHODS[@]} -gt 0 ]] && echo "- **Method**: $(IFS=', '; echo "${METHODS[*]}")"
        [[ -n "$NEGATIVE_CONTROL" ]] && echo "- **Negative control**: $NEGATIVE_CONTROL"
        [[ -n "$SCREENSHOT" ]] && echo "- **Screenshot**: \`$SCREENSHOT\`"
        [[ -n "$NOTE" ]] && echo "- **Notes**: $NOTE"
        echo "- **Checked by**: ${BY:-unknown} at $TIMESTAMP"
    } >> "$MD_PATH"
fi

echo "$ID validation -> $STATE ($JSON_PATH)"

# Activity ledger (durable per-engagement record; best-effort). Project dir and agent come from
# the finding path: $PROJECT_DIR/<agent>/findings/<id>.json.
if declare -F _activity_event >/dev/null 2>&1; then
    case "$STATE" in
        confirmed) _ACT_VERDICT=confirmed ;;
        validated) _ACT_VERDICT=candidate ;;
        refuted)   _ACT_VERDICT=negative ;;
        *)         _ACT_VERDICT=n/a ;;
    esac
    _activity_event "$(dirname "$(dirname "$(dirname "$JSON_PATH")")")" validate \
        "${GRIMNIR_ACTOR:-$(basename "$(dirname "$(dirname "$JSON_PATH")")")}" \
        "$ID -> $STATE${METHODS[*]:+ (${METHODS[*]})}" --verdict "$_ACT_VERDICT" --ref "finding:$ID"
fi

# Emit to any event sink + update the finding index (optional — degrades gracefully).
# Resolve the engagement by PROGRAM (derived from the finding path) so the
# index update lands on the right engagement regardless of id-scheme drift.
if declare -F _sink_register_finding >/dev/null 2>&1; then
    _EMIT_PROGRAM="$(basename "$(dirname "$(dirname "$(dirname "$JSON_PATH")")")")"
    _EMIT_AGENT="$(basename "$(dirname "$(dirname "$JSON_PATH")")")"
    _EMIT_ENG_ID="$(_emit engagement_id_for "$_EMIT_PROGRAM")" || true
    _EMIT_SEV="$(echo "$UPDATED" | jq -r '.severity // "info"')"
    _EMIT_TITLE="$(echo "$UPDATED" | jq -r '.title // ""')"
    # Must match exactly what finding.sh registered, or validation updates land on a
    # different index row than the one creation made. An AGT-NNN id is already unique
    # and is used verbatim; only legacy FINDING-NNN gets the agent glued on.
    if [[ "$ID" =~ ^[A-Z]{3}-[0-9]{3}$ ]]; then
        _EMIT_FID="$ID"
    else
        _EMIT_FID="${_EMIT_AGENT}-${ID}"
    fi
    _emit finding_validated "$_EMIT_FID" "${_EMIT_ENG_ID:-$_EMIT_PROGRAM}" "$STATE" || true
    _emit register_finding "$_EMIT_FID" "$_EMIT_ENG_ID" "$_EMIT_PROGRAM" "$_EMIT_TITLE" \
        "$_EMIT_SEV" "$_EMIT_AGENT" "$STATE" "draft" "$JSON_PATH" || true
fi
