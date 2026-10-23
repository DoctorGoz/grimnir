#!/bin/bash
set -euo pipefail

# Grimnir Unified Finding Creator
# Creates structured JSON findings with optional companion markdown

# Report findings to an optional event sink (degrades gracefully if absent)
_FINDING_REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ -f "$_FINDING_REPO/scripts/event-emitter.sh" ]] && source "$_FINDING_REPO/scripts/event-emitter.sh"
declare -F _emit >/dev/null 2>&1 || _emit() { :; }

usage() {
    cat <<'EOF'
Usage: finding.sh --project-dir DIR --agent AGENT --severity SEV --title TITLE [OPTIONS]

Required:
  --project-dir DIR     Absolute path to project directory
  --agent AGENT         huginn | specter | artemis | hunter | nimbus | nomad
  --severity SEV        critical | high | medium | low | info
  --title TITLE         Finding title

Common options:
  --description TEXT    Vulnerability description
  --impact TEXT         Impact summary
  --target TARGET       Affected target (repeatable)
  --category CAT        Framework category e.g. API1, LLM01, NET02 (repeatable)
  --cwe CWE             CWE identifier e.g. CWE-639 (repeatable)
  --cvss SCORE          CVSS 3.1 base score
  --status STATUS       suspected | under_investigation | confirmed (default: suspected)
                        Triage status only — orthogonal to --validation-state and it does
                        NOT gate shipping. What may ship is validation_state == confirmed.
  --channel-rung RUNG   Response-channel rung for ssrf/imds (hunting Rule 32):
                        blind|partial|full|credential|execution. Absent = blind, which
                        caps the finding at medium in the evidence gate.
  --class CLASS         Vulnerability class for the evidence gate: ssrf|injection|sqli|ssti|
                        rce|imds|xxe | bola|idor|bfla|authz | xss|dom|redirect|csrf.
                        Recorded at creation so promotion knows which proof to demand --
                        validate-finding.sh re-derives it rather than asking again.
  --validation-state ST theoretical | validated | confirmed | refuted (default: theoretical)
                        Evidence strength, orthogonal to --status. New findings are
                        theoretical until promoted via validate-finding.sh. Only
                        confirmed findings ship in reports/submissions.
  --negative-control T  What the negative control was and its result (authz findings)
  --validation-method M manual-repro | negative-control | screenshot | second-opinion |
                        tool-output | out-of-band (repeatable)
  --validation-screenshot PATH  Screenshot (relative to $PROJECT_DIR) confirming the vuln
  --validated-by WHO    operator | grimnir | agent name
  --tag TAG             Free-form tag (repeatable)
  --reference URL       Reference URL (repeatable)
  --evidence-file PATH  Evidence file relative to $PROJECT_DIR (repeatable)
  --evidence-desc TEXT   Description for the preceding --evidence-file
  --step TEXT           Reproduction step (repeatable, ordered)
  --remediation TEXT    Remediation note (added to immediate)
  --chain-id ID         Attack chain ID (e.g. CHAIN-001) to link related findings
  --chain-position N    Position in the attack chain (1 = initial access, 2+)
  --claim SPEC          Seed one claim, "kind|severity|text|control" (repeatable), kind =
                        base | escalation. Verdict starts untested; ids are C1, C2, ... in
                        order. Exactly one base claim is required when any claim is given.
                        validate-finding.sh --claim-verdict then settles each one, and the
                        finding is filed at the floor: the highest severity whose claims
                        all survived (scripts/finding_state.py show).
  --repro               Scaffold $PROJECT_DIR/repro/<ID>.sh, a one-command operator repro
                        (creds by label placeholder from credentials.jsonl; prints
                        EXPECTED and ACTUAL). Fill in the request, then run it.
  --no-markdown         Skip companion markdown generation

Specter-specific:
  --endpoint TEXT       e.g. "GET /api/v1/users/{id}"
  --method METHOD       HTTP method
  --request TEXT        Raw request (inline or @filepath)
  --response TEXT       Raw response (inline or @filepath)
  --response-code N     HTTP response code

ARTEMIS-specific:
  --success-rate X/N    e.g. "4/5"
  --model TEXT          Identified model name
  --guardrail STATUS    bypassed | partially_bypassed | effective | not_present
  --attack-vector VEC   direct_injection | indirect_injection | etc.

Hunter-specific:
  --host IP             Affected host IP (repeatable)
  --port PORT           Affected port (repeatable)
  --protocol PROTO      Protocol (repeatable)
  --cve CVE-ID          CVE reference (repeatable)
  --service TEXT        Service name
  --service-version V   Service version
  --access-gained LVL   none | user | root | system | admin

Nimbus-specific (cloud):
  --provider P          aws | azure | gcp | other
  --account-id ID       Account / subscription / project id
  --region R            Cloud region
  --cloud-service S      e.g. s3, iam, lambda, ec2, storage, gke
  --resource R          ARN / resource id / bucket / role name
  --permission P        IAM action / permission abused
  --cloud-access LVL    none | read | write | admin | account-takeover
  --exploit TEXT        Exploit / technique used (cloud, mobile)

Nomad-specific (mobile):
  --platform P          android | ios
  --package-id ID       App package / bundle id
  --component C         Activity/service/receiver/provider/deeplink/url-scheme
  --exported            Component is exported / externally reachable
  --analysis A          static | dynamic
  --mobile-access LVL   none | local | data | account-takeover
  (also accepts --permission and --exploit)

Output:
  Creates AGT-NNN.json (and .md unless --no-markdown), e.g. SPE-004.json
  Prints finding ID and path to stdout
EOF
    exit 1
}

# ── Defaults ──
PROJECT_DIR=""
AGENT=""
SEVERITY=""
TITLE=""
DESCRIPTION=""
IMPACT_SUMMARY=""
STATUS="suspected"
VALIDATION_STATE="theoretical"
VULN_CLASS=""
CHANNEL_RUNG=""
NEGATIVE_CONTROL=""
VALIDATION_SCREENSHOT=""
VALIDATED_BY=""
CVSS=""
NO_MARKDOWN=false
CHAIN_ID=""
CHAIN_POSITION=""
REPRO=false

# Arrays
TARGETS=()
CATEGORIES=()
CWES=()
TAGS=()
REFERENCES=()
EVIDENCE_FILES=()
EVIDENCE_DESCS=()
STEPS=()
REMEDIATIONS=()
VALIDATION_METHODS=()
CLAIMS=()

# Specter
ENDPOINT=""
METHOD=""
REQUEST=""
RESPONSE=""
RESPONSE_CODE=""

# ARTEMIS
SUCCESS_RATE=""
MODEL=""
GUARDRAIL=""
ATTACK_VECTOR=""

# Hunter
HOSTS=()
PORTS=()
PROTOCOLS=()
CVES=()
SERVICE_NAME=""
SERVICE_VERSION=""
ACCESS_GAINED=""

# Nimbus (cloud) / shared exploit
PROVIDER=""
ACCOUNT_ID=""
REGION=""
CLOUD_SERVICE=""
RESOURCE=""
PERMISSION=""
CLOUD_ACCESS=""
EXPLOIT=""

# Nomad (mobile)
PLATFORM=""
PACKAGE_ID=""
COMPONENT=""
EXPORTED=""
ANALYSIS=""
MOBILE_ACCESS=""

# ── Parse arguments ──
while [[ $# -gt 0 ]]; do
    case "$1" in
        --project-dir)    PROJECT_DIR="$2"; shift 2 ;;
        --agent)          AGENT="$2"; shift 2 ;;
        --severity)       SEVERITY="$2"; shift 2 ;;
        --title)          TITLE="$2"; shift 2 ;;
        --description)    DESCRIPTION="$2"; shift 2 ;;
        --impact)         IMPACT_SUMMARY="$2"; shift 2 ;;
        --target)         TARGETS+=("$2"); shift 2 ;;
        --category)       CATEGORIES+=("$2"); shift 2 ;;
        --cwe)            CWES+=("$2"); shift 2 ;;
        --cvss)           CVSS="$2"; shift 2 ;;
        --status)         STATUS="$2"; shift 2 ;;
        --class)                 VULN_CLASS="$2"; shift 2 ;;
        --channel-rung)          CHANNEL_RUNG="$2"; shift 2 ;;
        --validation-state)      VALIDATION_STATE="$2"; shift 2 ;;
        --negative-control)      NEGATIVE_CONTROL="$2"; shift 2 ;;
        --validation-method)     VALIDATION_METHODS+=("$2"); shift 2 ;;
        --validation-screenshot) VALIDATION_SCREENSHOT="$2"; shift 2 ;;
        --validated-by)          VALIDATED_BY="$2"; shift 2 ;;
        --tag)            TAGS+=("$2"); shift 2 ;;
        --reference)      REFERENCES+=("$2"); shift 2 ;;
        --evidence-file)  EVIDENCE_FILES+=("$2"); shift 2 ;;
        --evidence-desc)  EVIDENCE_DESCS+=("$2"); shift 2 ;;
        --step)           STEPS+=("$2"); shift 2 ;;
        --remediation)    REMEDIATIONS+=("$2"); shift 2 ;;
        --chain-id)       CHAIN_ID="$2"; shift 2 ;;
        --chain-position)  CHAIN_POSITION="$2"; shift 2 ;;
        --claim)          CLAIMS+=("$2"); shift 2 ;;
        --repro)          REPRO=true; shift ;;
        --no-markdown)    NO_MARKDOWN=true; shift ;;
        --endpoint)       ENDPOINT="$2"; shift 2 ;;
        --method)         METHOD="$2"; shift 2 ;;
        --request)        REQUEST="$2"; shift 2 ;;
        --response)       RESPONSE="$2"; shift 2 ;;
        --response-code)  RESPONSE_CODE="$2"; shift 2 ;;
        --success-rate)   SUCCESS_RATE="$2"; shift 2 ;;
        --model)          MODEL="$2"; shift 2 ;;
        --guardrail)      GUARDRAIL="$2"; shift 2 ;;
        --attack-vector)  ATTACK_VECTOR="$2"; shift 2 ;;
        --host)           HOSTS+=("$2"); shift 2 ;;
        --port)           PORTS+=("$2"); shift 2 ;;
        --protocol)       PROTOCOLS+=("$2"); shift 2 ;;
        --cve)            CVES+=("$2"); shift 2 ;;
        --service)        SERVICE_NAME="$2"; shift 2 ;;
        --service-version) SERVICE_VERSION="$2"; shift 2 ;;
        --access-gained)  ACCESS_GAINED="$2"; shift 2 ;;
        --provider)       PROVIDER="$2"; shift 2 ;;
        --account-id)     ACCOUNT_ID="$2"; shift 2 ;;
        --region)         REGION="$2"; shift 2 ;;
        --cloud-service)  CLOUD_SERVICE="$2"; shift 2 ;;
        --resource)       RESOURCE="$2"; shift 2 ;;
        --permission)     PERMISSION="$2"; shift 2 ;;
        --cloud-access)   CLOUD_ACCESS="$2"; shift 2 ;;
        --exploit)        EXPLOIT="$2"; shift 2 ;;
        --platform)       PLATFORM="$2"; shift 2 ;;
        --package-id)     PACKAGE_ID="$2"; shift 2 ;;
        --component)      COMPONENT="$2"; shift 2 ;;
        --exported)       EXPORTED="true"; shift ;;
        --analysis)       ANALYSIS="$2"; shift 2 ;;
        --mobile-access)  MOBILE_ACCESS="$2"; shift 2 ;;
        --help|-h)        usage ;;
        *)                echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# ── Validate required fields ──
[[ -z "$PROJECT_DIR" ]] && { echo "Error: --project-dir is required" >&2; exit 1; }
[[ "$PROJECT_DIR" != /* ]] && { echo "Error: --project-dir must be an absolute path" >&2; exit 1; }
[[ -z "$AGENT" ]] && { echo "Error: --agent is required" >&2; exit 1; }
[[ "$AGENT" =~ ^(huginn|specter|artemis|hunter|nimbus|nomad)$ ]] || { echo "Error: --agent must be huginn, specter, artemis, hunter, nimbus, or nomad" >&2; exit 1; }
[[ -z "$SEVERITY" ]] && { echo "Error: --severity is required" >&2; exit 1; }
[[ "$SEVERITY" =~ ^(critical|high|medium|low|info)$ ]] || { echo "Error: invalid severity" >&2; exit 1; }
[[ -z "$TITLE" ]] && { echo "Error: --title is required" >&2; exit 1; }
{ [[ ${#TITLE} -lt 5 || ${#TITLE} -gt 200 ]]; } && { echo "Error: --title must be 5-200 chars — be descriptive (e.g. 'Reflected XSS in search param', not 'XSS')" >&2; exit 1; }
# Same vocabulary evidence_gate() switches on. Rejecting here means a typo surfaces at
# creation instead of silently disabling the gate at promotion (an unknown class is a
# deliberate no-op there, so "--class bolla" would quietly waive the proof requirement).
[[ -z "$VULN_CLASS" || "$VULN_CLASS" =~ ^(ssrf|injection|sqli|ssti|rce|imds|xxe|bola|idor|bfla|authz|authn|missing-auth|tier|infoleak|jwt|bopla|race|xss|dom|redirect|csrf)$ ]] || { echo "Error: --class '$VULN_CLASS' is not a class the evidence gate knows. Use one of: ssrf injection sqli ssti rce imds xxe bola idor bfla authz authn missing-auth tier infoleak jwt bopla race xss dom redirect csrf" >&2; exit 1; }
[[ "$VALIDATION_STATE" =~ ^(theoretical|validated|confirmed|refuted)$ ]] || { echo "Error: --validation-state must be theoretical, validated, confirmed, or refuted" >&2; exit 1; }

# ── Validate enum-constrained access levels (must match finding.schema.json; describe WHAT was accessed in --exploit/--description, not here) ──
[[ -n "$ACCESS_GAINED" && ! "$ACCESS_GAINED" =~ ^(none|user|root|system|admin)$ ]] && { echo "Error: --access-gained must be one of: none, user, root, system, admin" >&2; exit 1; }
[[ -n "$CLOUD_ACCESS"  && ! "$CLOUD_ACCESS"  =~ ^(none|read|write|admin|account-takeover)$ ]] && { echo "Error: --cloud-access must be one of: none, read, write, admin, account-takeover" >&2; exit 1; }
[[ -n "$MOBILE_ACCESS" && ! "$MOBILE_ACCESS" =~ ^(none|local|data|account-takeover)$ ]] && { echo "Error: --mobile-access must be one of: none, local, data, account-takeover" >&2; exit 1; }

# Claims: "kind|severity|text|control". Reject a malformed spec here, while the agent is
# still looking at it; a silently dropped claim would make the floor look better than it is.
CLAIMS_JSON="[]"
if [[ ${#CLAIMS[@]} -gt 0 ]]; then
    _nbase=0; _i=0
    for _spec in "${CLAIMS[@]}"; do
        _i=$((_i+1))
        IFS='|' read -r _k _s _t _c <<<"$_spec"
        [[ "$_k" =~ ^(base|escalation)$ ]] || { echo "Error: --claim kind must be base or escalation (got '$_k'): $_spec" >&2; exit 1; }
        [[ "$_s" =~ ^(critical|high|medium|low|info)$ ]] || { echo "Error: --claim severity invalid (got '$_s'): $_spec" >&2; exit 1; }
        [[ -n "$_t" ]] || { echo "Error: --claim needs text: $_spec" >&2; exit 1; }
        [[ "$_k" == base ]] && _nbase=$((_nbase+1))
        CLAIMS_JSON=$(jq --arg id "C$_i" --arg k "$_k" --arg s "$_s" --arg t "$_t" --arg c "${_c:-}" \
            '. + [{id:$id, kind:$k, text:$t, severity_if_true:$s, control:$c, verdict:"untested", evidence:[]}]' <<<"$CLAIMS_JSON")
    done
    [[ "$_nbase" -eq 1 ]] || { echo "Error: --claim needs exactly one base claim (got $_nbase)" >&2; exit 1; }
fi

# ── Determine finding number ──
FINDINGS_DIR="$PROJECT_DIR/$AGENT/findings"
mkdir -p "$FINDINGS_DIR"

# Finding ids are AGT-NNN: a three-letter agent prefix plus three digits. The old
# FINDING-NNN form was NOT unique across a project -- every agent numbered from 001, so
# a project could hold two distinct FINDING-003 and a tool resolving a bare id could
# (and did) write to the wrong one. The prefix makes the bare id globally unique.
# Migration policy: enforce forward, leave history alone; everything that reads a
# finding accepts both shapes.
agent_prefix() {
    case "$1" in
        huginn)  echo HUG ;; specter) echo SPE ;; artemis) echo ART ;;
        hunter)  echo HUN ;; nimbus)  echo NIM ;; nomad)   echo NOM ;;
        *) echo "Error: no id prefix defined for agent '$1'" >&2; exit 1 ;;
    esac
}
PREFIX="$(agent_prefix "$AGENT")"

# Continue from the highest number already present in EITHER shape, so a directory
# holding legacy FINDING-00N files does not get a colliding AGT-00N alongside them.
# (Counting files would also collide the moment one is deleted or numbered out of order.)
# `|| true` on the grep: an empty findings dir means it matches nothing and exits 1,
# which under `set -o pipefail` would kill the script on the FIRST finding of every
# engagement -- the one case that must always work.
HIGHEST=$({ find "$FINDINGS_DIR" -maxdepth 1 \( -name "${PREFIX}-*.json" -o -name 'FINDING-*.json' \) 2>/dev/null \
    | sed -E 's/.*-([0-9]{3})\.json$/\1/' | grep -E '^[0-9]{3}$' || true; } | sort -n | tail -1)
NEXT_NUM=$(printf "%03d" $(( 10#${HIGHEST:-0} + 1 )))
FINDING_ID="${PREFIX}-$NEXT_NUM"
TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# ── Helper: build JSON array from bash array ──
json_array() {
    local arr=("$@")
    if [[ ${#arr[@]} -eq 0 ]]; then
        echo "[]"
        return
    fi
    printf '%s\n' "${arr[@]}" | jq -R . | jq -s .
}

# ── Build base JSON ──
BASE=$(jq -n \
    --arg id "$FINDING_ID" \
    --arg title "$TITLE" \
    --arg severity "$SEVERITY" \
    --arg status "$STATUS" \
    --arg vstate "$VALIDATION_STATE" \
    --arg description "$DESCRIPTION" \
    --arg impact_summary "$IMPACT_SUMMARY" \
    --arg agent "$AGENT" \
    --arg created_at "$TIMESTAMP" \
    '{
        id: $id,
        title: $title,
        severity: $severity,
        status: $status,
        validation: { state: $vstate },
        description: $description,
        impact: { summary: $impact_summary },
        agent: $agent,
        created_at: $created_at,
        updated_at: $created_at
    }'
)

# Enrich the validation object if details were supplied at creation time
if [[ ${#VALIDATION_METHODS[@]} -gt 0 ]]; then
    BASE=$(echo "$BASE" | jq --argjson arr "$(json_array "${VALIDATION_METHODS[@]}")" '.validation.method = $arr')
fi

# ── Vulnerability-class inference ──────────────────────────────────────────────
# The evidence gate is armed by validation.vuln_class. Making that depend on a flag an
# agent has to remember produced ZERO classed findings across a real corpus, so the
# evidence gate never fired in production at all. The CWE and framework category are already being recorded;
# derive the class from those instead of asking for it twice.
#
# Deliberately CONSERVATIVE. A wrong class makes the gate demand the wrong artifact --
# worse than demanding nothing -- so only unambiguous identifiers map. CWE-200
# (information exposure, the single most common CWE in the corpus) and API8/API9
# (misconfiguration, inventory) map to nothing on purpose: they describe findings whose
# proof is the response itself, and many are on the never-submit list anyway.
infer_vuln_class() {
    [[ -n "$VULN_CLASS" ]] && return 0        # an explicit --class always wins
    local t
    for t in "${CWES[@]}"; do
        case "${t^^}" in
            CWE-639|CWE-284|CWE-285|CWE-862|CWE-863|CWE-566|CWE-1220|CWE-425)
                                   VULN_CLASS=authz ;;
            CWE-918)               VULN_CLASS=ssrf ;;
            CWE-79|CWE-80)         VULN_CLASS=xss ;;
            CWE-89)                VULN_CLASS=sqli ;;
            CWE-943|CWE-77|CWE-78|CWE-74|CWE-1336|CWE-94)
                                   VULN_CLASS=injection ;;
            CWE-352)               VULN_CLASS=csrf ;;
            CWE-601)               VULN_CLASS=redirect ;;
            CWE-611|CWE-827)       VULN_CLASS=xxe ;;
            CWE-502)               VULN_CLASS=rce ;;
        esac
        [[ -n "$VULN_CLASS" ]] && { CLASS_INFERRED_FROM="$t"; return 0; }
    done
    for t in "${CATEGORIES[@]}"; do
        case "${t^^}" in
            API1|API5|MCP02|MCP10) VULN_CLASS=authz ;;
            API7)                  VULN_CLASS=ssrf ;;
        esac
        [[ -n "$VULN_CLASS" ]] && { CLASS_INFERRED_FROM="$t"; return 0; }
    done
    return 0
}
infer_vuln_class

# An unclassed high/critical finding is the one that slips past the gate entirely, so say
# so while the context is still in hand -- at report time it is too late to go get proof.
case "$SEVERITY" in
    critical|high)
        if [[ -z "$VULN_CLASS" ]]; then
            printf 'WARNING: %s severity finding has no vulnerability class, so the evidence gate cannot enforce a proof for it.\n' "$SEVERITY" >&2
            printf '         Pass --class (ssrf|injection|sqli|ssti|rce|imds|xxe|bola|idor|bfla|authz|xss|dom|redirect|csrf),\n' >&2
            printf '         or a --cwe / --category it can be derived from. Leave it unset only if no class applies.\n' >&2
        fi ;;
esac

[[ -n "$VULN_CLASS" ]] && BASE=$(echo "$BASE" | jq --arg v "$VULN_CLASS" '.validation.vuln_class = $v')
[[ -z "$CHANNEL_RUNG" || "$CHANNEL_RUNG" =~ ^(blind|partial|full|credential|execution)$ ]] || { echo "Error: --channel-rung '$CHANNEL_RUNG' is not a rung. Use blind|partial|full|credential|execution." >&2; exit 1; }
[[ -n "$CHANNEL_RUNG" ]] && BASE=$(echo "$BASE" | jq --arg v "$CHANNEL_RUNG" '.validation.channel_rung = $v')
[[ -n "$NEGATIVE_CONTROL" ]] && BASE=$(echo "$BASE" | jq --arg v "$NEGATIVE_CONTROL" '.validation.negative_control = $v')
[[ -n "$VALIDATION_SCREENSHOT" ]] && BASE=$(echo "$BASE" | jq --arg v "$VALIDATION_SCREENSHOT" '.validation.screenshot = $v')
[[ -n "$VALIDATED_BY" ]] && BASE=$(echo "$BASE" | jq --arg v "$VALIDATED_BY" '.validation.checked_by = $v')
# Stamp checked_at whenever the finding is created above 'theoretical'
if [[ "$VALIDATION_STATE" != "theoretical" ]]; then
    BASE=$(echo "$BASE" | jq --arg t "$TIMESTAMP" '.validation.checked_at = $t')
fi

[[ ${#CLAIMS[@]} -gt 0 ]] && BASE=$(echo "$BASE" | jq --argjson c "$CLAIMS_JSON" '.claims = $c')

# Add CVSS if provided
if [[ -n "$CVSS" ]]; then
    BASE=$(echo "$BASE" | jq --argjson cvss "$CVSS" '.cvss_score = $cvss')
fi

# Add arrays
if [[ ${#TARGETS[@]} -gt 0 ]]; then
    BASE=$(echo "$BASE" | jq --argjson arr "$(json_array "${TARGETS[@]}")" '.affected_targets = $arr')
fi

if [[ ${#TAGS[@]} -gt 0 ]]; then
    BASE=$(echo "$BASE" | jq --argjson arr "$(json_array "${TAGS[@]}")" '.tags = $arr')
fi

# Add attack chain fields
if [[ -n "$CHAIN_ID" ]]; then
    BASE=$(echo "$BASE" | jq --arg cid "$CHAIN_ID" '.chain_id = $cid')
    if [[ -n "$CHAIN_POSITION" ]]; then
        BASE=$(echo "$BASE" | jq --argjson pos "$CHAIN_POSITION" '.chain_position = $pos')
    fi
fi

if [[ ${#REFERENCES[@]} -gt 0 ]]; then
    BASE=$(echo "$BASE" | jq --argjson arr "$(json_array "${REFERENCES[@]}")" '.references = $arr')
fi

if [[ ${#STEPS[@]} -gt 0 ]]; then
    BASE=$(echo "$BASE" | jq --argjson arr "$(json_array "${STEPS[@]}")" '.reproduction_steps = $arr')
fi

if [[ ${#REMEDIATIONS[@]} -gt 0 ]]; then
    BASE=$(echo "$BASE" | jq --argjson arr "$(json_array "${REMEDIATIONS[@]}")" '.remediation = { immediate: $arr }')
fi

# ── Build evidence array ──
if [[ ${#EVIDENCE_FILES[@]} -gt 0 ]]; then
    EV_JSON="[]"
    for i in "${!EVIDENCE_FILES[@]}"; do
        DESC="${EVIDENCE_DESCS[$i]:-"Evidence file"}"
        EV_JSON=$(echo "$EV_JSON" | jq \
            --arg path "${EVIDENCE_FILES[$i]}" \
            --arg desc "$DESC" \
            '. + [{"type": "file", "description": $desc, "path": $path}]')
    done
    BASE=$(echo "$BASE" | jq --argjson ev "$EV_JSON" '.evidence = $ev')
fi

# ── Build framework mappings ──
FRAMEWORKS="{}"
for cat in "${CATEGORIES[@]}"; do
    if [[ "$cat" =~ ^API[0-9] ]]; then
        FRAMEWORKS=$(echo "$FRAMEWORKS" | jq --arg c "$cat" '.owasp_api = (.owasp_api // []) + [$c]')
    elif [[ "$cat" =~ ^LLM[0-9] ]]; then
        FRAMEWORKS=$(echo "$FRAMEWORKS" | jq --arg c "$cat" '.owasp_llm = (.owasp_llm // []) + [$c]')
    elif [[ "$cat" =~ ^ASI[0-9] ]]; then
        FRAMEWORKS=$(echo "$FRAMEWORKS" | jq --arg c "$cat" '.owasp_agentic = (.owasp_agentic // []) + [$c]')
    elif [[ "$cat" =~ ^NET[0-9] ]]; then
        FRAMEWORKS=$(echo "$FRAMEWORKS" | jq --arg c "$cat" '.ptes = (.ptes // []) + [$c]')
    elif [[ "$cat" =~ ^WSTG ]]; then
        FRAMEWORKS=$(echo "$FRAMEWORKS" | jq --arg c "$cat" '.owasp_wstg = (.owasp_wstg // []) + [$c]')
    elif [[ "$cat" =~ ^T[0-9] ]]; then
        FRAMEWORKS=$(echo "$FRAMEWORKS" | jq --arg c "$cat" '.mitre_attack = (.mitre_attack // []) + [$c]')
    elif [[ "$cat" =~ ^AML ]]; then
        FRAMEWORKS=$(echo "$FRAMEWORKS" | jq --arg c "$cat" '.mitre_atlas = (.mitre_atlas // []) + [$c]')
    fi
done

if [[ ${#CWES[@]} -gt 0 ]]; then
    FRAMEWORKS=$(echo "$FRAMEWORKS" | jq --argjson arr "$(json_array "${CWES[@]}")" '.cwe = $arr')
fi

if [[ "$FRAMEWORKS" != "{}" ]]; then
    BASE=$(echo "$BASE" | jq --argjson fw "$FRAMEWORKS" '.frameworks = $fw')
fi

# ── Agent-specific extensions ──
case "$AGENT" in
    specter)
        EXT="{}"
        [[ -n "$ENDPOINT" ]] && EXT=$(echo "$EXT" | jq --arg v "$ENDPOINT" '.endpoint = $v')
        [[ -n "$METHOD" ]] && EXT=$(echo "$EXT" | jq --arg v "$METHOD" '.method = $v')
        # request/response can carry raw control bytes or invalid UTF-8 (binary bodies,
        # overlong WAF-evasion payloads). jq would silently rewrite those to U+FFFD and the
        # evidence would no longer match what was sent, so normalise: clean text stays literal,
        # anything else is base64'd and flagged (schema: request_encoding/response_encoding).
        if [[ -n "$REQUEST" ]]; then
            RF=$(printf '%s' "$REQUEST" | python3 "$_FINDING_REPO/scripts/field-encode.py")
            EXT=$(echo "$EXT" | jq --argjson rf "$RF" \
                '.request = $rf.value | (if $rf.encoding=="base64" then .request_encoding="base64" else . end)')
        fi
        if [[ -n "$RESPONSE" ]]; then
            RF=$(printf '%s' "$RESPONSE" | python3 "$_FINDING_REPO/scripts/field-encode.py")
            EXT=$(echo "$EXT" | jq --argjson rf "$RF" \
                '.response = $rf.value | (if $rf.encoding=="base64" then .response_encoding="base64" else . end)')
        fi
        [[ -n "$RESPONSE_CODE" ]] && EXT=$(echo "$EXT" | jq --argjson v "$RESPONSE_CODE" '.response_code = $v')
        [[ "$EXT" != "{}" ]] && BASE=$(echo "$BASE" | jq --argjson ext "$EXT" '.specter_ext = $ext')
        ;;
    artemis)
        EXT="{}"
        if [[ -n "$SUCCESS_RATE" ]]; then
            SUCC=$(echo "$SUCCESS_RATE" | cut -d/ -f1)
            ATT=$(echo "$SUCCESS_RATE" | cut -d/ -f2)
            EXT=$(echo "$EXT" | jq --argjson s "$SUCC" --argjson a "$ATT" '.success_rate = {successes: $s, attempts: $a}')
        fi
        [[ -n "$MODEL" ]] && EXT=$(echo "$EXT" | jq --arg v "$MODEL" '.model_identified = $v')
        [[ -n "$GUARDRAIL" ]] && EXT=$(echo "$EXT" | jq --arg v "$GUARDRAIL" '.guardrail_status = $v')
        [[ -n "$ATTACK_VECTOR" ]] && EXT=$(echo "$EXT" | jq --arg v "$ATTACK_VECTOR" '.attack_vector = $v')
        [[ "$EXT" != "{}" ]] && BASE=$(echo "$BASE" | jq --argjson ext "$EXT" '.artemis_ext = $ext')
        ;;
    hunter)
        EXT="{}"
        if [[ ${#HOSTS[@]} -gt 0 ]]; then
            HOSTS_JSON="[]"
            for h in "${HOSTS[@]}"; do
                HOSTS_JSON=$(echo "$HOSTS_JSON" | jq --arg ip "$h" '. + [{"ip": $ip}]')
            done
            EXT=$(echo "$EXT" | jq --argjson h "$HOSTS_JSON" '.affected_hosts = $h')
        fi
        if [[ ${#PORTS[@]} -gt 0 ]]; then
            PORTS_JSON=$(printf '%s\n' "${PORTS[@]}" | jq -R 'tonumber' | jq -s .)
            EXT=$(echo "$EXT" | jq --argjson p "$PORTS_JSON" '.ports = $p')
        fi
        if [[ ${#PROTOCOLS[@]} -gt 0 ]]; then
            EXT=$(echo "$EXT" | jq --argjson p "$(json_array "${PROTOCOLS[@]}")" '.protocols = $p')
        fi
        [[ -n "$SERVICE_NAME" ]] && EXT=$(echo "$EXT" | jq --arg v "$SERVICE_NAME" '.service_name = $v')
        [[ -n "$SERVICE_VERSION" ]] && EXT=$(echo "$EXT" | jq --arg v "$SERVICE_VERSION" '.service_version = $v')
        if [[ ${#CVES[@]} -gt 0 ]]; then
            EXT=$(echo "$EXT" | jq --argjson c "$(json_array "${CVES[@]}")" '.cve_ids = $c')
        fi
        [[ -n "$ACCESS_GAINED" ]] && EXT=$(echo "$EXT" | jq --arg v "$ACCESS_GAINED" '.access_gained = $v')
        [[ "$EXT" != "{}" ]] && BASE=$(echo "$BASE" | jq --argjson ext "$EXT" '.hunter_ext = $ext')
        ;;
    nimbus)
        EXT="{}"
        [[ -n "$PROVIDER" ]] && EXT=$(echo "$EXT" | jq --arg v "$PROVIDER" '.provider = $v')
        [[ -n "$ACCOUNT_ID" ]] && EXT=$(echo "$EXT" | jq --arg v "$ACCOUNT_ID" '.account_id = $v')
        [[ -n "$REGION" ]] && EXT=$(echo "$EXT" | jq --arg v "$REGION" '.region = $v')
        [[ -n "$CLOUD_SERVICE" ]] && EXT=$(echo "$EXT" | jq --arg v "$CLOUD_SERVICE" '.service = $v')
        [[ -n "$RESOURCE" ]] && EXT=$(echo "$EXT" | jq --arg v "$RESOURCE" '.resource = $v')
        [[ -n "$PERMISSION" ]] && EXT=$(echo "$EXT" | jq --arg v "$PERMISSION" '.permission = $v')
        [[ -n "$EXPLOIT" ]] && EXT=$(echo "$EXT" | jq --arg v "$EXPLOIT" '.exploit = $v')
        [[ -n "$CLOUD_ACCESS" ]] && EXT=$(echo "$EXT" | jq --arg v "$CLOUD_ACCESS" '.access_gained = $v')
        [[ "$EXT" != "{}" ]] && BASE=$(echo "$BASE" | jq --argjson ext "$EXT" '.cloud_ext = $ext')
        ;;
    nomad)
        EXT="{}"
        [[ -n "$PLATFORM" ]] && EXT=$(echo "$EXT" | jq --arg v "$PLATFORM" '.platform = $v')
        [[ -n "$PACKAGE_ID" ]] && EXT=$(echo "$EXT" | jq --arg v "$PACKAGE_ID" '.package_id = $v')
        [[ -n "$COMPONENT" ]] && EXT=$(echo "$EXT" | jq --arg v "$COMPONENT" '.component = $v')
        [[ -n "$EXPORTED" ]] && EXT=$(echo "$EXT" | jq --argjson v "$EXPORTED" '.exported = $v')
        [[ -n "$PERMISSION" ]] && EXT=$(echo "$EXT" | jq --arg v "$PERMISSION" '.permission = $v')
        [[ -n "$ANALYSIS" ]] && EXT=$(echo "$EXT" | jq --arg v "$ANALYSIS" '.analysis = $v')
        [[ -n "$EXPLOIT" ]] && EXT=$(echo "$EXT" | jq --arg v "$EXPLOIT" '.exploit = $v')
        [[ -n "$MOBILE_ACCESS" ]] && EXT=$(echo "$EXT" | jq --arg v "$MOBILE_ACCESS" '.access_gained = $v')
        [[ "$EXT" != "{}" ]] && BASE=$(echo "$BASE" | jq --argjson ext "$EXT" '.mobile_ext = $ext')
        ;;
esac

# ── Write JSON ──
JSON_PATH="$FINDINGS_DIR/$FINDING_ID.json"
echo "$BASE" | jq . > "$JSON_PATH"

# ── Generate companion markdown ──
if [[ "$NO_MARKDOWN" != true ]]; then
    MD_PATH="$FINDINGS_DIR/$FINDING_ID.md"
    SEV_UPPER=$(echo "$SEVERITY" | tr '[:lower:]' '[:upper:]')

    cat > "$MD_PATH" <<MDEOF
# $FINDING_ID: $TITLE

| Field | Value |
|-------|-------|
| **Severity** | $SEV_UPPER |
| **CVSS** | ${CVSS:-N/A} |
| **Status** | $STATUS |
| **Validation** | $VALIDATION_STATE |
| **Agent** | $AGENT |
| **Created** | $TIMESTAMP |
MDEOF

    # Validation detail (only when there is more than the default state)
    if [[ -n "$NEGATIVE_CONTROL" || ${#VALIDATION_METHODS[@]} -gt 0 || -n "$VALIDATION_SCREENSHOT" ]]; then
        echo "" >> "$MD_PATH"
        echo "## Validation" >> "$MD_PATH"
        echo "" >> "$MD_PATH"
        echo "- **State**: $VALIDATION_STATE" >> "$MD_PATH"
        [[ ${#VALIDATION_METHODS[@]} -gt 0 ]] && echo "- **Method**: $(IFS=', '; echo "${VALIDATION_METHODS[*]}")" >> "$MD_PATH"
        [[ -n "$NEGATIVE_CONTROL" ]] && echo "- **Negative control**: $NEGATIVE_CONTROL" >> "$MD_PATH"
        [[ -n "$VALIDATION_SCREENSHOT" ]] && echo "- **Screenshot**: \`$VALIDATION_SCREENSHOT\`" >> "$MD_PATH"
        [[ -n "$VALIDATED_BY" ]] && echo "- **Checked by**: $VALIDATED_BY" >> "$MD_PATH"
    fi

    # Attack chain
    if [[ -n "$CHAIN_ID" ]]; then
        echo "| **Chain** | $CHAIN_ID (step ${CHAIN_POSITION:-?}) |" >> "$MD_PATH"
    fi

    # Framework categories
    if [[ ${#CATEGORIES[@]} -gt 0 ]]; then
        echo "| **Categories** | $(IFS=', '; echo "${CATEGORIES[*]}") |" >> "$MD_PATH"
    fi
    if [[ ${#CWES[@]} -gt 0 ]]; then
        echo "| **CWE** | $(IFS=', '; echo "${CWES[*]}") |" >> "$MD_PATH"
    fi

    echo "" >> "$MD_PATH"

    # Description
    if [[ -n "$DESCRIPTION" ]]; then
        echo "## Description" >> "$MD_PATH"
        echo "" >> "$MD_PATH"
        echo "$DESCRIPTION" >> "$MD_PATH"
        echo "" >> "$MD_PATH"
    fi

    # Affected targets
    if [[ ${#TARGETS[@]} -gt 0 ]]; then
        echo "## Affected Targets" >> "$MD_PATH"
        echo "" >> "$MD_PATH"
        for t in "${TARGETS[@]}"; do
            echo "- \`$t\`" >> "$MD_PATH"
        done
        echo "" >> "$MD_PATH"
    fi

    # Agent-specific details
    case "$AGENT" in
        specter)
            if [[ -n "$ENDPOINT" || -n "$METHOD" ]]; then
                echo "## Technical Details" >> "$MD_PATH"
                echo "" >> "$MD_PATH"
                [[ -n "$ENDPOINT" ]] && echo "- **Endpoint**: \`$ENDPOINT\`" >> "$MD_PATH"
                [[ -n "$METHOD" ]] && echo "- **Method**: $METHOD" >> "$MD_PATH"
                [[ -n "$RESPONSE_CODE" ]] && echo "- **Response Code**: $RESPONSE_CODE" >> "$MD_PATH"
                echo "" >> "$MD_PATH"
            fi
            ;;
        artemis)
            if [[ -n "$SUCCESS_RATE" || -n "$MODEL" || -n "$GUARDRAIL" ]]; then
                echo "## Technical Details" >> "$MD_PATH"
                echo "" >> "$MD_PATH"
                [[ -n "$SUCCESS_RATE" ]] && echo "- **Success Rate**: $SUCCESS_RATE" >> "$MD_PATH"
                [[ -n "$MODEL" ]] && echo "- **Model**: $MODEL" >> "$MD_PATH"
                [[ -n "$GUARDRAIL" ]] && echo "- **Guardrail Status**: $GUARDRAIL" >> "$MD_PATH"
                [[ -n "$ATTACK_VECTOR" ]] && echo "- **Attack Vector**: $ATTACK_VECTOR" >> "$MD_PATH"
                echo "" >> "$MD_PATH"
            fi
            ;;
        hunter)
            if [[ ${#HOSTS[@]} -gt 0 || -n "$SERVICE_NAME" ]]; then
                echo "## Technical Details" >> "$MD_PATH"
                echo "" >> "$MD_PATH"
                [[ ${#HOSTS[@]} -gt 0 ]] && echo "- **Hosts**: $(IFS=', '; echo "${HOSTS[*]}")" >> "$MD_PATH"
                [[ ${#PORTS[@]} -gt 0 ]] && echo "- **Ports**: $(IFS=', '; echo "${PORTS[*]}")" >> "$MD_PATH"
                [[ -n "$SERVICE_NAME" ]] && echo "- **Service**: $SERVICE_NAME ${SERVICE_VERSION:-}" >> "$MD_PATH"
                [[ -n "$ACCESS_GAINED" ]] && echo "- **Access Gained**: $ACCESS_GAINED" >> "$MD_PATH"
                [[ ${#CVES[@]} -gt 0 ]] && echo "- **CVEs**: $(IFS=', '; echo "${CVES[*]}")" >> "$MD_PATH"
                echo "" >> "$MD_PATH"
            fi
            ;;
        nimbus)
            if [[ -n "$PROVIDER" || -n "$RESOURCE" || -n "$CLOUD_SERVICE" ]]; then
                echo "## Technical Details" >> "$MD_PATH"
                echo "" >> "$MD_PATH"
                [[ -n "$PROVIDER" ]] && echo "- **Provider**: $PROVIDER" >> "$MD_PATH"
                [[ -n "$ACCOUNT_ID" ]] && echo "- **Account**: $ACCOUNT_ID" >> "$MD_PATH"
                [[ -n "$REGION" ]] && echo "- **Region**: $REGION" >> "$MD_PATH"
                [[ -n "$CLOUD_SERVICE" ]] && echo "- **Service**: $CLOUD_SERVICE" >> "$MD_PATH"
                [[ -n "$RESOURCE" ]] && echo "- **Resource**: \`$RESOURCE\`" >> "$MD_PATH"
                [[ -n "$PERMISSION" ]] && echo "- **Permission**: $PERMISSION" >> "$MD_PATH"
                [[ -n "$CLOUD_ACCESS" ]] && echo "- **Access Gained**: $CLOUD_ACCESS" >> "$MD_PATH"
                [[ -n "$EXPLOIT" ]] && echo "- **Exploit**: $EXPLOIT" >> "$MD_PATH"
                echo "" >> "$MD_PATH"
            fi
            ;;
        nomad)
            if [[ -n "$PLATFORM" || -n "$PACKAGE_ID" || -n "$COMPONENT" ]]; then
                echo "## Technical Details" >> "$MD_PATH"
                echo "" >> "$MD_PATH"
                [[ -n "$PLATFORM" ]] && echo "- **Platform**: $PLATFORM" >> "$MD_PATH"
                [[ -n "$PACKAGE_ID" ]] && echo "- **Package**: \`$PACKAGE_ID\`" >> "$MD_PATH"
                [[ -n "$COMPONENT" ]] && echo "- **Component**: $COMPONENT" >> "$MD_PATH"
                [[ -n "$EXPORTED" ]] && echo "- **Exported**: $EXPORTED" >> "$MD_PATH"
                [[ -n "$PERMISSION" ]] && echo "- **Permission**: $PERMISSION" >> "$MD_PATH"
                [[ -n "$ANALYSIS" ]] && echo "- **Analysis**: $ANALYSIS" >> "$MD_PATH"
                [[ -n "$MOBILE_ACCESS" ]] && echo "- **Access Gained**: $MOBILE_ACCESS" >> "$MD_PATH"
                [[ -n "$EXPLOIT" ]] && echo "- **Exploit**: $EXPLOIT" >> "$MD_PATH"
                echo "" >> "$MD_PATH"
            fi
            ;;
    esac

    # Impact
    if [[ -n "$IMPACT_SUMMARY" ]]; then
        echo "## Impact" >> "$MD_PATH"
        echo "" >> "$MD_PATH"
        echo "$IMPACT_SUMMARY" >> "$MD_PATH"
        echo "" >> "$MD_PATH"
    fi

    # Reproduction steps
    if [[ ${#STEPS[@]} -gt 0 ]]; then
        echo "## Steps to Reproduce" >> "$MD_PATH"
        echo "" >> "$MD_PATH"
        for i in "${!STEPS[@]}"; do
            echo "$((i+1)). ${STEPS[$i]}" >> "$MD_PATH"
        done
        echo "" >> "$MD_PATH"
    fi

    # Evidence
    if [[ ${#EVIDENCE_FILES[@]} -gt 0 ]]; then
        echo "## Evidence" >> "$MD_PATH"
        echo "" >> "$MD_PATH"
        for i in "${!EVIDENCE_FILES[@]}"; do
            DESC="${EVIDENCE_DESCS[$i]:-"Evidence file"}"
            echo "- $DESC: \`${EVIDENCE_FILES[$i]}\`" >> "$MD_PATH"
        done
        echo "" >> "$MD_PATH"
    fi

    # Remediation
    if [[ ${#REMEDIATIONS[@]} -gt 0 ]]; then
        echo "## Remediation" >> "$MD_PATH"
        echo "" >> "$MD_PATH"
        for r in "${REMEDIATIONS[@]}"; do
            echo "- $r" >> "$MD_PATH"
        done
        echo "" >> "$MD_PATH"
    fi

    # References
    if [[ ${#REFERENCES[@]} -gt 0 ]]; then
        echo "## References" >> "$MD_PATH"
        echo "" >> "$MD_PATH"
        for ref in "${REFERENCES[@]}"; do
            echo "- $ref" >> "$MD_PATH"
        done
        echo "" >> "$MD_PATH"
    fi
fi

# ── Operator repro scaffold ──
# One command a human can run cold. Placeholders only: credentials are looked up by label
# from the engagement vault at run time, so no real value is ever baked into the script.
if [[ "$REPRO" == true ]]; then
    REPRO_PATH="$PROJECT_DIR/repro/$FINDING_ID.sh"
    mkdir -p "$PROJECT_DIR/repro"
    cat > "$REPRO_PATH" <<REPRO_EOF
#!/usr/bin/env bash
# Repro for $FINDING_ID: $TITLE
# Usage: PROJECT_DIR=<engagement dir> bash $FINDING_ID.sh
# Fill in the CONFIG block, run, compare ACTUAL with EXPECTED.
set -euo pipefail

PROJECT_DIR="\${PROJECT_DIR:?set PROJECT_DIR to the engagement directory}"
CRED_LABEL="REPLACE_WITH_CREDENTIAL_LABEL"          # row label in credentials.jsonl
URL="https://target.example.com/REPLACE_PATH"
METHOD="GET"
EXPECTED="REPLACE: status and marker proving the base claim, e.g. 200 and a field from another account"

TOKEN=\$(jq -r --arg l "\$CRED_LABEL" 'select(.label == \$l) | (.token // .value)' "\$PROJECT_DIR/credentials.jsonl" | head -1)
[[ -n "\$TOKEN" && "\$TOKEN" != null ]] || { echo "no credential labelled \$CRED_LABEL" >&2; exit 2; }

echo "EXPECTED: \$EXPECTED"
BODY=\$(mktemp); trap 'rm -f "\$BODY"' EXIT
# Single request; add -d / extra -H flags for the real call.
CODE=\$(curl -sS -m 30 -o "\$BODY" -w '%{http_code}' -X "\$METHOD" -H "Authorization: Bearer \$TOKEN" "\$URL") || CODE=curl-failed
echo "ACTUAL:   \$CODE \$(head -c 200 "\$BODY" | tr '\\n' ' ')"
REPRO_EOF
    chmod +x "$REPRO_PATH"
    echo "repro scaffold: $REPRO_PATH" >&2
fi

# ── Report to an event sink (optional; never blocks finding creation) ──
if declare -F _sink_register_finding >/dev/null 2>&1; then
    PROGRAM="$(basename "$PROJECT_DIR")"
    _EMIT_ENG="$(_emit engagement_id_for "$PROGRAM")" || true
    # An AGT-NNN id is already globally unique; only the legacy FINDING-NNN shape needs
    # the agent glued on to avoid colliding in the sink index.
    if [[ "$FINDING_ID" =~ ^[A-Z]{3}-[0-9]{3}$ ]]; then
        _EMIT_FID="$FINDING_ID"
    else
        _EMIT_FID="${AGENT}-${FINDING_ID}"
    fi
    _emit finding_created "$_EMIT_FID" "${_EMIT_ENG:-$PROGRAM}" "$SEVERITY" "$AGENT" "$TITLE" || true
    _emit register_finding "$_EMIT_FID" "$_EMIT_ENG" "$PROGRAM" "$TITLE" "$SEVERITY" "$AGENT" "$VALIDATION_STATE" "draft" "$JSON_PATH" || true
fi

# ── Activity ledger (durable per-engagement record; best-effort) ──
if declare -F _activity_event >/dev/null 2>&1; then
    _ACT_VERDICT="candidate"
    [[ "$VALIDATION_STATE" == "confirmed" ]] && _ACT_VERDICT="confirmed"
    _activity_event "$PROJECT_DIR" finding "${GRIMNIR_ACTOR:-$AGENT}" \
        "$FINDING_ID [$SEVERITY] $TITLE" --verdict "$_ACT_VERDICT" \
        --ref "finding:$FINDING_ID" ${ENDPOINT:+--target "$ENDPOINT"}
fi

echo "$FINDING_ID $JSON_PATH"
