#!/usr/bin/env bash
# reachability.sh — intelligence-layer LANE gate (see ROADMAP-intelligence-layer.md).
# Before dispatching specialists, label each high-value lane REACHABLE / GATED(gate) /
# UNKNOWN against the gate taxonomy, given what the operator holds. The point: stop
# entering gated/dead lanes BEFORE the expensive testing — the #1 documented source of
# fruitless effort.
#
# Mechanism vs judgment: this pre-fills the gates you HOLD (from the intake's "Account
# Capabilities" block) + stack-known gates (from the lessons loader) and auto-verdicts
# the most common high-value lane (cross-account authz). YOU complete the rest of the
# matrix from classification.md. The tool structures the question and fills known
# answers; it does not fake precision.
#
# Gate taxonomy: kyc funded-balance second-account first-credential oauth-app
#                device paid-tier geo-egress browser-interactive otp-2fa approval-role
#
# first-credential = at least one working bearer/account (the FIRST token). OAuth/JWT/token
#   lanes need it before they can do ANYTHING — a lane declaring it must not be planned
#   REACHABLE at zero credentials. Auto-derived from "Accounts held" (>=1 => held).
# oauth-app = the operator has registered an OAuth application / client we control (client_id
#   + redirect_uri) for lanes that require standing up our own client. Not auto-derivable;
#   default not-held, set with set-gate when you have registered one.
#
# Usage:
#   scripts/reachability.sh init --project-dir DIR [--handle H] [--stack S] [--force]
#   scripts/reachability.sh show --project-dir DIR
#   scripts/reachability.sh set-gate --project-dir DIR --gate G --held true|false
#   scripts/reachability.sh sync --project-dir DIR
#
# set-gate/sync keep reachability.json CURRENT as gates get unlocked mid-engagement
# (accounts registered, emulator stood up). The playbook matcher reads gates_held, so a
# stale file silently BLOCKS lanes you can actually reach — re-sync when a gate flips.
set -euo pipefail

LESSONS_QUERY="${GRIMNIR_LESSONS_QUERY:-$HOME/.grimnir/lessons/lessons-query.py}"

CMD="${1:-}"; shift || true
PROJECT_DIR=""; HANDLE=""; STACK=""; FORCE=false; GATE=""; HELD=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --project-dir) PROJECT_DIR="$2"; shift 2 ;;
    --handle)      HANDLE="$2"; shift 2 ;;
    --stack)       STACK="$2"; shift 2 ;;
    --gate)        GATE="$2"; shift 2 ;;
    --held)        HELD="$2"; shift 2 ;;
    --force)       FORCE=true; shift ;;
    -h|--help)     sed -n '2,24p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done
[[ -z "$PROJECT_DIR" ]] && { echo "Error: --project-dir required" >&2; exit 1; }
[[ "$PROJECT_DIR" != /* ]] && { echo "Error: --project-dir must be absolute" >&2; exit 1; }

INTAKE="$PROJECT_DIR/project.md"
RJSON="$PROJECT_DIR/reachability.json"
RMD="$PROJECT_DIR/reachability.md"
PROJECT="$(basename "$PROJECT_DIR")"

# Read a value from an intake "Account Capabilities" bullet:
#   "- Accounts held: 2"  ->  "2"   (label matched as a prefix up to the colon)
cap() {
  [[ -f "$INTAKE" ]] || { echo ""; return 0; }
  # `|| true` so a no-match grep does not trip pipefail+set -e (the bullet is optional).
  { grep -iE "^[[:space:]]*-[[:space:]]*$1[^:]*:" "$INTAKE" 2>/dev/null || true; } \
    | head -1 | sed -E 's/^[^:]*:[[:space:]]*//; s/[[:space:]]*$//'
}
truthy() { echo "$1" | grep -qiE '^(yes|true|y|verified|paid|enrolled|level-?[1-9])' && echo true || echo false; }

# Re-verdict any lane gated on second-account after gates_held changes, so the machine
# file the matcher reads stays internally consistent.
_resync_lanes() { # $1=reachability.json path — keep second-account lanes' verdict in sync
  local f="$1" tmp; tmp="$(mktemp)"
  jq --argjson sec "$(jq '.gates_held["second-account"]' "$f")" '
      (.lanes) |= (map(
        if ((.gates // []) | index("second-account")) then
          .verdict = (if $sec then "REACHABLE" else "GATED" end)
          | .note = (if $sec then "2+ accounts held"
                     else "need a 2nd account before cross-tenant authz testing" end)
        else . end))' "$f" > "$tmp" && mv "$tmp" "$f"
}

case "$CMD" in
  show)
    [[ -f "$RMD" ]] && { cat "$RMD"; exit 0; }
    echo "no reachability.md at $PROJECT_DIR — run: $0 init --project-dir $PROJECT_DIR" >&2; exit 1 ;;
  set-gate)
    [[ -f "$RJSON" ]] || { echo "no reachability.json at $PROJECT_DIR — run init first" >&2; exit 1; }
    [[ -z "$GATE" ]] && { echo "Error: --gate required (e.g. second-account, first-credential, oauth-app, device, otp-2fa, funded-balance, approval-role)" >&2; exit 2; }
    case "$(echo "$HELD" | tr '[:upper:]' '[:lower:]')" in
      true|yes|y|1|held)   HB=true ;;
      false|no|n|0|"")     HB=false ;;
      *) echo "Error: --held must be true|false" >&2; exit 2 ;;
    esac
    NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    tmp="$(mktemp)"
    jq --arg g "$GATE" --argjson v "$HB" --arg now "$NOW" \
       '.gates_held[$g] = $v | .generated_at = $now
        | ._note = "gate \($g)=\($v) via set-gate"' "$RJSON" > "$tmp" && mv "$tmp" "$RJSON"
    _resync_lanes "$RJSON"
    echo "reachability: set gate '$GATE' = $HB in $RJSON"
    exit 0 ;;
  sync)
    [[ -f "$RJSON" ]] || { echo "no reachability.json at $PROJECT_DIR — run init first" >&2; exit 1; }
    # Re-derive the account gate from credential material in the project — by DISCOVERING
    # it, not assuming one filename in one place. The old sync matched `-maxdepth 1 creds*`
    # and counted FILES; that missed the `credentials.jsonl` convention entirely (it starts
    # "crede", not "creds") and any nested layout (e.g. tools/creds/{A,B}.json), so it
    # reported second-account=false WHILE the operator held two accounts and the matcher
    # then hid the highest-value lane. A gate that fails toward inaction, silently. Now:
    # recurse (bounded, heavy dirs pruned), match the real conventions, and count DISTINCT
    # IDENTITIES rather than files. See ROADMAP item 20.
    mapfile -t CREDFILES < <(
      find "$PROJECT_DIR" -maxdepth 6 \
        \( -type d \( -name .git -o -name node_modules -o -name __pycache__ \
                      -o -name evidence -o -name logs -o -name recon \
                      -o -name '*_extracted' \) -prune \) -o \
        \( -type f \( -iname 'credentials.jsonl' \
                      -o -iname 'creds*.json'  -o -iname 'creds*.jsonl' \
                      -o -iname '*-creds.json' -o -iname '*-creds.jsonl' \
                      -o -ipath '*/creds/*.json'  -o -ipath '*/creds/*.jsonl' \
                      -o -ipath '*/credentials/*.json' \) -print \) \
        2>/dev/null | sort -u
    )
    # Pull an identity token per credential record; opaque files still count as one identity
    # each (fail toward "reachable"), and distinct opaque JSONL lines are hashed so genuine
    # second accounts are never collapsed into one.
    _idkeys='(.account // .username // .user // .email // .handle // .login // .label // .name // (.id|tostring)) // empty'
    identtmp="$(mktemp)"; matched_report=""
    for f in "${CREDFILES[@]:-}"; do
      [[ -z "$f" || ! -f "$f" ]] && continue
      before="$(wc -l < "$identtmp" | tr -d ' ')"
      case "$f" in
        *.jsonl)
          while IFS= read -r line; do
            [[ -z "${line//[[:space:]]/}" ]] && continue
            id="$(printf '%s' "$line" | jq -er "$_idkeys" 2>/dev/null)" || id=""
            [[ -z "$id" ]] && id="rawline:$(printf '%s' "$line" | sha1sum | cut -c1-12)"
            printf '%s\n' "$id" >> "$identtmp"
          done < "$f" ;;
        *.json)
          if ! jq -er "(if type==\"array\" then .[] elif (has(\"accounts\") and (.accounts|type==\"array\")) then .accounts[] else . end) | $_idkeys" \
                 "$f" >> "$identtmp" 2>/dev/null; then
            printf 'file:%s\n' "$f" >> "$identtmp"
          fi ;;
      esac
      after="$(wc -l < "$identtmp" | tr -d ' ')"
      matched_report+="  matched: ${f#"$PROJECT_DIR"/} (+$((after-before)) identity/ies)"$'\n'
    done
    idcount="$(sort -u "$identtmp" | grep -c . || true)"; rm -f "$identtmp"
    nfiles="${#CREDFILES[@]}"; [[ "$nfiles" -eq 1 && -z "${CREDFILES[0]:-}" ]] && nfiles=0
    sec=false; [[ "${idcount:-0}" -ge 2 ]] && sec=true
    NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    tmp="$(mktemp)"
    jq --argjson v "$sec" --arg raw "identities: $idcount across $nfiles file(s)" --arg now "$NOW" \
       '.gates_held["second-account"] = $v | .gates_held["accounts_raw"] = $raw
        | .generated_at = $now | ._note = "second-account re-derived from distinct credential identities via sync"' \
       "$RJSON" > "$tmp" && mv "$tmp" "$RJSON"
    _resync_lanes "$RJSON"
    echo "reachability: sync — $idcount distinct identity/ies across $nfiles credential file(s) -> second-account=$sec"
    printf '%s' "$matched_report"
    [[ "$nfiles" -eq 0 ]] && \
      echo "  (no credential files matched under $PROJECT_DIR — looked for credentials.jsonl, creds*.json, */creds/*.json, *-creds.json)"
    echo "  (device / geo-egress / funded-balance cannot be auto-derived — set with: $0 set-gate --gate device --held true)"
    exit 0 ;;
  init) ;;
  *) echo "usage: $0 init|show|set-gate|sync --project-dir DIR [--gate G --held true|false]" >&2; exit 2 ;;
esac

if [[ -f "$RMD" && "$FORCE" != true ]]; then
  echo "reachability.md already exists at $PROJECT_DIR (use --force to regenerate)" >&2
  exit 0
fi

# ── Derive gates held from the intake "Account Capabilities" block ──
ACCOUNTS="$(cap 'Accounts held')"
KYC="$(cap 'KYC level')";   KYC="${KYC:-none}"
FUNDED="$(cap 'Funded balance')"
DEVICE="$(cap 'Mobile device')"
PLAN="$(cap 'Plan tier')";  PLAN="${PLAN:-free}"
GEO="$(cap 'Geo-egress')";  GEO="${GEO:-unknown}"
OTP="$(cap 'OTP/2FA')"
ROLE="$(cap 'Elevated role')"

second_account=false
echo "$ACCOUNTS" | grep -qiE '\b([2-9]|[1-9][0-9]+|two|three|four|five|more|multiple)\b' && second_account=true
# first-credential: held when the operator has AT LEAST ONE account/token (>=1). OAuth/JWT/token
# lanes gate on this so they are not planned REACHABLE at zero credentials. 2+ implies 1+.
first_credential=false
{ echo "$ACCOUNTS" | grep -qiE '\b([1-9][0-9]*|one|two|three|four|five|single|multiple|more)\b' \
  || [[ "$second_account" == true ]]; } && first_credential=true
# oauth-app: our own registered OAuth client. Not auto-derivable; read an "OAuth app" capability
# line if the intake has one, else default not-held (set later with set-gate).
oauth_app="$(truthy "$(cap 'OAuth app')")"
funded="$(truthy "$FUNDED")"; device="$(truthy "$DEVICE")"
otp="$(truthy "$OTP")";       role="$(truthy "$ROLE")"

# ── Stack-known gates from the lessons loader (best-effort; degrade gracefully) ──
known_gates='[]'
if [[ -f "$LESSONS_QUERY" ]] && command -v python3 >/dev/null 2>&1; then
  q="${HANDLE:-${STACK:-$PROJECT}}"
  hits="$(python3 "$LESSONS_QUERY" match "$q" 2>/dev/null \
          | grep -ioE 'kyc|funded|second account|2nd account|device|paid tier|paid feature|plan upgrade|geo|2fa|otp|browser' \
          | sort -u | head -10 || true)"
  [[ -n "$hits" ]] && known_gates="$(printf '%s\n' "$hits" | jq -R . | jq -s . 2>/dev/null || echo '[]')"
fi

NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# ── reachability.json (machine-readable; consumed by playbook.py) ──
jq -n \
  --arg now "$NOW" --arg project "$PROJECT" \
  --arg accounts "$ACCOUNTS" --argjson second "$second_account" \
  --arg kyc "$KYC" --argjson funded "$funded" --argjson device "$device" \
  --arg plan "$PLAN" --arg geo "$GEO" --argjson otp "$otp" --argjson role "$role" \
  --argjson firstcred "$first_credential" --argjson oauthapp "$oauth_app" \
  --argjson known "$known_gates" \
  '{
     generated_at: $now, project: $project,
     gates_held: {
       "second-account": $second, "first-credential": $firstcred,
       "oauth-app": $oauthapp, "accounts_raw": $accounts,
       "kyc": $kyc, "funded-balance": $funded, "device": $device,
       "paid-tier": $plan, "geo-egress": $geo, "otp-2fa": $otp, "approval-role": $role
     },
     stack_known_gates: $known,
     lanes: [
       { lane: "cross-account / cross-tenant authz (BOLA/BFLA)", class: "AUTHZ",
         gates: ["second-account"],
         verdict: (if $second then "REACHABLE" else "GATED" end),
         note: (if $second then "2+ accounts held"
                else "need a 2nd account before cross-tenant authz testing" end) }
     ]
   }' > "$RJSON"

# ── reachability.md (human matrix; format mirrors templates/reachability.md) ──
yn() { [[ "$1" == true ]] && echo yes || echo no; }
{
  echo "# Reachability Pre-Check — $PROJECT"
  echo
  echo "_Generated $NOW by reachability.sh. The LANE gate: do not plan or dispatch a"
  echo "primary lane you cannot reach. Complete the lane matrix from classification.md._"
  echo
  echo "## Gates held (from project.md -> Account Capabilities)"
  echo
  echo "| Gate | Held |"
  echo "|------|------|"
  echo "| second-account | $([[ $second_account == true ]] && echo yes || echo 'NO (gated)') (raw: ${ACCOUNTS:-unset}) |"
  echo "| first-credential | $([[ $first_credential == true ]] && echo yes || echo 'NO (gated)') (raw: ${ACCOUNTS:-unset}) |"
  echo "| oauth-app | $(yn "$oauth_app") |"
  echo "| kyc | $KYC |"
  echo "| funded-balance | $(yn "$funded") (raw: ${FUNDED:-unset}) |"
  echo "| device | $(yn "$device") (raw: ${DEVICE:-unset}) |"
  echo "| paid-tier | $PLAN |"
  echo "| geo-egress | $GEO |"
  echo "| otp-2fa | $(yn "$otp") |"
  echo "| approval-role | $(yn "$role") |"
  echo
  if [[ "$known_gates" != "[]" ]]; then
    echo "## Stack-known gates (prior programs on this stack hit these — from lessons)"
    echo
    echo "$known_gates" | jq -r '.[] | "- " + .'
    echo
  fi
  echo "## Lane matrix"
  echo
  echo "One row per high-value lane from classification.md. Verdict ="
  echo "REACHABLE / GATED(gate) / UNKNOWN(needs-check). Lead the test plan with"
  echo "REACHABLE lanes + the program focus areas; deprioritize GATED ones."
  echo
  echo "| Lane / surface | Class | Gate(s) | Verdict | Note |"
  echo "|----------------|-------|---------|---------|------|"
} > "$RMD"
jq -r '.lanes[] | "| \(.lane) | \(.class) | \(.gates|join(", ")) | \(.verdict) | \(.note) |"' "$RJSON" >> "$RMD"
printf '| (add lanes from classification.md) |  |  | UNKNOWN |  |\n' >> "$RMD"

echo "reachability: wrote $RMD and $RJSON"
[[ "$second_account" != true ]] && \
  echo "  [!] cross-tenant authz is GATED (no 2nd account) — surface to operator before dispatch"
exit 0
