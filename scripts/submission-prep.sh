#!/usr/bin/env bash
# submission-prep.sh — confirmed finding -> submission-ready package + GO/NO-GO.
#
# Phase 4 / connector C3 of the autonomous pipeline (see
# ~/.grimnir/docs/ROADMAP-submission-pipeline.md). The confirmation harness makes a finding
# `confirmed`; this makes a confirmed finding *shipped*. It is the front half's mirror and it
# is gate-style, exactly like validate-finding.sh: args in, a package plus a verdict out.
#
# MVP = spec build-order #1: steps 1 (PRECONDITION), 2 (DRAFT), 4 (HYGIENE), 7 (PACKAGE).
# Deferred to a later pass: step 3 (CVSS auto-vector), step 5 (checklist-as-assertions),
# step 6 (Council). Those surface here as TODO(operator) markers, not as silent gaps.
#
# WHY A MACHINE AND NOT A CHECKLIST: every leak the manual flow produces (an em-dash in
# external output, an internal codename, a report drafted from a finding that was never
# actually confirmed, an internal id baked into an attached filename) is a discipline lapse.
# This PRODUCES the artifact and ENFORCES the rules, so they do not depend on a final
# read-through. It never finishes the report — the judgment sections stay TODO for the human,
# and a package with judgment still open is honestly reported NO-GO.
#
# Usage:
#   submission-prep.sh --project-dir DIR --agent AGENT --id AGT-NNN --slug WEAKNESS-SLUG
#                      [--no-poc] [--force]
#
#   submission-prep.sh --project-dir DIR --id AGT-NNN --mark DISPOSITION [--ref R] [--reason ...]
#       Record-only (the submit/outcome step): stamp a TERMINAL disposition
#       (submitted|duplicate|not-applicable|wont-fix|withdrawn|resolved|na) onto the finding
#       JSON so a filed / dupe / N-A finding stops re-surfacing as a fresh deliver task. No
#       packaging, no slug needed. This is F2 — the write-back is_ship_ready already reads.
#
#   --slug   weakness-descriptive, kebab-case, and MUST NOT contain a finding id. Filenames
#            travel with attachments, so an internal id in a slug leaks through the one
#            channel the content hygiene linter cannot see. Name from the weakness
#            (e.g. device-pairing-account-takeover), never the id (SPE-004-...).
#
# Exit: 0 = GO · 1 = NO-GO (package built, not yet shippable) · 2 = usage · 3 = refused
#       (finding not confirmed, or an id-bearing slug — the hard gate)
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() { sed -n '2,36p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }

PROJECT_DIR="" AGENT="" ID="" SLUG="" NO_POC="" FORCE="" MARK="" REF="" MARK_REASON=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --project-dir) PROJECT_DIR="$2"; shift 2 ;;
        --agent)       AGENT="$2"; shift 2 ;;
        --id)          ID="$2"; shift 2 ;;
        --slug)        SLUG="$2"; shift 2 ;;
        --no-poc)      NO_POC=1; shift ;;
        --force)       FORCE=1; shift ;;
        --mark)        MARK="$2"; shift 2 ;;
        --ref)         REF="$2"; shift 2 ;;
        --reason)      MARK_REASON="$2"; shift 2 ;;
        -h|--help)     usage ;;
        *) echo "unknown arg: $1" >&2; usage ;;
    esac
done

if [[ -n "$MARK" ]]; then
    [[ -z "$PROJECT_DIR" || -z "$ID" ]] && {
        echo "Error: --mark needs --project-dir and --id" >&2; usage; }
else
    [[ -z "$PROJECT_DIR" || -z "$AGENT" || -z "$ID" || -z "$SLUG" ]] && {
        echo "Error: --project-dir, --agent, --id and --slug are all required" >&2; usage; }
fi
[[ -d "$PROJECT_DIR" ]] || { echo "Error: project dir not found: $PROJECT_DIR" >&2; exit 2; }

# ── --mark: record-only disposition write-back (F2) ────────────────────────────
# The submit/outcome step: stamp a TERMINAL disposition on the finding JSON so a filed /
# duplicate / not-applicable finding never re-surfaces as a fresh "confirmed finding ready"
# deliver task. No packaging, no slug. is_ship_ready() already treats the field as terminal;
# this is the writer that was missing. Also emits a no-file decision (backlog suppression)
# for the deliberately-not-filed cases, and emits an event when a sink is configured.
if [[ -n "$MARK" ]]; then
    FJSON="$PROJECT_DIR/${AGENT:+$AGENT/}findings/$ID.json"
    if [[ ! -f "$FJSON" ]]; then
        mapfile -t _hits < <(ls "$PROJECT_DIR"/*/findings/"$ID".json 2>/dev/null || true)
        [[ ${#_hits[@]} -ge 1 ]] && FJSON="${_hits[0]}"
    fi
    [[ -f "$FJSON" ]] || { echo "Error: finding $ID not found under $PROJECT_DIR" >&2; exit 2; }
    if ! python3 "$REPO/scripts/finding_state.py" set-disposition \
            --path "$FJSON" --disposition "$MARK" \
            ${REF:+--ref "$REF"} ${MARK_REASON:+--reason "$MARK_REASON"} \
            --source "submission-prep --mark"; then
        echo "Error: could not stamp disposition '$MARK' (must be a terminal disposition)" >&2
        exit 1
    fi
    if [[ "$MARK" != "submitted" && -x "$REPO/scripts/decision-log.sh" ]]; then
        bash "$REPO/scripts/decision-log.sh" record --project-dir "$PROJECT_DIR" \
            --type no-file --finding "$ID" --actor operator \
            --reason "${MARK_REASON:-disposition=$MARK${REF:+ ($REF)}}" >/dev/null 2>&1 || true
    fi
    if [[ -f "$REPO/scripts/event-emitter.sh" ]]; then
        # shellcheck source=/dev/null
        source "$REPO/scripts/event-emitter.sh" 2>/dev/null || true
        _emit event "finding_dispositioned" "{\"id\":\"$ID\",\"disposition\":\"$MARK\"}" 2>/dev/null || true
    fi
    echo "marked $ID disposition=$MARK -- it will no longer emit a deliver/submit task."
    exit 0
fi

# ── Slug hygiene (the filename channel content-hygiene cannot see) ─────────────
# Reject an id-bearing slug BEFORE writing anything: an attached file keeps its name.
_us="$(printf '%s' "$SLUG" | tr '[:upper:]' '[:lower:]')"
if [[ ! "$_us" =~ ^[a-z0-9][a-z0-9-]+$ ]]; then
    echo "REFUSED: slug must be kebab-case (a-z, 0-9, hyphen): '$SLUG'" >&2; exit 3
fi
if printf '%s' "$_us" | grep -Eq '(^|[^a-z])(f|finding)-?[0-9]{2,}|[a-z]{2,3}-[0-9]{3}'; then
    echo "REFUSED: slug '$SLUG' looks like it carries a finding id. Name from the weakness, not the id." >&2
    echo "         Filenames travel with attachments; the id belongs in the finding JSON, not the file name." >&2
    exit 3
fi

# ── Locate the finding record ─────────────────────────────────────────────────
FJSON="$PROJECT_DIR/$AGENT/findings/$ID.json"
if [[ ! -f "$FJSON" ]]; then
    mapfile -t _hits < <(ls "$PROJECT_DIR"/*/findings/"$ID".json 2>/dev/null || true)
    [[ ${#_hits[@]} -ge 1 ]] && FJSON="${_hits[0]}"
fi
[[ -f "$FJSON" ]] || { echo "Error: finding $ID not found under $PROJECT_DIR (agent=$AGENT)" >&2; exit 2; }

jqr() { jq -r "$1 // \"\"" "$FJSON" 2>/dev/null; }

# ── STEP 1: PRECONDITION — confirm-before-submit, ENFORCED not trusted ─────────
STATE="$(jqr '.validation.state')"; STATE="${STATE:-theoretical}"
if [[ "$STATE" != "confirmed" && "$STATE" != "validated" ]]; then
    echo "NO-GO (refused): $ID is '$STATE', not confirmed/validated."
    echo "  A theoretical finding never ships. Promote it first with validate-finding.sh"
    echo "  (reproducible PoC + an independent check: negative control / OOB / screenshot)."
    exit 3
fi

SEVERITY="$(jqr '.severity')"; SEVERITY="${SEVERITY:-medium}"
TITLE="$(jqr '.title')"
VCLASS="$(jqr '.validation.vuln_class')"
DESC="$(jqr '.description')"
IMPACT="$(jqr '.impact.summary')"
CVSS="$(jqr '.cvss_score')"
CONFAT="$(jqr '.validation.checked_at')"
NEGCTL="$(jqr '.validation.negative_control')"
mapfile -t REPRO < <(jq -r '.reproduction_steps // [] | .[]? | if type=="string" then . else (.action // .step // (.|tostring)) end' "$FJSON" 2>/dev/null || true)

REPORTS="$PROJECT_DIR/reports"
mkdir -p "$REPORTS"
REPORT="$REPORTS/$SLUG-report.md"
GAPDOC="$REPORTS/$SLUG-gap-closure.md"
PUSHBACK="$REPORTS/$SLUG-pushback-playbook.md"
EVDIR="$REPORTS/$SLUG-evidence"

# Draft only what is missing (or everything, with --force). This makes a re-run a RE-CHECK
# that preserves the operator's edits instead of overwriting the report they just filled in.
# --force means "re-scaffold from scratch, discard my edits".
should_write() { [[ ! -e "$1" || -n "$FORCE" ]]; }
if [[ -e "$REPORT" && -z "$FORCE" ]]; then
    echo "re-check mode: $(basename "$REPORT") exists, preserving operator edits (use --force to re-scaffold)."
fi

# ── STEP 2 (poc): regenerate the runnable PoC bundle if the harness left evidence ─
POC_SRC="$PROJECT_DIR/evidence/$ID/poc"
if [[ -z "$NO_POC" ]] && [[ -d "$PROJECT_DIR/evidence/$ID" ]] && command -v python3 >/dev/null 2>&1; then
    python3 "$REPO/scripts/confirm/poc-export.py" --finding-id "$ID" --project-dir "$PROJECT_DIR" >/dev/null 2>&1 || true
fi

# ── STEP 2 (draft): a CLEAN machine skeleton, not the template's prose ─────────
# The bb-report.md TEMPLATE itself trips the hygiene linter (its guidance literally says
# "no Specter/ARTEMIS ids" and uses em-dashes), so we emit the template's STRUCTURE with the
# known fields filled and neutral TODO markers — never the instructional brackets. Anything
# the linter then flags is a REAL leak in the finding's own content, which is the point.
todo() { printf 'TODO(operator): %s\n' "$1"; }
repro_block() {
    if [[ ${#REPRO[@]} -gt 0 ]]; then
        local i=1; for step in "${REPRO[@]}"; do printf '**Step %d.** %s\n\n' "$i" "$step"; i=$((i+1)); done
    else
        todo "paste the exact request/response captures with correlation IDs (see $EVDIR/)"
    fi
}

if should_write "$REPORT"; then
{
cat <<EOF
# ${TITLE:-$(todo "descriptive title: weakness + scope of impact, dismissal-hard, no internal ids")}

**Program:** $(todo "program name")
**Asset:** $(todo "domain or service, identified from the app itself (UI/JS), not its hostname")
**Weakness:** ${VCLASS:+${VCLASS} }$(todo "class + framework codes, e.g. OWASP API5:2023, CWE-863")
**Severity (proposed):** ${SEVERITY}, CVSS 3.1 base ${CVSS:-$(todo "run the FIRST calculator; score must match the vector below")}
**Confirmed:** ${CONFAT:-$(todo "date")}, against the confirmed scope of reach. Full request/response captures retained.
**Related:** $(todo "adjacent to a prior report on this surface, or 'Standalone, first report here' (run a search of the program's disclosed reports)")

---

## Summary

${DESC:-$(todo "2-4 sentences. Lead with concrete data / business impact, not mechanics.")}

## Impact

${IMPACT:-$(todo "quantified, concrete impact: what is read/written/driven, at what scale, in the program's data-class terms")}

## Architecture context

$(todo "how the system SHOULD enforce the boundary that failed: name the specific JWT claim / scope / role that would have enforced it. Proves 'server fails to check', not 'design lacks a control'.")

## Reproduction

**Prerequisites:** $(todo "auth artifacts + any required headers; state if none")

$(repro_block)

## Pre-empting prior dismissal patterns

$(todo "run a search of the program's disclosed reports; address each past N/A/downgrade pattern this program has used on similar reports, before they can raise it")

## CVSS 3.1 vector and per-metric justification

$(todo "paste the FIRST-verified vector CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_ and justify each metric in ownership/data-class terms")

## Remediation

$(todo "specific enforcement control(s) + defense in depth + audit-trail recommendation")

## Evidence package

- \`$EVDIR/\`: sanitized captures and a runnable PoC (repro.sh)
- All correlation IDs referenced above are retained in that directory
EOF
} > "$REPORT"
fi

# Gap-closure doc (internal): the claim audit + the pre-submission checklist, clean.
if should_write "$GAPDOC"; then
{
cat <<EOF
# Gap closure: $SLUG (internal, do not attach)

Enumerate every claim the report makes, mark each demonstrated or asserted, TEST each
asserted one, then re-enumerate. Closing one gap routinely opens another. A pre-emption
paragraph is never a substitute for a test. Write the report to what survives.

| # | Claim | demonstrated / asserted | evidence path or test to run | closed? |
|---|-------|-------------------------|------------------------------|---------|
| 1 | $(printf '%s' "${TITLE:-the core claim}") | asserted | | no |
| 2 | | | | |

## Pre-submission checklist (gate before you file)

- [ ] Gap loop closed: every asserted claim tested, then re-enumerated until closed or provably unclosable
- [ ] Evidence contains a party other than us (a resource we created ourselves is not a victim's)
- [ ] Repro walked from a clean environment with the tools the steps name (no hidden dependence on our session/cookies/egress/geo)
- [ ] Asset identified from the app itself (UI copy, title, JS bundle), not inferred from its hostname
- [ ] No out-of-scope impact claimed (DoS, spam, self-XSS, or whatever this program excludes)
- [ ] Every claim matches an artifact on disk: numbers, IDs, status codes diffed against $EVDIR/
- [ ] CVSS vector run through the FIRST calculator; score matches vector; no metric carries weight the evidence lacks
- [ ] No em-dashes; no internal codenames or finding ids anywhere in the body
- [ ] Prior dismissals reviewed; their patterns addressed in the pre-emption section
- [ ] If cross-tenant/market: owned-vs-foreign differential documented
- [ ] Single-account engagement: degraded-mode caveat noted, or a second account requested
EOF
} > "$GAPDOC"
fi

# Pushback playbook scaffold: mandatory for High/Critical (paired rebuttal artifact).
if [[ "$SEVERITY" == "high" || "$SEVERITY" == "critical" ]] && should_write "$PUSHBACK"; then
{
cat <<EOF
# Pushback playbook: $SLUG (internal, do not attach)

Paired rebuttal for a $SEVERITY finding. Surgical follow-ups for AFTER specific pushback
arrives, never a gate on filing. File first; finish this after (duplicates are decided in
hours). One rebuttal per anticipated objection, each anchored on evidence already on disk.

## Anticipated: severity downgrade
$(todo "the concrete primitive + repeatability that holds the proposed CVSS; cite the exact metric they will push and why the evidence supports it")

## Anticipated: triage-out-of-scope / informative
$(todo "why this is in scope and impactful; the data class and the boundary crossed")

## Anticipated: 'working as designed'
$(todo "the specific claim/scope/role that the server FAILED to enforce; WAD applies to design, not to a missing check")

## Anticipated: duplicate
$(todo "run a search of the program's disclosed reports; if a parent exists, the structural difference; date the parent to gauge dupe-window")
EOF
} > "$PUSHBACK"
fi

# ── STEP 7 (package): sanitized evidence copies; originals in evidence/ untouched ─
mkdir -p "$EVDIR"
# Sanitize working notes -> shippable: strip finding id, agent codenames, em-dashes.
sanitize() {  # <src> <dst>
    sed -E \
        -e "s/\b$ID\b/[finding]/g" \
        -e 's/\b([Gg]rimnir|HUGINN|[Hh]uginn|Specter|SPECTER|ARTEMIS|[Aa]rtemis|Hunter|HUNTER|Nimbus|NIMBUS|Nomad|NOMAD)\b/the tester/g' \
        -e "s/$(printf '—')/, /g" \
        "$1" > "$2" 2>/dev/null || cp "$1" "$2"
}
_poc_copied=0
if [[ -d "$POC_SRC" ]]; then
    for f in "$POC_SRC"/*; do
        [[ -f "$f" ]] || continue
        sanitize "$f" "$EVDIR/$(basename "$f")"
        _poc_copied=$((_poc_copied+1))
    done
fi

# ── STEP 4: HYGIENE — external-output linter as a HARD gate on the outbound report ─
# `if` context, not a bare assignment: the linter exits non-zero on a hit, and under
# `set -e` a failing command substitution would abort the script before the verdict below.
if HYG_OUT="$(bash "$REPO/scripts/check-report-hygiene.sh" "$REPORT" 2>&1)"; then
    HYG_RC=0
else
    HYG_RC=$?
fi

# ── GO / NO-GO ────────────────────────────────────────────────────────────────
REASONS=()
[[ $HYG_RC -ne 0 ]] && REASONS+=("hygiene: $(printf '%s' "$HYG_OUT" | grep -i RESULT | tail -1 | sed 's/^[[:space:]]*//')")
TODO_N="$(grep -c 'TODO(operator)' "$REPORT" || true)"
[[ "${TODO_N:-0}" -gt 0 ]] && REASONS+=("$TODO_N judgment section(s) still TODO(operator) — the human must complete these")
if [[ "$SEVERITY" == "high" || "$SEVERITY" == "critical" ]] && grep -q 'TODO(operator)' "$PUSHBACK" 2>/dev/null; then
    REASONS+=("pushback playbook not yet filled (mandatory for $SEVERITY)")
fi
[[ $_poc_copied -eq 0 ]] && REASONS+=("no runnable PoC in evidence package (evidence/$ID/poc missing — run the confirm harness)")

echo
echo "Package for $ID ($SEVERITY, state=$STATE) -> $REPORTS/"
echo "  report:   $(basename "$REPORT")"
echo "  gap-doc:  $(basename "$GAPDOC")   (internal)"
[[ -f "$PUSHBACK" ]] && echo "  pushback: $(basename "$PUSHBACK")   (internal, mandatory for $SEVERITY)"
echo "  evidence: $(basename "$EVDIR")/   ($_poc_copied sanitized file(s))"
echo

# Best-effort: emit a package-prepared event when an event sink is configured.
if [[ -f "$REPO/scripts/event-emitter.sh" ]]; then
    # shellcheck source=/dev/null
    source "$REPO/scripts/event-emitter.sh" 2>/dev/null || true
    _emit event "submission_prepared" \
        "{\"id\":\"$ID\",\"slug\":\"$SLUG\",\"severity\":\"$SEVERITY\",\"verdict\":\"$([[ ${#REASONS[@]} -eq 0 ]] && echo GO || echo NO-GO)\"}" 2>/dev/null || true
fi

if [[ ${#REASONS[@]} -eq 0 ]]; then
    echo "GO — package is hygiene-clean and complete. Operator: final read, then submit."
    exit 0
fi
echo "NO-GO — package built, not yet shippable:"
for r in "${REASONS[@]}"; do echo "  - $r"; done
echo "Fill the TODO(operator) sections, then re-run to re-check (or --force to overwrite)."
exit 1
