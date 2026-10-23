#!/usr/bin/env bash
# check-report-hygiene.sh -- pre-submission lint for EXTERNAL bug-bounty reports.
#
# DIFFERENT guard, OPPOSITE direction to check-repo-hygiene.sh:
#   - check-repo-hygiene.sh   guards the PUBLIC REPO: no operator PII / program
#                             names / keys get committed IN.
#   - check-report-hygiene.sh guards OUTBOUND SUBMISSIONS: no AI-slop typography
#                             and no internal codenames go OUT to a program.
#
# Why this exists: engagement reports live OUTSIDE the repo ($GRIMNIR_WORKSPACE/$PROGRAM/),
# so no git hook ever sees them, and the "no em-dashes / no internal codenames in
# submitted reports" rule (CLAUDE.md, External Bug Bounty Submissions) has no
# automated gate. This is that gate -- run it by hand (or from a submission
# wrapper) before you paste a report into HackerOne / Bugcrowd / a disclosure.
# Especially important for drafts written by a delegated model (e.g. a cheaper model),
# which does not inherit the operator's house-style memory and defaults to
# em-dash-heavy prose.
#
# Usage:
#   scripts/check-report-hygiene.sh reports/FOO.md [more.md ...]
#   scripts/check-report-hygiene.sh --stdin < draft.md
#   scripts/check-report-hygiene.sh --warn-only reports/FOO.md   # never exit non-zero
#   scripts/check-report-hygiene.sh --strict    reports/FOO.md   # warnings fail too
#   scripts/check-report-hygiene.sh --finding F.json reports/FOO.md  # warn if severity > floor
#   scripts/check-report-hygiene.sh --selftest                   # prove it catches/passes
#
# Exit: 1 if any ERROR-class hit (em-dash / en-dash / smart quote / ellipsis /
#       internal codename). Placeholder holes (a bare NNNNNNN submission id,
#       TODO/FIXME, a capitalized 'Hunter') are WARN: reported, do NOT fail,
#       unless --strict. 0 when clean.
#
# NOTE: every pattern below is written as an ASCII \x{...} PCRE escape, never a
# literal Unicode glyph, so this script passes its own check.
set -u

warn_only=0
strict=0
use_stdin=0
selftest=0
finding=""
files=()
tmp_stdin=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --stdin)     use_stdin=1; shift ;;
    --warn-only) warn_only=1; shift ;;
    --strict)    strict=1; shift ;;
    --selftest)  selftest=1; shift ;;
    --finding)   finding="${2:?--finding needs a path}"; shift 2 ;;
    -h|--help)   sed -n '2,34p' "$0"; exit 0 ;;
    --)          shift; while [[ $# -gt 0 ]]; do files+=("$1"); shift; done ;;
    -*)          echo "unknown arg: $1" >&2; exit 2 ;;
    *)           files+=("$1"); shift ;;
  esac
done

err=0
wrn=0

cleanup() { [[ -n "$tmp_stdin" && -f "$tmp_stdin" ]] && rm -f "$tmp_stdin"; }
trap cleanup EXIT

# scan_one FILE LABEL PCRE_PATTERN ERROR|WARN
scan_one() {
  local f="$1" label="$2" pat="$3" sev="$4" hits
  hits=$(grep -nP "$pat" "$f" 2>/dev/null) || return 0
  [[ -z "$hits" ]] && return 0
  if [[ "$sev" == "ERROR" ]]; then
    err=$((err+1)); printf '  [ERROR] %s\n' "$label"
  else
    wrn=$((wrn+1)); printf '  [warn]  %s\n' "$label"
  fi
  while IFS= read -r line; do
    printf '          %.180s\n' "$line"
  done <<< "$hits"
}

scan_file() {
  local f="$1"
  if [[ ! -r "$f" ]]; then
    echo "== $f ==" ; echo "  [ERROR] cannot read file"; err=$((err+1)); return
  fi
  echo "== $f =="
  # -- ERROR class: AI-slop typography (banned in external output) --
  scan_one "$f" "em-dash (U+2014): banned in external output, use comma/colon/period" '\x{2014}' ERROR
  scan_one "$f" "en-dash (U+2013): use a hyphen or the word 'to'"                      '\x{2013}' ERROR
  scan_one "$f" "smart double-quote (U+201C/201D): use ASCII double quote"             '[\x{201C}\x{201D}]' ERROR
  scan_one "$f" "smart single-quote / apostrophe (U+2018/2019): use ASCII apostrophe"  '[\x{2018}\x{2019}]' ERROR
  scan_one "$f" "ellipsis char (U+2026): use three ASCII dots"                         '\x{2026}' ERROR
  # -- ERROR class: internal codenames must never reach a program --
  scan_one "$f" "internal codename (grimnir/huginn/specter/artemis/nimbus/nomad)" \
                '(?i)\b(grimnir|huginn|specter|artemis|nimbus|nomad)\b' ERROR
  # -- WARN class: review, do not auto-fail --
  scan_one "$f" "internal codename 'Hunter' (capitalized): confirm this is not the agent name" \
                '\b(Hunter|HUNTER)\b' WARN
  scan_one "$f" "unfilled submission-id placeholder (NNNNN...): fill the real id before posting" \
                'N{5,}' WARN
  scan_one "$f" "TODO/FIXME marker left in the draft" '\b(TODO|FIXME)\b' WARN
  [[ -n "$finding" ]] && check_floor "$f"
  echo
}

# WARN when the report states a severity above the finding's floor (the highest severity
# whose claims all survived). File at the floor; add escalations later as comments.
sev_rank() {
  case "${1,,}" in info) echo 0 ;; low) echo 1 ;; medium) echo 2 ;; high) echo 3 ;; critical) echo 4 ;; *) echo -1 ;; esac
}
check_floor() {
  local f="$1" floor stated
  floor=$(jq -r '.floor_severity // empty' "$finding" 2>/dev/null)
  if [[ -z "$floor" ]]; then
    wrn=$((wrn+1)); printf '  [warn]  %s has no floor_severity (not confirmed, or base claim not survived)\n' "$finding"
    return
  fi
  # A "Severity: High" line (bold/table forms included), else a CVSS rating word "(High)".
  stated=$(grep -iEm1 'severity[^A-Za-z]{0,6}(critical|high|medium|low|info)' "$f" | grep -ioE '(critical|high|medium|low|info)' | head -1)
  [[ -z "$stated" ]] && stated=$(grep -iEm1 'cvss.*\((critical|high|medium|low)\)' "$f" | grep -ioE '\((critical|high|medium|low)\)' | tr -d '()' | head -1)
  [[ -z "$stated" ]] && return
  if [[ $(sev_rank "$stated") -gt $(sev_rank "$floor") ]]; then
    wrn=$((wrn+1)); printf '  [warn]  report states severity %s but the finding floor is %s: file at the floor, add the escalation as a comment\n' "$stated" "$floor"
  fi
}

run_selftest() {
  local d dirty clean
  d=$(mktemp -d)
  dirty="$d/dirty.md"; clean="$d/clean.md"
  # A dirty draft: em-dash, smart quotes, a codename, a placeholder.
  printf 'The token rotates \xE2\x80\x94 but never dies. The \xE2\x80\x9Cgrace\xE2\x80\x9D window.\n' > "$dirty"
  printf 'Delegated to Specter for the API leg. See submission #NNNNNNN.\n' >> "$dirty"
  # A clean draft: ASCII only, no codenames, id filled.
  printf 'The token rotates, but never dies. The "grace" window. See submission #3861234.\n' > "$clean"

  echo "### selftest: DIRTY draft (must FAIL with errors) ###"
  ( err=0; wrn=0; scan_file "$dirty"
    if [[ $err -gt 0 ]]; then echo "  -> caught $err error category(ies) [PASS]"; else echo "  -> NO errors caught [FAIL]"; fi )
  echo "### selftest: CLEAN draft (must PASS, 0 errors) ###"
  ( err=0; wrn=0; scan_file "$clean"
    if [[ $err -eq 0 ]]; then echo "  -> 0 errors [PASS]"; else echo "  -> $err errors on a clean draft [FAIL]"; fi )
  rm -rf "$d"
}

if [[ $selftest -eq 1 ]]; then
  run_selftest
  exit 0
fi

if [[ $use_stdin -eq 1 ]]; then
  tmp_stdin=$(mktemp)
  cat > "$tmp_stdin"
  files+=("$tmp_stdin")
fi

if [[ ${#files[@]} -eq 0 ]]; then
  echo "usage: $0 [--warn-only|--strict] <report.md> [more.md ...]   (or --stdin, --selftest)" >&2
  exit 2
fi

for f in "${files[@]}"; do
  scan_file "$f"
done

if [[ $err -gt 0 ]]; then
  echo "RESULT: $err error-class category(ies), $wrn warning(s). NOT submission-clean."
  [[ $warn_only -eq 1 ]] && exit 0
  exit 1
fi
if [[ $wrn -gt 0 ]]; then
  echo "RESULT: clean of hard hygiene issues; $wrn warning(s) to review before posting."
  [[ $strict -eq 1 ]] && exit 1
  exit 0
fi
echo "RESULT: clean. No external-hygiene issues found."
exit 0
