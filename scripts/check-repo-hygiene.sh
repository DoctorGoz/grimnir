#!/usr/bin/env bash
# check-repo-hygiene.sh — sweep for operator-specific leakage in tracked files.
#
# Tracked Grimnir files must stay generic (CLAUDE.md "Public Repository Hygiene").
# This guard enforces the public/private boundary, and is BUILT the same way:
#   - GENERIC patterns ship in the repo (kept false-positive-free for a SECURITY
#     tool, which legitimately contains example JWTs, AWS example keys, and
#     cloud-metadata IPs — so we do NOT generically scan for those).
#   - OPERATOR-SPECIFIC identifiers (your home IP, tailnet IP, hostnames, email,
#     real program/client names) live in a PRIVATE list OUTSIDE the repo and are
#     loaded at runtime — so this guard never itself leaks what it guards.
#
# Usage:
#   scripts/check-repo-hygiene.sh                 # sweep staged diff (pre-commit)
#   scripts/check-repo-hygiene.sh --tree          # sweep the entire tracked tree
#   scripts/check-repo-hygiene.sh --stdin         # sweep content piped on stdin
#   scripts/check-repo-hygiene.sh --pattern X     # add one extra ERE inline
#   scripts/check-repo-hygiene.sh --no-derive     # skip workspace-derived names
#   scripts/check-repo-hygiene.sh --workspace D   # derive from D instead
#
# Operator-local patterns (one case-insensitive extended-regex per line; blank
# lines and lines starting with # are ignored) are read from:
#   $GRIMNIR_HYGIENE_PATTERNS   if set, else  ~/.grimnir/hygiene-patterns.txt
# Copy templates/hygiene-patterns.txt.example to that path and fill it in.
#
# Program names are additionally DERIVED from the engagement directories under
#   $GRIMNIR_WORKSPACE           if set, else  ~/workspace
# so a new engagement is covered the moment its directory exists, with no list
# to maintain. Handles that are ordinary words or generic vendor names are
# suppressed via
#   $GRIMNIR_HYGIENE_ALLOW_WORDS if set, else  ~/.grimnir/hygiene-allow-words.txt
# Copy templates/hygiene-allow-words.txt.example to that path.
set -u

# ── Generic patterns: never belong in ANY operator's tracked files ───────────
# Deliberately minimal + FP-free. Operator-specific values go in the local list.
GENERIC_PATTERNS=(
  # NOTE: Grimnir's own finding-ID formats — FINDING-NNN (per-agent files) and
  # F-NNN (the event stream) — are generic placeholders used across
  # templates, docs, fixtures, and tooling. So "FINDING-001" / "F-001" are NOT leaks and are
  # intentionally NOT matched here: no regex can distinguish a real engagement's
  # F-003 from a placeholder F-003 (identical strings). Real engagement specifics
  # (program names, the finding tags that actually matter) are caught by the
  # operator-local list. A prior generic F-number pattern was removed: as written
  # (no hyphen) it matched no real codename (the operator's are hyphenated F-NNN)
  # and only ever false-positived on flake8 lint codes such as F401.
  '\bH1[ -]?#[0-9]{6,}'                  # bug bounty platform report numbers
  'report #[0-9]{6,}'                    # generic report-number references
  '-----BEGIN [A-Z ]*PRIVATE KEY-----'  # a real private-key block
  # Structural: a platform research-attribution header with a REAL handle as its
  # value. Placeholders use angle brackets (`<your-h1-handle>`) which start with
  # '<' and are NOT matched, so the generic guidance passes while a baked-in
  # operator handle is caught — regardless of which operator. This catches the
  # CLASS (any handle in this header), not one hardcoded value, so it can't be
  # defeated by an identifier the local denylist happens not to list.
  'X-(HackerOne-Research|Bugcrowd-[A-Za-z-]+):[[:space:]]*[A-Za-z0-9_]'
  # Operator ACTIVITY volume, the same Tier-2 class as the performance figures above.
  # "no finding had ever carried one" is methodology and belongs in a tracked file;
  # the same sentence with a corpus count and an engagement count attached additionally
  # publishes how much work this operator has done, which is nobody else's business and
  # is not true of anyone else's corpus. State the direction, keep the numbers
  # operator-side. (This comment illustrated the rule with the real figures until v0.5.1,
  # which is how a guard ends up carrying the thing it exists to block: the example is
  # always the most convenient place to put the real value.)
  '[0-9]{2,} (findings|engagements) (across|on|in) [0-9]+'
  '(across|out of) [0-9]{2,} (real )?(engagements|programs|findings)'
  # Operator performance data. Bounty amounts and submission scoreboards are the
  # operator's business performance, and an amount plus a race margin is correlatable
  # against a platform's public activity feed. The tracked rules may state the
  # DIRECTION of an outcome; the numbers belong in ~/.grimnir/rules/hunting-local.md.
  # (Shipped once in v0.3.0 before this guard existed — the guard knew about hostnames
  # and handles but had no concept of performance data.)
  '\$[0-9]{1,3},[0-9]{3}'                                    # $2,000 / $2,200
  '(paid|earned|bounty|awarded|payout)[^.]{0,40}\$[0-9]'     # amount in bounty context
  '[0-9]+ (of|for) [0-9]+ (submissions|reports|findings)'    # "0 of 10 submissions"
  '(dupe|duplicate|conversion|paid) rate[^.]{0,24}[0-9]+ ?%' # "dupe rate of 78%"
)

# ── Args ─────────────────────────────────────────────────────────────────────
mode="staged"
extra_patterns=()
derive="yes"
patterns_file="${GRIMNIR_HYGIENE_PATTERNS:-$HOME/.grimnir/hygiene-patterns.txt}"
allow_words_file="${GRIMNIR_HYGIENE_ALLOW_WORDS:-$HOME/.grimnir/hygiene-allow-words.txt}"
workspace="${GRIMNIR_WORKSPACE:-$HOME/workspace}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tree)          mode="tree"; shift ;;
    --stdin)         mode="stdin"; shift ;;
    --pattern)       extra_patterns+=("$2"); shift 2 ;;
    --patterns-file) patterns_file="$2"; shift 2 ;;
    --no-derive)     derive="no"; shift ;;
    --workspace)     workspace="$2"; shift 2 ;;
    -h|--help)       sed -n '2,22p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

# ── Load operator-local patterns (the private half of the boundary) ──────────
local_patterns=()
if [[ -f "$patterns_file" ]]; then
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line#"${line%%[![:space:]]*}"}"   # ltrim
    line="${line%"${line##*[![:space:]]}"}"    # rtrim
    [[ -z "$line" || "$line" == '#'* ]] && continue
    local_patterns+=("$line")
  done < "$patterns_file"
fi

# ── Derive program names from the engagement directories that already exist ──
# A hand-maintained pattern file cannot keep up with this category. It is edited
# when someone remembers; engagement directories appear whenever an engagement
# starts. That gap is not hypothetical: program names shipped in v0.3.0 and were
# still in four tracked files at v0.4.0, and this gate passed them every time —
# not because it was broken, but because it held six patterns while the
# workspace held dozens of engagements. It scanned the files, matched none of
# its patterns, and reported success.
#
# The leak arrives as provenance ("found on <program>", "the <program> reports
# turned on"), which is exactly the moment a real name is more convenient than a
# placeholder, so the list has to derive itself from what is on disk.
#
# Engagements elsewhere: set GRIMNIR_WORKSPACE (or pass --workspace).
# Dictionary-word handles: list them one per line in the allow-words file, since
# a handle like a common noun cannot be distinguished from ordinary prose here.
# That file is operator-local for the same reason the pattern file is — a
# tracked list of which words to ignore would itself name programs.
RESERVED_NAMES='^(grimnir|huginn|specter|artemis|hunter|nimbus|nomad|tara|tools|android|go|bin|venv|src|tmp)$'
allow_words=()
if [[ -f "$allow_words_file" ]]; then
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line#"${line%%[![:space:]]*}"}"; line="${line%"${line##*[![:space:]]}"}"
    [[ -z "$line" || "$line" == '#'* ]] && continue
    allow_words+=("${line,,}")
  done < "$allow_words_file"
fi

derived_patterns=()
derived_names=()
if [[ "$derive" == "yes" && -d "$workspace" ]]; then
  for _d in "$workspace"/*/; do
    [[ -d "$_d" ]] || continue
    _n="$(basename "$_d")"
    _l="${_n,,}"
    # Too short to be evidence, structurally not a program dir, or reserved.
    (( ${#_n} < 5 )) && continue
    [[ "$_n" =~ ^[A-Za-z0-9._-]+$ ]] || continue
    [[ "$_l" =~ $RESERVED_NAMES ]] && continue
    _skip=no
    for _w in "${allow_words[@]}"; do [[ "$_l" == "$_w" ]] && { _skip=yes; break; }; done
    [[ "$_skip" == yes ]] && continue
    # Escape ERE metacharacters, then bound on non-alphanumeric so a handle does
    # not match inside a longer identifier.
    _esc=$(printf '%s' "$_n" | sed 's/[].[^$()*+?{}|\\]/\\&/g')
    derived_patterns+=( "(^|[^A-Za-z0-9-])${_esc}([^A-Za-z0-9-]|$)" )
    derived_names+=( "$_n" )
  done
fi

all=( "${GENERIC_PATTERNS[@]}" "${extra_patterns[@]}" "${local_patterns[@]}" "${derived_patterns[@]}" )
joined=$(IFS='|'; echo "${all[*]}")

# ── Absolute home paths: an operator's username baked into a tracked file ────
# This is BOTH an identity leak and a portability bug, and it is invisible to the
# pattern lists above: the operator-local file lists program names, not the account
# name, and no generic pattern can say "a username, but not a placeholder" in ERE
# (POSIX has no negative lookahead). So it gets its own pass with an explicit
# allowlist of sanctioned placeholders.
#
# It catches two spellings, because the second one defeated a plain `/home/<user>`
# search during the v0.5.0 sweep: Claude Code names a project directory by mangling
# the working directory, so "/home/me/workspace/grimnir" is also written
# "-home-me-workspace-grimnir", and a script hardcoding THAT form looked clean.
# Hyphens are allowed in the candidate because real accounts contain them
# (`ec2-user`, `ci-runner`); which part is the username differs by spelling, so the
# two forms are un-prefixed by separate rules below.
HOME_PATH_RE='(/home/|/Users/|-home-)[A-Za-z0-9_][A-Za-z0-9_-]*'
# Two things are not a personal identity and must not be flagged:
#   - documentation placeholders (you / user / x / ...)
#   - DISTRO AND PLATFORM DEFAULT ACCOUNTS (kali, ubuntu, ec2-user, vagrant, ...)
# The second group is why this list is not just placeholders. A security repo carries
# platform setup docs, and "/home/kali" in a Kali install note names the distro's own
# default account, not a person -- caught as a false positive against this repo's own
# history, where the flagged line was a commit message about REMOVING such paths.
HOME_PLACEHOLDERS='^(you|your|user|username|youruser|operator|me|x|USER|HOME|kali|root|ubuntu|debian|admin|vagrant|ec2-user|pi|docker|runner|node)$'

# Emit any input line whose home-path segment is not a sanctioned placeholder.
home_scan() {
  grep -inE "$HOME_PATH_RE" 2>/dev/null | while IFS= read -r _line; do
    while IFS= read -r _seg; do
      [[ -z "$_seg" || "$_seg" =~ $HOME_PLACEHOLDERS ]] && continue
      printf '%s\n' "$_line"
      break
    done < <(printf '%s\n' "$_line" | grep -oE "$HOME_PATH_RE" \
             | sed -E -e 's#^(/home/|/Users/)([A-Za-z0-9_-]+).*#\2#' \
                      -e 's#^-home-([A-Za-z0-9_]+).*#\1#')
  done
}

# ── Scan ─────────────────────────────────────────────────────────────────────
case "$mode" in
  staged)
    # Only inspect ADDED lines (what this commit introduces), so a commit that
    # REMOVES a leak isn't blocked by the removed line showing in its own diff.
    # Exclude this script itself — it contains the patterns as literal regexes.
    staged_added=$(git diff --staged -- . ':(exclude)scripts/check-repo-hygiene.sh' \
                   | grep -E '^\+' | grep -vE '^\+\+\+' || true)
    hits=$(printf '%s\n' "$staged_added" | grep -inE "$joined" || true)
    home_hits=$(printf '%s\n' "$staged_added" | home_scan || true) ;;
  stdin)
    stdin_buf=$(cat)
    hits=$(printf '%s\n' "$stdin_buf" | grep -inE "$joined" || true)
    home_hits=$(printf '%s\n' "$stdin_buf" | home_scan || true) ;;
  tree)
    # Exclude this script (it contains the generic patterns as literal regexes)
    # and the local patterns file (if it happens to live inside the repo).
    tree_files=$(git ls-files | grep -vE '^scripts/check-repo-hygiene\.sh$')
    hits=$(printf '%s\n' "$tree_files" | xargs grep -inE "$joined" 2>/dev/null || true)
    home_hits=$(printf '%s\n' "$tree_files" \
                | xargs grep -nE "$HOME_PATH_RE" 2>/dev/null | home_scan || true) ;;
esac

if [[ -n "${home_hits:-}" ]]; then
  echo "[!] Absolute home path with a real username in tracked content ($mode mode):" >&2
  echo "$home_hits" >&2
  echo "" >&2
  echo "This leaks the operator's account name AND hardcodes a path no other clone has." >&2
  echo "Use a configurable root — \$GRIMNIR_WORKSPACE (engagement data),"            >&2
  echo "\$GRIMNIR_HOME (host-global store), \$GRIMNIR_REPO_DIR (this checkout) —"     >&2
  echo "or, for an illustrative path in docs, one of the sanctioned placeholders:"   >&2
  echo "  you your user username youruser operator me x USER HOME"                   >&2
  exit 1
fi

if [[ -n "$hits" ]]; then
  echo "[!] Operator-specific leakage detected ($mode mode):" >&2
  echo "$hits" >&2
  echo "" >&2
  echo "Sanitize before committing — tracked files must stay generic (CLAUDE.md)." >&2
  if (( ${#derived_names[@]} )); then
    echo "" >&2
    echo "Some patterns are derived from engagement directories in $workspace." >&2
    echo "If a hit is an ordinary word rather than a program reference, add it to" >&2
    echo "$allow_words_file (one per line) and re-run; that file stays operator-local." >&2
  fi
  exit 1
fi

echo "[ok] no leakage detected ($mode mode; ${#local_patterns[@]} operator-local pattern(s), ${#derived_patterns[@]} derived from $workspace)"
exit 0
