#!/usr/bin/env bash
# grimnir git-state preflight
# ---------------------------
# Runs BEFORE launching Claude/Gemini in a Grimnir repo, enforcing the dev/deploy
# model by surfacing (not silently allowing) drift:
#   Rule 1 — never leave uncommitted/unpushed dev changes on this machine
#   Rule 2 — don't run out-of-date: know if you're behind the remote
#
# CHECK & NOTIFY by default (never blocks the launch). Set GRIMNIR_PREFLIGHT_STRICT=1
# to be prompted before launching when something is off. Offline-safe.
#
# Usage:  git-preflight.sh [REPO_DIR]   (defaults to $PWD)
set -uo pipefail

REPO="${1:-$PWD}"
name="$(basename "$REPO")"
cd "$REPO" 2>/dev/null || exit 0
git rev-parse --git-dir >/dev/null 2>&1 || exit 0   # not a git repo — skip silently

# Best-effort fetch so "behind" is accurate; bounded + offline-safe.
[[ "${GRIMNIR_PREFLIGHT_NOFETCH:-0}" == "1" ]] || timeout 5 git fetch -q 2>/dev/null || true

branch="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo '?')"
upstream="$(git rev-parse --abbrev-ref '@{u}' 2>/dev/null || echo '')"
dirty="$(git status --porcelain 2>/dev/null | wc -l | tr -d ' ')"
ahead=0; behind=0
if [[ -n "$upstream" ]]; then
    ahead="$(git rev-list --count '@{u}..HEAD' 2>/dev/null || echo 0)"
    behind="$(git rev-list --count 'HEAD..@{u}' 2>/dev/null || echo 0)"
fi

problems=0
echo "── grimnir preflight: ${name} (${branch}) ──" >&2
if [[ "$dirty" -gt 0 ]]; then
    echo "  ⚠  ${dirty} uncommitted change(s) — commit before they drift (Rule 1)" >&2; problems=1
fi
if [[ "$ahead" -gt 0 ]]; then
    echo "  ⚠  ${ahead} unpushed commit(s) — push so remote hosts can pull (Rule 1)" >&2; problems=1
fi
if [[ "$behind" -gt 0 ]]; then
    echo "  ⚠  ${behind} commit(s) behind ${upstream} — consider: git -C ${REPO} pull (Rule 2)" >&2; problems=1
fi
if [[ "$problems" -eq 0 ]]; then
    echo "  ✓  clean & in sync${upstream:+ with $upstream}" >&2
fi

if [[ "$problems" -eq 1 && "${GRIMNIR_PREFLIGHT_STRICT:-0}" == "1" ]]; then
    read -t 15 -rp "  Launch anyway? [Y/n] " ans 2>/dev/null || ans="Y"
    [[ "${ans:-Y}" =~ ^[Nn] ]] && { echo "  launch aborted by preflight." >&2; exit 1; }
fi
exit 0
