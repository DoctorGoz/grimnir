#!/usr/bin/env bash
# caido-rotate.sh -- archive and retire the oldest Caido project, then open a fresh one.
#
# WHY THIS EXISTS
#   Caido has no API to prune proxy history: none of its GraphQL mutations delete
#   request/response records. In-place SQLite deletion does not help either -- the
#   project databases run with freelist=0, so DELETE frees no bytes and VACUUM needs
#   a full second copy of the file as scratch. Deleting the whole project is the only
#   operation that returns disk, so the only sustainable pattern is rotation.
#
#   The free tier caps projects at 2, which fixes the shape: one live slot and one
#   prior slot. Each run retires the older slot and opens a replacement, so capture
#   stays bounded to roughly one rotation period.
#
# SAFETY
#   Nothing is deleted until the archive has been verified three ways: zstd integrity,
#   byte-identity against the original, and a SQLite quick_check plus row counts on the
#   decompressed copy. Any failure aborts the run with the project untouched, and the
#   proxy service is restarted on every exit path.
#
# USAGE
#   caido-rotate.sh [--dry-run] [--project ID] [--name NAME] [--no-create] [--help]
#
# CONFIG (environment)
#   CAIDO_DATA_DIR        default $HOME/.local/share/caido
#   CAIDO_ARCHIVE_DIR     default $GRIMNIR_HOME/archive  ($HOME/.grimnir/archive)
#   CAIDO_SERVICE         default caido.service          (systemd --user unit)
#   CAIDO_CLIENT          default <repo>/.claude/skills/caido-mode/caido-client.ts
#   CAIDO_PROJECT_PREFIX  default hunt                   (new project: <prefix>-YYYY-MM)
#   CAIDO_WS_MAX_HOST_MB  default 50                     (drop WS telemetry firehoses)
#   CAIDO_ZSTD_LEVEL      default 19
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

CAIDO_DATA_DIR="${CAIDO_DATA_DIR:-$HOME/.local/share/caido}"
CAIDO_ARCHIVE_DIR="${CAIDO_ARCHIVE_DIR:-${GRIMNIR_HOME:-$HOME/.grimnir}/archive}"
CAIDO_SERVICE="${CAIDO_SERVICE:-caido.service}"
CAIDO_CLIENT="${CAIDO_CLIENT:-$REPO_DIR/.claude/skills/caido-mode/caido-client.ts}"
CAIDO_PROJECT_PREFIX="${CAIDO_PROJECT_PREFIX:-hunt}"
CAIDO_WS_MAX_HOST_MB="${CAIDO_WS_MAX_HOST_MB:-50}"
CAIDO_ZSTD_LEVEL="${CAIDO_ZSTD_LEVEL:-19}"

PROJECTS_DB="$CAIDO_DATA_DIR/projects.db"
EXTRACT_PY="$SCRIPT_DIR/caido_extract.py"

DRY_RUN=0
NO_CREATE=0
TARGET_ID=""
NEW_NAME=""

log()  { printf '[caido-rotate] %s\n' "$*"; }
die()  { printf '[caido-rotate] ERROR: %s\n' "$*" >&2; exit 1; }

usage() { sed -n '2,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)    DRY_RUN=1 ;;
    --no-create)  NO_CREATE=1 ;;
    --project)    TARGET_ID="${2:-}"; shift ;;
    --name)       NEW_NAME="${2:-}"; shift ;;
    --help|-h)    usage; exit 0 ;;
    *)            die "unknown option: $1 (try --help)" ;;
  esac
  shift
done

# ---- preflight ---------------------------------------------------------------
for tool in sqlite3 zstd python3 jq sha256sum cmp systemctl; do
  command -v "$tool" >/dev/null 2>&1 || die "missing required tool: $tool"
done
[[ -f "$PROJECTS_DB"  ]] || die "no Caido projects.db at $PROJECTS_DB"
[[ -f "$EXTRACT_PY"   ]] || die "missing helper: $EXTRACT_PY"

# ---- choose what to retire ---------------------------------------------------
# Steady state is two projects: retire the older, open a replacement. With fewer
# than two there is nothing to rotate out yet -- just open the second slot.
mapfile -t PROJECT_ROWS < <(sqlite3 -separator $'\t' "$PROJECTS_DB" \
  "SELECT id, name, created_at FROM projects WHERE temporary = 0 ORDER BY created_at ASC;")
PROJECT_COUNT=${#PROJECT_ROWS[@]}

log "projects on disk: $PROJECT_COUNT"
for row in "${PROJECT_ROWS[@]}"; do
  IFS=$'\t' read -r pid pname pcreated <<< "$row"
  psize=$(du -sh "$CAIDO_DATA_DIR/projects/$pid" 2>/dev/null | cut -f1 || echo '?')
  log "  $pname  ($psize, created $pcreated)"
done

if [[ -n "$TARGET_ID" ]]; then
  RETIRE_ROW=""
  for row in "${PROJECT_ROWS[@]}"; do
    [[ "$row" == "$TARGET_ID"$'\t'* ]] && RETIRE_ROW="$row"
  done
  [[ -n "$RETIRE_ROW" ]] || die "no such project: $TARGET_ID"
elif (( PROJECT_COUNT >= 2 )); then
  RETIRE_ROW="${PROJECT_ROWS[0]}"
else
  RETIRE_ROW=""
  log "fewer than 2 projects -- nothing to retire, will only open a new slot"
fi

NEW_NAME="${NEW_NAME:-${CAIDO_PROJECT_PREFIX}-$(date +%Y-%m)}"

UNINITIALIZED=0
if [[ -n "$RETIRE_ROW" ]]; then
  IFS=$'\t' read -r RETIRE_ID RETIRE_NAME RETIRE_CREATED <<< "$RETIRE_ROW"
  PROJECT_DIR="$CAIDO_DATA_DIR/projects/$RETIRE_ID"
  [[ -d "$PROJECT_DIR" ]] || die "project dir missing: $PROJECT_DIR"
  if [[ ! -f "$PROJECT_DIR/database.caido" ]]; then
    # Caido only lays down project databases when a project is first selected,
    # so one that was created and never opened has nothing worth archiving.
    UNINITIALIZED=1
    log "retiring : $RETIRE_NAME ($RETIRE_ID) -- never initialized, nothing to archive"
  else
    SAFE_NAME="$(printf '%s' "$RETIRE_NAME" | tr -c 'A-Za-z0-9._-' '-' | cut -c1-40)"
    ARCHIVE_DIR="$CAIDO_ARCHIVE_DIR/caido-${SAFE_NAME}-$(date +%Y-%m-%d)"
    INDEX_SIZE=$(stat -c%s "$PROJECT_DIR/database.caido")
    log "retiring : $RETIRE_NAME ($RETIRE_ID)"
    log "archive  : $ARCHIVE_DIR"
  fi
fi
log "new slot : $NEW_NAME"

if (( DRY_RUN )); then
  log "DRY RUN -- no changes made"
  exit 0
fi

# ---- service control ---------------------------------------------------------
SERVICE_STOPPED=0
start_service() {
  (( SERVICE_STOPPED )) || return 0
  log "starting $CAIDO_SERVICE"
  systemctl --user start "$CAIDO_SERVICE" || log "WARNING: failed to restart service"
  SERVICE_STOPPED=0
}
trap start_service EXIT

if [[ -n "$RETIRE_ROW" ]] && (( UNINITIALIZED )); then
  log "dropping uninitialized project $RETIRE_NAME"
  rm -rf "$PROJECT_DIR"
  sqlite3 "$PROJECTS_DB" "DELETE FROM projects WHERE id = '$RETIRE_ID';"
elif [[ -n "$RETIRE_ROW" ]]; then
  # Free space for the verification pass: the archive plus one decompressed copy.
  AVAIL=$(df -B1 --output=avail "$CAIDO_ARCHIVE_DIR" 2>/dev/null | tail -1 \
          || df -B1 --output=avail "$HOME" | tail -1)
  NEEDED=$(( INDEX_SIZE * 3 / 2 ))
  (( AVAIL > NEEDED )) || die "need ~$(( NEEDED / 1024 / 1024 )) MB free for verification, have $(( AVAIL / 1024 / 1024 )) MB"

  mkdir -p "$ARCHIVE_DIR"

  log "stopping $CAIDO_SERVICE for a quiescent copy"
  systemctl --user stop "$CAIDO_SERVICE"
  SERVICE_STOPPED=1
  for _ in $(seq 20); do
    systemctl --user is-active --quiet "$CAIDO_SERVICE" || break
    sleep 1
  done
  systemctl --user is-active --quiet "$CAIDO_SERVICE" && die "service would not stop"

  for wal in "$PROJECT_DIR"/*.caido-wal; do
    [[ -e "$wal" ]] || continue
    [[ -s "$wal" ]] && die "WAL not checkpointed: $wal (service still writing?)"
  done
  log "WAL checkpointed clean"

  # ---- extract what lives only in the raw DB ---------------------------------
  log "extracting replay responses and WebSocket payloads"
  python3 "$EXTRACT_PY" \
    --project-dir "$PROJECT_DIR" \
    --out-dir "$ARCHIVE_DIR" \
    --ws-max-host-mb "$CAIDO_WS_MAX_HOST_MB" > "$ARCHIVE_DIR/extract-summary.json"
  jq -r '"  replay: \(.replay.entries) entries, \(.replay.with_body) with bodies (\(.replay.bytes/1048576|floor) MB)",
         "  ws    : \(.websocket.messages) msgs across \(.websocket.hosts) hosts (\(.websocket.bytes/1048576|floor) MB), \(.websocket.excluded_hosts|length) hosts dropped as telemetry"' \
    "$ARCHIVE_DIR/extract-summary.json"

  # ---- compress the index ----------------------------------------------------
  log "compressing index (zstd -$CAIDO_ZSTD_LEVEL), $(( INDEX_SIZE / 1024 / 1024 )) MB in"
  zstd -q -T0 "-$CAIDO_ZSTD_LEVEL" --long=27 \
    "$PROJECT_DIR/database.caido" -o "$ARCHIVE_DIR/database.caido.zst"

  # ---- verify three ways BEFORE deleting anything ----------------------------
  log "verifying archive"
  zstd -q -t "$ARCHIVE_DIR/database.caido.zst" || die "zstd integrity check failed"

  VERIFY_TMP="$ARCHIVE_DIR/.verify.caido"
  zstd -q -d --long=27 "$ARCHIVE_DIR/database.caido.zst" -o "$VERIFY_TMP"
  # sqlite3 drops -shm/-wal sidecars next to the file even for a read-only open,
  # so sweep those too or they end up in the archive directory.
  cleanup_verify() { rm -f "$VERIFY_TMP" "$VERIFY_TMP"-shm "$VERIFY_TMP"-wal; }
  trap 'cleanup_verify; start_service' EXIT

  cmp "$PROJECT_DIR/database.caido" "$VERIFY_TMP" || die "archive is not byte-identical"
  [[ "$(sqlite3 "file:$VERIFY_TMP?mode=ro" 'PRAGMA quick_check;')" == "ok" ]] \
    || die "restored archive fails SQLite quick_check"
  REQ_COUNT=$(sqlite3 "file:$VERIFY_TMP?mode=ro" "SELECT COUNT(*) FROM requests;")
  REPLAY_COUNT=$(sqlite3 "file:$VERIFY_TMP?mode=ro" "SELECT COUNT(*) FROM replay_entries;")
  (( REQ_COUNT >= 0 && REPLAY_COUNT >= 0 )) || die "archive row counts unreadable"
  log "verified: byte-identical, quick_check ok, $REQ_COUNT requests / $REPLAY_COUNT replay entries"
  cleanup_verify
  trap start_service EXIT

  # ---- manifest --------------------------------------------------------------
  ORIG_TOTAL=$(du -sb "$PROJECT_DIR" | cut -f1)
  cat > "$ARCHIVE_DIR/README.md" <<EOF
# Caido project archive -- $RETIRE_NAME

Retired $(date -u +%Y-%m-%dT%H:%M:%SZ) by \`caido-rotate.sh\`.
Project id \`$RETIRE_ID\`, created $RETIRE_CREATED, $(( ORIG_TOTAL / 1024 / 1024 )) MB on disk.

Retired because Caido cannot prune proxy history: no GraphQL mutation deletes
request/response records, and in-place SQLite deletion cannot reclaim space
(freelist=0, and VACUUM needs a full second copy as scratch). Deleting the
project is the only operation that returns disk.

## Contents

| File | Holds |
|---|---|
| \`database.caido.zst\` | The complete Caido index, verified byte-identical. $REQ_COUNT request records, sitemap, findings, scopes, environments, and all $REPLAY_COUNT replay REQUEST bodies. |
| \`replay-responses.jsonl.gz\` | Response bodies for replay entries (base64 in \`response_b64\`). |
| \`ws-messages.jsonl.gz\` | WebSocket payloads (base64 in \`payload_b64\`), telemetry hosts excluded. |
| \`host-coverage.json\` | Per-host request counts and date ranges -- the coverage denominator. |
| \`extract-summary.json\` | Exactly what was pulled and which hosts were dropped. |

Dropped: \`database_raw.caido\` -- intercepted request/response bodies, plus any
WebSocket host exceeding ${CAIDO_WS_MAX_HOST_MB} MB of payload.

## Restore

\`\`\`bash
zstd -d database.caido.zst -o database.caido
sqlite3 "file:database.caido?mode=ro" \\
  "SELECT host, COUNT(*) FROM requests GROUP BY host ORDER BY 2 DESC LIMIT 20;"
\`\`\`

The index queries standalone; it will **not** load as a Caido project without its
raw counterpart. Treat it as a read-only record of what was tested.
EOF

  ( cd "$ARCHIVE_DIR" && sha256sum ./* > SHA256SUMS 2>/dev/null || true )

  # ---- delete: only now, with the archive verified ---------------------------
  log "deleting project ($(( ORIG_TOTAL / 1024 / 1024 )) MB)"
  rm -rf "$PROJECT_DIR"
  sqlite3 "$PROJECTS_DB" "DELETE FROM projects WHERE id = '$RETIRE_ID';"
  log "archived to $ARCHIVE_DIR ($(du -sh "$ARCHIVE_DIR" | cut -f1))"
fi

# ---- reopen ------------------------------------------------------------------
start_service
trap - EXIT

for _ in $(seq 30); do
  curl -sf -o /dev/null "http://localhost:8080/" 2>/dev/null && break
  sleep 1
done

if (( ! NO_CREATE )); then
  log "creating project: $NEW_NAME"
  # The client prints "[caido] ..." progress lines on stdout ahead of its JSON,
  # so strip those before parsing rather than assuming clean output.
  NEW_ID=$(npx --yes tsx "$CAIDO_CLIENT" create-project "$NEW_NAME" 2>/dev/null \
           | grep -v '^\[caido\]' | jq -r '.id // empty' || true)
  if [[ -n "$NEW_ID" && "$NEW_ID" != "null" ]]; then
    npx --yes tsx "$CAIDO_CLIENT" select-project "$NEW_ID" >/dev/null 2>&1 || true
    log "created and selected $NEW_NAME ($NEW_ID)"
  else
    log "WARNING: could not create $NEW_NAME -- create it manually (cap is 2 projects)"
  fi
fi

log "done. disk: $(df -h / | awk 'NR==2{print $4" free ("$5" used)"}')"
