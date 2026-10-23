#!/usr/bin/env bash
# safe-grep.sh — grep with a per-process memory ceiling.
#
# Why: on some hosts `grep` is ugrep, which buffers whole lines. A minified JS
# bundle is often ONE multi-hundred-KB line, so ugrep can balloon to many GB and
# trip the kernel OOM-killer — which then kills whatever process is biggest
# (often a sibling agent), and silently truncates the grep's own results so the
# caller thinks "no more matches." This wrapper caps the grep's address space so
# a runaway fails cleanly with ENOMEM instead of taking down the box.
#
# Usage: exactly like grep. e.g.  bash scripts/safe-grep.sh -oaE 'pat' file
# Cap:   GRIMNIR_GREP_MAXMEM_KB (default 8388608 = 8 GiB). We have plenty of RAM;
#        the point is only to stop a pathological runaway before the global OOM.
#
# NOTE: for mining minified JS specifically, prefer scripts/js-endpoints.py
# (streaming, reads each file individually — cannot OOM on a single long line).
set -uo pipefail
cap="${GRIMNIR_GREP_MAXMEM_KB:-8388608}"
# -v caps virtual address space for THIS shell + the exec'd grep only (not global,
# so it won't break node/V8 agents that reserve huge vsz elsewhere).
ulimit -v "$cap" 2>/dev/null || true
exec grep "$@"
