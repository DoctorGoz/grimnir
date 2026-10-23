#!/usr/bin/env bash
# Thin wrapper so the pass runs under the `bash huginn/scripts/*` permission grant.
# All logic is in fetch-surface.py. See its header for usage.
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$here/fetch-surface.py" "$@"
