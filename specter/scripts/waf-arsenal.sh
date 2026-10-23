#!/usr/bin/env bash
# WAF arsenal — targeted evasion payload engineering (fingerprint -> context -> variants).
# Thin wrapper over specter/scripts/waf/arsenal.py so it runs under the `bash specter/scripts/*`
# allow-list. All subcommands and flags pass straight through.
#
#   waf-arsenal.sh encode --payload "<script>alert(1)</script>" --waf cloudflare --context html_text
#   waf-arsenal.sh probe  --url https://t.example/search --param q
#   waf-arsenal.sh run    --url https://t.example/search --param q --payload "' OR 1=1-- -"
#
# A variant is a CANDIDATE. A 200 through the WAF is not a finding: confirm the underlying
# payload fires at the origin, then promote with scripts/validate-finding.sh.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$HERE/waf/arsenal.py" "$@"
