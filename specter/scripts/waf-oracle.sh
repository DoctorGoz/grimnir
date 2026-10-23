#!/usr/bin/env bash
# WAF test oracle — measure evasion against REAL OWASP ModSecurity/CRS (via podman).
# Thin wrapper over specter/scripts/waf/oracle.py (runs under `bash specter/scripts/*`).
#
#   waf-oracle.sh up                 # start CRS + backend (~5s, idempotent)
#   waf-oracle.sh status             # reachable? blocks a raw payload?
#   waf-oracle.sh measure --payload '<script>alert(1)</script>' --context html_text --waf modsecurity
#   waf-oracle.sh down               # tear everything down
#
# Requires podman. A variant that "passed_waf" cleared CRS's request filter -- it is NOT
# a finding until the underlying payload fires at a real origin (scripts/validate-finding.sh).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$HERE/waf/oracle.py" "$@"
