#!/usr/bin/env bash
# triage-probe.sh <host> <mode:direct|socks> <outfile> <path> [path...]
# Recon-grade GET probe for account-free triage: status line, response headers,
# body peek per path. 0.6s spacing between requests (stays under ~2 rps RoE).
# mode=socks routes through a local SOCKS tunnel (SOCKS_PROXY, default
# socks5h://127.0.0.1:8899) to a residential egress.
set -u
HOST="$1"; MODE="$2"; OUT="$3"; shift 3
UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36'
# A program's egress proxy (roe.json "proxy" / GRIMNIR_PROXY, exported by the calling harness) wins over
# the mode=socks default and is applied even in mode=direct — nothing goes direct while a proxy is
# configured. No project dir here, so egress_init reads GRIMNIR_PROXY from the environment; an
# unusable value refuses the run (exit 4).
source "$(dirname "${BASH_SOURCE[0]}")/../../scripts/egress-env.sh"
egress_init "" || exit 4
PROXY_URL=""
[ "$MODE" = "socks" ] && PROXY_URL="${SOCKS_PROXY:-socks5h://127.0.0.1:8899}"
PROXY_URL="$(egress_effective_proxy "$PROXY_URL")"
PROXY=""
[ -n "$PROXY_URL" ] && PROXY="--proxy $PROXY_URL"
{
  echo "# probe host=$HOST mode=$MODE date=$(date -u +%FT%TZ)"
  echo "# egress=$(curl -s --max-time 10 $PROXY https://ipinfo.io/ip)"
  for p in "$@"; do
    echo "===== GET $p"
    curl -sS --max-time 20 $PROXY -D - -o /tmp/triage-probe-body.$$ \
      -H "User-Agent: $UA" -H "Accept: */*" "https://$HOST$p" | head -c 1600
    echo
    echo "--- body[0:400]:"
    head -c 400 /tmp/triage-probe-body.$$ 2>/dev/null
    echo; echo
    sleep 0.6
  done
  rm -f /tmp/triage-probe-body.$$
} 2>&1 | tee "$OUT"
