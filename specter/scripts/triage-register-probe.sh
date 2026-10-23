#!/usr/bin/env bash
# triage-register-probe.sh <host> <mode:direct|socks> [outfile]
# Answers "is self-registration enabled?" on an Open edX /register form WITHOUT
# creating an account: GET the form, then POST it with all fields empty.
# Empty fields can only fail validation - nothing is persisted.
set -u
HOST="$1"; MODE="$2"; OUT="${3:-/dev/stdout}"
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
exec > >(tee "$OUT") 2>&1
JAR=$(mktemp); PAGE=$(mktemp); POSTBODY=$(mktemp)
curl -sS --max-time 20 $PROXY -c "$JAR" -H "User-Agent: $UA" -o "$PAGE" "https://$HOST/register"
CSRF=$(grep -oE 'name="csrftoken" value="[^"]*"' "$PAGE" | head -1 | grep -oE 'value="[^"]*"' | cut -d'"' -f2)
if [ -z "$CSRF" ]; then CSRF=$(grep csrftoken "$JAR" | awk '{print $7}' | head -1); fi
echo "# host=$HOST date=$(date -u +%FT%TZ)"
echo "# csrf token found: ${CSRF:+yes}"
echo "===== POST /user_api/v1/account/registration/ (all fields empty)"
curl -sS --max-time 20 $PROXY -b "$JAR" -c "$JAR" -D - -o "$POSTBODY" \
  -H "User-Agent: $UA" -H "Referer: https://$HOST/register" \
  -H "X-CSRFToken: $CSRF" -H "Content-Type: application/x-www-form-urlencoded" \
  --data "email=&name=&username=&password=&honor_code=true" \
  "https://$HOST/user_api/v1/account/registration/" | head -25
echo "--- post body[0:800]:"
head -c 800 "$POSTBODY"
rm -f "$JAR" "$PAGE" "$POSTBODY"
