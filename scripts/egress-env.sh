#!/usr/bin/env bash
# egress-env.sh — source this: shell tooling honors the program's egress proxy, or refuses.
#
# The proxy is roe.json's "proxy" (GRIMNIR_PROXY overrides), read by scripts/egress.py, the one
# reader. Same contract as the Python clients: fail closed. A script that touches the target either
# routes through the proxy or refuses; it never connects directly while a proxy is configured.
#
#   source "$REPO/scripts/egress-env.sh"
#   egress_init "$PROJECT_DIR" || exit 4          # exports ALL_PROXY/HTTPS_PROXY/... + GRIMNIR_PROXY
#   egress_refuse_if_proxied nmap || exit 4       # for a tool that cannot ride a proxy
#   PROXY="$(egress_effective_proxy "$PROXY")"    # an explicit --proxy never overrides the program's
#
# egress_init with no project dir reads GRIMNIR_PROXY only. Exit 4 matches the calling harness's
# `refused-egress`.
_EGRESS_PY="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/egress.py"

egress_init() {  # egress_init [project_dir]
    local out
    if ! out="$(python3 "$_EGRESS_PY" env ${1:+--project-dir "$1"})"; then
        echo "refusing to run: the program's egress proxy is configured but unusable (see above); a direct connection would bypass it" >&2
        return 4
    fi
    [[ -n "$out" ]] && eval "$out"
    return 0
}

egress_refuse_if_proxied() {  # egress_refuse_if_proxied <tool>  (call after egress_init)
    [[ -z "${GRIMNIR_PROXY:-}" ]] && return 0
    echo "$1: refusing to run — the program's egress proxy is '$GRIMNIR_PROXY' and this tool cannot route through it (raw sockets/UDP/ICMP); a direct connection would bypass the program's egress" >&2
    return 4
}

egress_effective_proxy() {  # egress_effective_proxy [explicit_proxy] -> the proxy to use, "" if none
    local explicit="${1:-}"
    if [[ -n "${GRIMNIR_PROXY:-}" ]]; then
        [[ -n "$explicit" && "$explicit" != "$GRIMNIR_PROXY" ]] \
            && echo "egress: ignoring --proxy $explicit; the program's egress proxy is $GRIMNIR_PROXY" >&2
        printf '%s' "$GRIMNIR_PROXY"
    else
        printf '%s' "$explicit"
    fi
}
