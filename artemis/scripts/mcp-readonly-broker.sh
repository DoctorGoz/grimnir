#!/usr/bin/env bash
# mcp-readonly-broker.sh — the read-only choke-point for hands-off MCP testing.
#
# WHY THIS EXISTS
#   When a model drives MCP testing with little supervision, the contract is read-mostly and the
#   safety design must NOT depend on the model obeying a prompt or on the permission layer being
#   configured perfectly. So the agent touches the target through exactly ONE path, this broker,
#   which is read-only BY CONSTRUCTION. It is a single choke-point with a write-refuse-list.
#
#   Layers: (1) confinement of the agent's allowed tools to this broker plus read tools,
#   (2) this broker, read-only by construction (below), and (3) a human confirm step before
#   anything leaves `theoretical`.
#
# READ-ONLY, ENFORCED TWO WAYS
#   * `--include-write` is stripped from EVERY passthrough — the fuzzer's destructive path is
#     unreachable through the broker no matter what the agent appends.
#   * `call` refuses any tool whose name matches a state-changing marker (a superset of
#     mcp-probe.sh's DESTRUCTIVE set — a single adaptive call to create/send/update IS a write,
#     unlike the probe firing a benign canary at a fetch/exec tool). Fail-safe = refuse.
#
# It only ever execs the three vetted sibling scripts (mcp-enum/mcp-probe/mcp-call) with sanitized
# args; it can launch nothing else. Auth is read from $GRIMNIR_MCP_AUTH (so a bearer token never
# rides on argv or in a prompt); pass --no-auth-env to suppress.
#
# Usage:
#   mcp-readonly-broker.sh enum     <url> [opts]                 # read-only handshake + surface map
#   mcp-readonly-broker.sh probe    <url> [opts]                 # injection fuzz (write path stripped,
#                                                                # --max-calls capped at $GRIMNIR_MCP_MAX_CALLS, 60)
#   mcp-readonly-broker.sh call     <url> --tool NAME --args JSON # single tool call (destructive refused)
#   mcp-readonly-broker.sh resource <url> --uri URI [opts]        # resources/read (read-only)
#   mcp-readonly-broker.sh --selftest                            # pure guard checks, no target
#
# Exit: passes through the underlying script's code; 2 usage; 3 refused (destructive tool); 4 refused (the program's egress proxy is unusable).
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# State-changing markers for the `call` guard. Superset of mcp-probe.sh's DESTRUCTIVE set: an
# adaptive single call to a create/send/update tool is itself a mutation, so the read-mostly floor
# is broader than the fuzzer's canary-at-exec-tool skip. Curated to avoid matching common read
# verbs as substrings (no bare set/put/post/patch — they hide in settings/output/compose/dispatch).
# Outbound verbs too (feedback, contact, submit, report...): a call there puts a message in front of
# people at the target, which is a write even when nothing in the product changes.
DESTRUCTIVE_RE='(delete|destroy|remove|drop|purge|revoke|wipe|terminate|deactivate|cancel|uninstall|create|update|write|insert|send|transfer|pay|grant|deploy|install|disable|enable|rotate|modify|overwrite|reset|feedback|contact|message|mail|notify|submit|report|comment|ticket|support|invite|share|publish|reply|book|order|purchase|subscribe|register|upload)'

is_destructive() { echo "${1:-}" | grep -qiE "$DESTRUCTIVE_RE"; }

selftest() {
    local ok=1
    for t in deleteUser destroy_all sendMoney create-token updateProfile revokeKey resetPassword feedback-to-devs submitForm contact_support bookFlight; do
        is_destructive "$t" || { echo "SELFTEST FAIL: '$t' should be destructive"; ok=0; }
    done
    for t in getUser list_tools read_resource searchDocs fetchUrl describe_tool show_config lookup query_db http_get; do
        is_destructive "$t" && { echo "SELFTEST FAIL: '$t' should be allowed"; ok=0; }
    done
    # --include-write must be stripped
    local -a out; mapfile -t out < <(strip_write --tool fetch --include-write --max-calls 5)
    printf '%s\n' "${out[@]}" | grep -q -- '--include-write' && { echo "SELFTEST FAIL: --include-write not stripped"; ok=0; }
    [[ $ok == 1 ]] && { echo "mcp-readonly-broker selftest OK"; return 0; } || return 1
}

# Echo the args with every --include-write removed (one per line, for safe re-capture).
strip_write() {
    local a
    for a in "$@"; do [[ "$a" == "--include-write" ]] && continue; printf '%s\n' "$a"; done
}

main() {
    local sub="${1:-}"
    [[ "$sub" == "--selftest" ]] && { selftest; return $?; }
    shift || true
    local url="${1:-}"; shift || true
    if [[ -z "$sub" || -z "$url" ]]; then
        sed -n '31,39p' "${BASH_SOURCE[0]}" >&2; return 2
    fi

    # egress-layer:begin
    # The program's egress proxy (roe.json of the engagement, or GRIMNIR_PROXY) is read HERE, once,
    # and exported to the three scripts below, which override any --proxy the agent passes: an
    # unattended run on a proxied program goes through that proxy or does not run (exit 4).
    if [[ -f "$HERE/../../scripts/egress-env.sh" ]]; then
        source "$HERE/../../scripts/egress-env.sh"
        egress_init "${GRIMNIR_MCP_PROJECT_DIR:-}" || return 4
    fi
    # egress-layer:end

    # Sanitize passthrough: drop --include-write anywhere in the tail.
    local -a args=(); local a
    for a in "$@"; do [[ "$a" == "--include-write" ]] && continue; args+=("$a"); done

    # project-dir-layer:begin
    # enum/probe write their output under the engagement ($GRIMNIR_MCP_PROJECT_DIR), never into the
    # caller's working directory (the repo, for an unattended specialist), unless told where.
    if [[ ( "$sub" == enum || "$sub" == probe ) && -n "${GRIMNIR_MCP_PROJECT_DIR:-}" ]] \
        && [[ ! " ${args[*]} " =~ \ --(project-dir|out)\  ]]; then
        args+=(--project-dir "$GRIMNIR_MCP_PROJECT_DIR")
    fi
    # project-dir-layer:end

    # Auth from the environment, never argv/prompt (unless suppressed).
    local -a auth=()
    if [[ -n "${GRIMNIR_MCP_AUTH:-}" && "${1:-}" != "--no-auth-env" ]]; then
        auth=(--auth "$GRIMNIR_MCP_AUTH")
    fi

    case "$sub" in
        enum)     exec bash "$HERE/mcp-enum.sh"  "$url" "${auth[@]}" "${args[@]}" ;;
        probe)
            # The fuzzer skips write-shaped tools by its own, narrower list, and trusts a server's
            # readOnlyHint; hand it this floor, which it applies regardless, and refuse an explicit one.
            local tool="" i
            for ((i=0; i<${#args[@]}; i++)); do
                [[ "${args[$i]}" == "--tool" ]] && { tool="${args[$((i+1))]:-}"; break; }
            done
            if [[ -n "$tool" ]] && is_destructive "$tool"; then
                echo "refused: tool '$tool' matches a state-changing marker — the read-mostly broker will not fuzz it" >&2
                return 3
            fi
            # An unattended fuzz is bounded: the fuzzer's own default (400 calls) is a manual-run figure.
            local cap="${GRIMNIR_MCP_MAX_CALLS:-60}" want="" j
            local -a capped=()
            for ((j=0; j<${#args[@]}; j++)); do
                if [[ "${args[$j]}" == "--max-calls" ]]; then want="${args[$((j+1))]:-}"; j=$((j+1)); continue; fi
                capped+=("${args[$j]}")
            done
            [[ "$want" =~ ^[0-9]+$ && "$want" -lt "$cap" ]] && cap="$want"
            GN_SKIP_RE="$DESTRUCTIVE_RE" exec bash "$HERE/mcp-probe.sh" "$url" "${auth[@]}" "${capped[@]}" --max-calls "$cap" ;;
        resource) exec bash "$HERE/mcp-call.sh"  "$url" "${auth[@]}" "${args[@]}" ;;  # --resource read is read-only
        call)
            # Extract --tool NAME and refuse if it looks state-changing.
            local tool="" i
            for ((i=0; i<${#args[@]}; i++)); do
                [[ "${args[$i]}" == "--tool" ]] && { tool="${args[$((i+1))]:-}"; break; }
            done
            if [[ -n "$tool" ]] && is_destructive "$tool"; then
                echo "refused: tool '$tool' matches a state-changing marker — the read-mostly broker will not call it (this is a floor, not a judgement of intent)" >&2
                return 3
            fi
            exec bash "$HERE/mcp-call.sh" "$url" "${auth[@]}" "${args[@]}" ;;
        *) echo "unknown subcommand: $sub (want enum|probe|call|resource)" >&2; return 2 ;;
    esac
}

main "$@"
