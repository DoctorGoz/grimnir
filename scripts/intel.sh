#!/bin/bash
set -euo pipefail

# Grimnir Intel Discovery Feed Manager
# Append-only JSONL feed for cross-agent intelligence sharing

usage() {
    cat <<'EOF'
Usage: intel.sh COMMAND [OPTIONS]

Commands:
  add       Append a new discovery
  query     Query the intel feed with filters
  mark      Mark a discovery as processed
  summary   Print intel feed statistics
  route     Show discoveries needing routing to agents

add (required):
  --project-dir DIR        Absolute path
  --agent AGENT            Source agent
  --type TYPE              endpoint|service|credential|technology|vulnerability_hint|
                           api_spec|subdomain|certificate|relationship|note
  --confidence LEVEL       confirmed|high|medium|low|unverified

add (type-specific):
  endpoint:     --url URL [--method M] [--auth-required BOOL] [--param P]... [--discovered-via TEXT]
  service:      --host H --port P --protocol PROTO [--service-name N] [--service-version V]
  credential:   --cred-type TYPE --location TEXT [--value-redacted TEXT] [--cred-service TEXT]
  technology:   --name NAME [--version V] [--tech-category CAT] [--tech-target TARGET]
  vuln_hint:    --hint TEXT [--affected TEXT] [--potential-category CAT] [--suggested-test TEXT]
  api_spec:     --format FMT --spec-url URL [--endpoints-count N]
  subdomain:    --subdomain FQDN [--resolved-ip IP] [--discovered-via TEXT]
  certificate:  --cert-host HOST [--issuer TEXT] [--san SAN]...
  relationship: --from TEXT --to TEXT --rel-type TEXT
  note:         --content TEXT [--context TEXT]

  --tag TAG              Routing tag (repeatable): needs-huginn, needs-specter, needs-artemis, needs-hunter, needs-nimbus, needs-nomad, high-value

query:
  --project-dir DIR      (required)
  --type TYPE            Filter by discovery type
  --agent AGENT          Filter by source agent
  --tag TAG              Filter by tag (repeatable, OR)
  --unprocessed          Only unprocessed
  --limit N              Max results (default: all)
  --format FORMAT        json|table (default: table)

mark:
  --project-dir DIR      (required)
  --id INTEL-ID          Discovery ID (required)
  --processed-by AGENT   (required)
  --related-finding FID  Associated finding ID

summary:
  --project-dir DIR      (required)

route:
  --project-dir DIR      (required)
  --for-agent AGENT      Filter to specific agent
EOF
    exit 1
}

NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)

[[ $# -lt 1 ]] && usage
COMMAND="$1"; shift

# ── Parse options ──
PROJECT_DIR=""
AGENT=""
DISC_TYPE=""
CONFIDENCE=""
TAGS=()

# type-specific
URL="" METHOD="" AUTH_REQUIRED="" PARAMS=() DISCOVERED_VIA=""
HOST="" PORT="" PROTOCOL="" SERVICE_NAME="" SERVICE_VERSION=""
CRED_TYPE="" LOCATION="" VALUE_REDACTED="" CRED_SERVICE=""
TECH_NAME="" VERSION="" TECH_CATEGORY="" TECH_TARGET=""
HINT="" AFFECTED="" POTENTIAL_CAT="" SUGGESTED_TEST=""
SPEC_FORMAT="" SPEC_URL="" ENDPOINTS_COUNT=""
SUBDOMAIN="" RESOLVED_IP=""
CERT_HOST="" ISSUER="" SANS=()
FROM="" TO="" REL_TYPE=""
CONTENT="" CONTEXT=""

# query/mark
INTEL_ID="" PROCESSED_BY="" RELATED_FINDING=""
FILTER_TYPE="" FILTER_AGENT="" FILTER_TAGS=() UNPROCESSED=false
LIMIT="" FORMAT="table" FOR_AGENT=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --project-dir)       PROJECT_DIR="$2"; shift 2 ;;
        --agent)             AGENT="$2"; shift 2 ;;
        --type)              DISC_TYPE="$2"; FILTER_TYPE="$2"; shift 2 ;;
        --confidence)        CONFIDENCE="$2"; shift 2 ;;
        --tag)               TAGS+=("$2"); FILTER_TAGS+=("$2"); shift 2 ;;
        --url)               URL="$2"; shift 2 ;;
        --method)            METHOD="${2:-GET}"; shift 2 ;;
        --auth-required)     AUTH_REQUIRED="$2"; shift 2 ;;
        --param)             PARAMS+=("$2"); shift 2 ;;
        --discovered-via)    DISCOVERED_VIA="$2"; shift 2 ;;
        --host)              HOST="$2"; shift 2 ;;
        --port)              PORT="$2"; shift 2 ;;
        --protocol)          PROTOCOL="$2"; shift 2 ;;
        --service-name)      SERVICE_NAME="$2"; shift 2 ;;
        --service-version)   SERVICE_VERSION="$2"; shift 2 ;;
        --cred-type)         CRED_TYPE="$2"; shift 2 ;;
        --location)          LOCATION="$2"; shift 2 ;;
        --value-redacted)    VALUE_REDACTED="$2"; shift 2 ;;
        --cred-service)      CRED_SERVICE="$2"; shift 2 ;;
        --name)              TECH_NAME="$2"; shift 2 ;;
        --version)           VERSION="$2"; shift 2 ;;
        --tech-category)     TECH_CATEGORY="$2"; shift 2 ;;
        --tech-target)       TECH_TARGET="$2"; shift 2 ;;
        --hint)              HINT="$2"; shift 2 ;;
        --affected)          AFFECTED="$2"; shift 2 ;;
        --potential-category) POTENTIAL_CAT="$2"; shift 2 ;;
        --suggested-test)    SUGGESTED_TEST="$2"; shift 2 ;;
        --format)            if [[ "$COMMAND" == "add" ]]; then SPEC_FORMAT="$2"; else FORMAT="$2"; fi; shift 2 ;;
        --spec-url)          SPEC_URL="$2"; shift 2 ;;
        --endpoints-count)   ENDPOINTS_COUNT="$2"; shift 2 ;;
        --subdomain)         SUBDOMAIN="$2"; shift 2 ;;
        --resolved-ip)       RESOLVED_IP="$2"; shift 2 ;;
        --cert-host)         CERT_HOST="$2"; shift 2 ;;
        --issuer)            ISSUER="$2"; shift 2 ;;
        --san)               SANS+=("$2"); shift 2 ;;
        --from)              FROM="$2"; shift 2 ;;
        --to)                TO="$2"; shift 2 ;;
        --rel-type)          REL_TYPE="$2"; shift 2 ;;
        --content)           CONTENT="$2"; shift 2 ;;
        --note|--notes)      CONTENT="$2"; shift 2 ;;   # alias: free-text -> .content (note type) / .discovered_via (endpoint,subdomain)
        --context)           CONTEXT="$2"; shift 2 ;;
        --id)                INTEL_ID="$2"; shift 2 ;;
        --processed-by)      PROCESSED_BY="$2"; shift 2 ;;
        --related-finding)   RELATED_FINDING="$2"; shift 2 ;;
        --unprocessed)       UNPROCESSED=true; shift ;;
        --limit)             LIMIT="$2"; shift 2 ;;
        --for-agent)         FOR_AGENT="$2"; shift 2 ;;
        --help|-h)           usage ;;
        *)                   echo "Unknown option: $1" >&2
                             echo "  hint: free-text goes in --note/--content (note type) or --discovered-via (endpoint/subdomain). Run 'intel.sh --help' for per-type flags." >&2
                             exit 1 ;;
    esac
done

[[ -z "$PROJECT_DIR" ]] && { echo "Error: --project-dir required" >&2; exit 1; }
[[ "$PROJECT_DIR" != /* ]] && { echo "Error: --project-dir must be absolute" >&2; exit 1; }

INTEL_FILE="$PROJECT_DIR/intel.jsonl"

json_array() {
    local arr=("$@")
    if [[ ${#arr[@]} -eq 0 ]]; then echo "[]"; return; fi
    printf '%s\n' "${arr[@]}" | jq -R . | jq -s .
}

case "$COMMAND" in
    add)
        [[ -z "$AGENT" ]] && { echo "Error: --agent required" >&2; exit 1; }
        [[ -z "$DISC_TYPE" ]] && { echo "Error: --type required" >&2; exit 1; }
        [[ -z "$CONFIDENCE" ]] && { echo "Error: --confidence required" >&2; exit 1; }

        # Determine next ID
        if [[ -f "$INTEL_FILE" ]]; then
            LINE_COUNT=$(wc -l < "$INTEL_FILE")
        else
            LINE_COUNT=0
        fi
        NEXT_ID=$(printf "INTEL-%06d" $((LINE_COUNT + 1)))

        # Build type-specific data object
        DATA='{}'
        case "$DISC_TYPE" in
            endpoint)
                [[ -z "$URL" ]] && { echo "Error: --url required for endpoint" >&2; exit 1; }
                DATA=$(echo "$DATA" | jq --arg v "$URL" '.url = $v')
                [[ -n "$METHOD" ]] && DATA=$(echo "$DATA" | jq --arg v "$METHOD" '.method = $v')
                [[ -n "$AUTH_REQUIRED" ]] && DATA=$(echo "$DATA" | jq --argjson v "$AUTH_REQUIRED" '.auth_required = $v')
                [[ ${#PARAMS[@]} -gt 0 ]] && DATA=$(echo "$DATA" | jq --argjson p "$(json_array "${PARAMS[@]}")" '.parameters = $p')
                DV="${DISCOVERED_VIA:-$CONTENT}"
                [[ -n "$DV" ]] && DATA=$(echo "$DATA" | jq --arg v "$DV" '.discovered_via = $v')
                ;;
            service)
                [[ -z "$HOST" ]] && { echo "Error: --host required for service" >&2; exit 1; }
                [[ -z "$PORT" ]] && { echo "Error: --port required for service" >&2; exit 1; }
                [[ -z "$PROTOCOL" ]] && { echo "Error: --protocol required for service" >&2; exit 1; }
                DATA=$(echo "$DATA" | jq --arg h "$HOST" --argjson p "$PORT" --arg pr "$PROTOCOL" '.host = $h | .port = $p | .protocol = $pr')
                [[ -n "$SERVICE_NAME" ]] && DATA=$(echo "$DATA" | jq --arg v "$SERVICE_NAME" '.service_name = $v')
                [[ -n "$SERVICE_VERSION" ]] && DATA=$(echo "$DATA" | jq --arg v "$SERVICE_VERSION" '.service_version = $v')
                ;;
            credential)
                [[ -z "$CRED_TYPE" ]] && { echo "Error: --cred-type required" >&2; exit 1; }
                DATA=$(echo "$DATA" | jq --arg v "$CRED_TYPE" '.type = $v')
                [[ -n "$LOCATION" ]] && DATA=$(echo "$DATA" | jq --arg v "$LOCATION" '.location = $v')
                [[ -n "$VALUE_REDACTED" ]] && DATA=$(echo "$DATA" | jq --arg v "$VALUE_REDACTED" '.value_redacted = $v')
                [[ -n "$CRED_SERVICE" ]] && DATA=$(echo "$DATA" | jq --arg v "$CRED_SERVICE" '.service = $v')
                ;;
            technology)
                [[ -z "$TECH_NAME" ]] && { echo "Error: --name required" >&2; exit 1; }
                DATA=$(echo "$DATA" | jq --arg v "$TECH_NAME" '.name = $v')
                [[ -n "$VERSION" ]] && DATA=$(echo "$DATA" | jq --arg v "$VERSION" '.version = $v')
                [[ -n "$TECH_CATEGORY" ]] && DATA=$(echo "$DATA" | jq --arg v "$TECH_CATEGORY" '.category = $v')
                [[ -n "$TECH_TARGET" ]] && DATA=$(echo "$DATA" | jq --arg v "$TECH_TARGET" '.target = $v')
                ;;
            vulnerability_hint)
                [[ -z "$HINT" ]] && { echo "Error: --hint required" >&2; exit 1; }
                DATA=$(echo "$DATA" | jq --arg v "$HINT" '.hint = $v')
                [[ -n "$AFFECTED" ]] && DATA=$(echo "$DATA" | jq --arg v "$AFFECTED" '.affected_endpoint = $v')
                [[ -n "$POTENTIAL_CAT" ]] && DATA=$(echo "$DATA" | jq --arg v "$POTENTIAL_CAT" '.potential_category = $v')
                [[ -n "$SUGGESTED_TEST" ]] && DATA=$(echo "$DATA" | jq --arg v "$SUGGESTED_TEST" '.suggested_test = $v')
                ;;
            api_spec)
                [[ -z "$SPEC_FORMAT" ]] && { echo "Error: --format required" >&2; exit 1; }
                [[ -z "$SPEC_URL" ]] && { echo "Error: --spec-url required" >&2; exit 1; }
                DATA=$(echo "$DATA" | jq --arg f "$SPEC_FORMAT" --arg u "$SPEC_URL" '.format = $f | .url = $u')
                [[ -n "$ENDPOINTS_COUNT" ]] && DATA=$(echo "$DATA" | jq --argjson n "$ENDPOINTS_COUNT" '.endpoints_count = $n')
                ;;
            subdomain)
                [[ -z "$SUBDOMAIN" ]] && { echo "Error: --subdomain required" >&2; exit 1; }
                DATA=$(echo "$DATA" | jq --arg v "$SUBDOMAIN" '.subdomain = $v')
                [[ -n "$RESOLVED_IP" ]] && DATA=$(echo "$DATA" | jq --arg v "$RESOLVED_IP" '.resolved_ip = $v')
                DV="${DISCOVERED_VIA:-$CONTENT}"
                [[ -n "$DV" ]] && DATA=$(echo "$DATA" | jq --arg v "$DV" '.discovered_via = $v')
                ;;
            certificate)
                [[ -z "$CERT_HOST" ]] && { echo "Error: --cert-host required" >&2; exit 1; }
                DATA=$(echo "$DATA" | jq --arg v "$CERT_HOST" '.host = $v')
                [[ -n "$ISSUER" ]] && DATA=$(echo "$DATA" | jq --arg v "$ISSUER" '.issuer = $v')
                [[ ${#SANS[@]} -gt 0 ]] && DATA=$(echo "$DATA" | jq --argjson s "$(json_array "${SANS[@]}")" '.sans = $s')
                ;;
            relationship)
                [[ -z "$FROM" || -z "$TO" || -z "$REL_TYPE" ]] && { echo "Error: --from, --to, --rel-type required" >&2; exit 1; }
                DATA=$(echo "$DATA" | jq --arg f "$FROM" --arg t "$TO" --arg r "$REL_TYPE" '.from = $f | .to = $t | .relationship_type = $r')
                ;;
            note)
                [[ -z "$CONTENT" ]] && { echo "Error: --content required" >&2; exit 1; }
                DATA=$(echo "$DATA" | jq --arg v "$CONTENT" '.content = $v')
                [[ -n "$CONTEXT" ]] && DATA=$(echo "$DATA" | jq --arg v "$CONTEXT" '.context = $v')
                ;;
            *)
                echo "Error: unknown type $DISC_TYPE" >&2; exit 1
                ;;
        esac

        # Build tags array
        TAGS_JSON="[]"
        if [[ ${#TAGS[@]} -gt 0 ]]; then
            TAGS_JSON=$(json_array "${TAGS[@]}")
        fi

        # Build entry
        ENTRY=$(jq -n -c \
            --arg id "$NEXT_ID" \
            --arg ts "$NOW" \
            --arg agent "$AGENT" \
            --arg dtype "$DISC_TYPE" \
            --argjson data "$DATA" \
            --arg conf "$CONFIDENCE" \
            --argjson tags "$TAGS_JSON" \
            '{
                id: $id,
                timestamp: $ts,
                source_agent: $agent,
                discovery_type: $dtype,
                data: $data,
                confidence: $conf,
                tags: $tags,
                processed: false
            }')

        echo "$ENTRY" >> "$INTEL_FILE"
        echo "$NEXT_ID"
        ;;

    query)
        [[ ! -f "$INTEL_FILE" ]] && { echo "No intel feed found at $PROJECT_DIR" >&2; exit 0; }

        # Build jq filter
        FILTER="."
        [[ -n "$FILTER_TYPE" ]] && FILTER="$FILTER | select(.discovery_type == \"$FILTER_TYPE\")"
        [[ -n "$FILTER_AGENT" ]] && FILTER="$FILTER | select(.source_agent == \"$FILTER_AGENT\")"
        [[ "$UNPROCESSED" == true ]] && FILTER="$FILTER | select(.processed == false)"

        if [[ ${#FILTER_TAGS[@]} -gt 0 ]]; then
            TAG_CONDS=""
            for t in "${FILTER_TAGS[@]}"; do
                [[ -n "$TAG_CONDS" ]] && TAG_CONDS="$TAG_CONDS or "
                TAG_CONDS="${TAG_CONDS}(.tags | index(\"$t\"))"
            done
            FILTER="$FILTER | select($TAG_CONDS)"
        fi

        RESULTS=$(jq -c "$FILTER" "$INTEL_FILE")

        if [[ -n "$LIMIT" ]]; then
            RESULTS=$(echo "$RESULTS" | head -n "$LIMIT")
        fi

        if [[ "$FORMAT" == "json" ]]; then
            echo "$RESULTS" | jq .
        else
            # Table format
            if [[ -z "$RESULTS" ]]; then
                echo "No results"
            else
                printf "%-14s %-10s %-18s %-10s %-6s %s\n" "ID" "AGENT" "TYPE" "CONF" "PROC" "SUMMARY"
                printf "%-14s %-10s %-18s %-10s %-6s %s\n" "──────────────" "──────────" "──────────────────" "──────────" "──────" "────────────────────"
                echo "$RESULTS" | while IFS= read -r line; do
                    ID=$(echo "$line" | jq -r '.id')
                    AG=$(echo "$line" | jq -r '.source_agent')
                    TY=$(echo "$line" | jq -r '.discovery_type')
                    CO=$(echo "$line" | jq -r '.confidence')
                    PR=$(echo "$line" | jq -r '.processed')
                    # Build summary from data
                    SUMM=$(echo "$line" | jq -r '
                        if .discovery_type == "endpoint" then .data.url // ""
                        elif .discovery_type == "service" then "\(.data.host):\(.data.port) \(.data.service_name // "")"
                        elif .discovery_type == "subdomain" then .data.subdomain // ""
                        elif .discovery_type == "technology" then "\(.data.name) \(.data.version // "")"
                        elif .discovery_type == "vulnerability_hint" then .data.hint // "" | .[0:60]
                        elif .discovery_type == "credential" then "\(.data.type) at \(.data.location // "unknown")"
                        elif .discovery_type == "note" then .data.content // "" | .[0:60]
                        elif .discovery_type == "relationship" then "\(.data.from) -> \(.data.to)"
                        elif .discovery_type == "certificate" then .data.host // ""
                        elif .discovery_type == "api_spec" then .data.url // ""
                        else "" end')
                    printf "%-14s %-10s %-18s %-10s %-6s %s\n" "$ID" "$AG" "$TY" "$CO" "$PR" "$SUMM"
                done
            fi
        fi
        ;;

    mark)
        [[ -z "$INTEL_ID" ]] && { echo "Error: --id required" >&2; exit 1; }
        [[ -z "$PROCESSED_BY" ]] && { echo "Error: --processed-by required" >&2; exit 1; }
        [[ ! -f "$INTEL_FILE" ]] && { echo "Error: no intel feed found" >&2; exit 1; }

        # Update the matching line
        TMPFILE=$(mktemp)
        FOUND=false
        while IFS= read -r line; do
            LID=$(echo "$line" | jq -r '.id')
            if [[ "$LID" == "$INTEL_ID" ]]; then
                FOUND=true
                line=$(echo "$line" | jq -c --arg pb "$PROCESSED_BY" '.processed = true | .processed_by = $pb')
                if [[ -n "$RELATED_FINDING" ]]; then
                    line=$(echo "$line" | jq -c --arg rf "$RELATED_FINDING" '.related_finding = $rf')
                fi
            fi
            echo "$line"
        done < "$INTEL_FILE" > "$TMPFILE"

        if [[ "$FOUND" == true ]]; then
            mv "$TMPFILE" "$INTEL_FILE"
            echo "Marked $INTEL_ID as processed by $PROCESSED_BY"
        else
            rm "$TMPFILE"
            echo "Error: $INTEL_ID not found" >&2
            exit 1
        fi
        ;;

    summary)
        [[ ! -f "$INTEL_FILE" ]] && { echo "No intel feed found at $PROJECT_DIR. Run /engage first." >&2; exit 0; }

        TOTAL=$(wc -l < "$INTEL_FILE")
        UNPROC=$(jq -c 'select(.processed == false)' "$INTEL_FILE" | wc -l)

        echo "Intel Feed: $INTEL_FILE"
        echo "Total discoveries: $TOTAL  |  Unprocessed: $UNPROC"
        echo ""

        echo "By Type:"
        jq -r '.discovery_type' "$INTEL_FILE" | sort | uniq -c | sort -rn | while read -r count dtype; do
            printf "  %-20s %d\n" "$dtype" "$count"
        done
        echo ""

        echo "By Source Agent:"
        jq -r '.source_agent' "$INTEL_FILE" | sort | uniq -c | sort -rn | while read -r count agent; do
            printf "  %-12s %d\n" "$agent" "$count"
        done
        echo ""

        echo "Routing Queue:"
        for a in huginn specter artemis hunter nimbus nomad; do
            COUNT=$(jq -c "select(.processed == false and (.tags | index(\"needs-$a\")))" "$INTEL_FILE" 2>/dev/null | wc -l)
            [[ "$COUNT" -gt 0 ]] && printf "  needs-%-8s %d discoveries pending\n" "$a" "$COUNT"
        done
        HV=$(jq -c 'select(.processed == false and (.tags | index("high-value")))' "$INTEL_FILE" 2>/dev/null | wc -l)
        [[ "$HV" -gt 0 ]] && printf "  high-value       %d discoveries pending\n" "$HV"
        ;;

    route)
        [[ ! -f "$INTEL_FILE" ]] && { echo "No intel feed found" >&2; exit 0; }

        if [[ -n "$FOR_AGENT" ]]; then
            FILTER="select(.processed == false and (.tags | index(\"needs-$FOR_AGENT\")))"
        else
            FILTER='select(.processed == false and (.tags | any(startswith("needs-"))))'
        fi

        RESULTS=$(jq -c "$FILTER" "$INTEL_FILE")

        if [[ -z "$RESULTS" ]]; then
            echo "No pending routing"
        else
            printf "%-14s %-10s %-18s %s\n" "ID" "ROUTE TO" "TYPE" "SUMMARY"
            printf "%-14s %-10s %-18s %s\n" "──────────────" "──────────" "──────────────────" "────────────────────"
            echo "$RESULTS" | while IFS= read -r line; do
                ID=$(echo "$line" | jq -r '.id')
                TY=$(echo "$line" | jq -r '.discovery_type')
                ROUTE=$(echo "$line" | jq -r '[.tags[] | select(startswith("needs-"))] | join(",")')
                SUMM=$(echo "$line" | jq -r '
                    if .discovery_type == "endpoint" then .data.url // ""
                    elif .discovery_type == "service" then "\(.data.host):\(.data.port) \(.data.service_name // "")"
                    elif .discovery_type == "subdomain" then .data.subdomain // ""
                    elif .discovery_type == "technology" then "\(.data.name) \(.data.version // "")"
                    elif .discovery_type == "vulnerability_hint" then .data.hint // "" | .[0:60]
                    elif .discovery_type == "credential" then "\(.data.type) at \(.data.location // "unknown")"
                    elif .discovery_type == "note" then .data.content // "" | .[0:60]
                    elif .discovery_type == "relationship" then "\(.data.from) -> \(.data.to)"
                    elif .discovery_type == "certificate" then .data.host // ""
                    elif .discovery_type == "api_spec" then .data.url // ""
                    else (.data.name // .data.url // "") end')
                printf "%-14s %-10s %-18s %s\n" "$ID" "$ROUTE" "$TY" "$SUMM"
            done
        fi
        ;;

    *)
        echo "Unknown command: $COMMAND" >&2
        usage
        ;;
esac
