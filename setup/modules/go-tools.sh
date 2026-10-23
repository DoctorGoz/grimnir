#!/bin/bash
# Module: Go Tools — install Go-based security tools

module_go_install() {
    log_section "Go Tools"

    if [ ${#GO_TOOLS[@]} -eq 0 ]; then
        log_info "No Go tools to install"
        return 0
    fi

    # Check if Go is installed
    if ! command -v go &>/dev/null; then
        log_info "Go not found — installing"
        sudo apt-get install -y -qq golang-go 2>/dev/null || {
            log_warn "Failed to install Go via apt, attempting snap"
            sudo snap install go --classic 2>/dev/null || {
                log_error "Cannot install Go — skipping Go tools"
                return 1
            }
        }
    fi

    GO_VERSION=$(go version 2>/dev/null | awk '{print $3}')
    log_info "Go version: $GO_VERSION"

    export GOPATH="$HOME/go"
    export PATH="$GOPATH/bin:$PATH"

    local INSTALLED=0
    local FAILED=0
    for tool in "${GO_TOOLS[@]}"; do
        TOOL_NAME=$(basename "${tool%%@*}")
        # Check if already installed
        if command -v "$TOOL_NAME" &>/dev/null; then
            log_ok "  $TOOL_NAME (already installed)"
            ((INSTALLED++))
            continue
        fi

        log_info "  Installing $TOOL_NAME..."
        if go install "$tool" 2>/dev/null; then
            log_ok "  $TOOL_NAME"
            ((INSTALLED++))
        else
            log_warn "  $TOOL_NAME — failed"
            ((FAILED++))
        fi
    done

    log_ok "Go tools: $INSTALLED installed, $FAILED failed"
}
