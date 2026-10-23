#!/bin/bash
# Module: System — base system setup, directories, user config

module_system_setup() {
    log_section "System Setup"

    # Detect architecture
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)  ARCH_LABEL="amd64" ;;
        aarch64) ARCH_LABEL="arm64" ;;
        armv7l)  ARCH_LABEL="armhf" ;;
        *)       ARCH_LABEL="$ARCH" ;;
    esac
    log_info "Architecture: $ARCH ($ARCH_LABEL)"

    # Detect available RAM
    TOTAL_RAM_MB=$(free -m | awk '/Mem:/{print $2}')
    log_info "Available RAM: ${TOTAL_RAM_MB}MB"

    if [ "$TOTAL_RAM_MB" -lt "$MIN_RAM_MB" ]; then
        log_warn "System has ${TOTAL_RAM_MB}MB RAM, profile recommends ${MIN_RAM_MB}MB"
        log_warn "Installation will continue but performance may be limited"
    fi

    # Create directory structure
    log_info "Creating directory structure"
    mkdir -p "$HOME/agents"/{hunter,specter,artemis,setup}
    mkdir -p "${GRIMNIR_WORKSPACE:-$HOME/workspace}"
    mkdir -p "$HOME/tools"
    mkdir -p "$HOME/go/bin"
    mkdir -p "$HOME/.gf"

    # Ensure PATH includes Go binaries and local bin
    PROFILE_FILE="$HOME/.bashrc"
    if ! grep -q 'go/bin' "$PROFILE_FILE" 2>/dev/null; then
        log_info "Adding Go bin to PATH"
        echo 'export PATH="$HOME/go/bin:$PATH"' >> "$PROFILE_FILE"
    fi
    if ! grep -q '/usr/local/bin' "$PROFILE_FILE" 2>/dev/null; then
        echo 'export PATH="/usr/local/bin:$PATH"' >> "$PROFILE_FILE"
    fi
    export PATH="$HOME/go/bin:/usr/local/bin:$PATH"

    # Setup Python venv
    if [ ! -d "$HOME/venv" ]; then
        log_info "Creating Python virtual environment"
        python3 -m venv "$HOME/venv" 2>/dev/null || {
            sudo apt-get install -y python3-venv
            python3 -m venv "$HOME/venv"
        }
    fi

    log_ok "System setup complete"
}
