#!/bin/bash
# Module: APT Packages — install system packages

module_apt_install() {
    log_section "APT Packages"

    if [ ${#APT_PACKAGES[@]} -eq 0 ]; then
        log_info "No APT packages to install"
        return 0
    fi

    log_info "Updating package index"
    sudo apt-get update -qq

    # Filter to only packages that aren't already installed
    local TO_INSTALL=()
    for pkg in "${APT_PACKAGES[@]}"; do
        if ! dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
            TO_INSTALL+=("$pkg")
        fi
    done

    if [ ${#TO_INSTALL[@]} -eq 0 ]; then
        log_ok "All ${#APT_PACKAGES[@]} APT packages already installed"
        return 0
    fi

    log_info "Installing ${#TO_INSTALL[@]} packages (${#APT_PACKAGES[@]} total, $(( ${#APT_PACKAGES[@]} - ${#TO_INSTALL[@]} )) already installed)"

    local FAILED=()
    for pkg in "${TO_INSTALL[@]}"; do
        if sudo apt-get install -y -qq "$pkg" 2>/dev/null; then
            log_ok "  $pkg"
        else
            log_warn "  $pkg — failed to install"
            FAILED+=("$pkg")
        fi
    done

    if [ ${#FAILED[@]} -gt 0 ]; then
        log_warn "${#FAILED[@]} packages failed: ${FAILED[*]}"
    fi

    log_ok "APT packages complete"
}
