#!/bin/bash
# Module: Python Packages — install into venv

module_pip_install() {
    log_section "Python Packages"

    if [ ${#PIP_PACKAGES[@]} -eq 0 ]; then
        log_info "No Python packages to install"
        return 0
    fi

    # Activate venv
    if [ -d "$HOME/venv" ]; then
        source "$HOME/venv/bin/activate"
    else
        log_warn "Python venv not found at ~/venv — creating"
        python3 -m venv "$HOME/venv"
        source "$HOME/venv/bin/activate"
    fi

    # Upgrade pip
    pip install --quiet --upgrade pip 2>/dev/null

    local INSTALLED=0
    local FAILED=0
    for pkg in "${PIP_PACKAGES[@]}"; do
        if pip show "$pkg" &>/dev/null; then
            log_ok "  $pkg (already installed)"
            ((INSTALLED++))
            continue
        fi

        if pip install --quiet "$pkg" 2>/dev/null; then
            log_ok "  $pkg"
            ((INSTALLED++))
        else
            log_warn "  $pkg — failed"
            ((FAILED++))
        fi
    done

    deactivate 2>/dev/null
    log_ok "Python packages: $INSTALLED installed, $FAILED failed"
}
