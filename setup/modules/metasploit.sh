#!/bin/bash
# Module: Metasploit Framework — install and configure

module_metasploit_install() {
    log_section "Metasploit Framework"

    if [ "$INSTALL_METASPLOIT" != "true" ]; then
        log_info "Metasploit not enabled for this profile — skipping"
        return 0
    fi

    # Check if already installed
    if command -v msfconsole &>/dev/null; then
        MSF_VERSION=$(msfconsole --version 2>/dev/null | head -1)
        log_ok "Metasploit already installed: $MSF_VERSION"
        return 0
    fi

    log_info "Installing Metasploit Framework"

    # Try apt first (Kali repos)
    if sudo apt-get install -y -qq metasploit-framework 2>/dev/null; then
        log_ok "Metasploit installed via apt"
    else
        # Fallback to installer script
        log_info "Attempting nightly installer"
        curl -fsSL https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > /tmp/msfinstall
        chmod +x /tmp/msfinstall
        if sudo /tmp/msfinstall; then
            log_ok "Metasploit installed via nightly installer"
        else
            log_error "Metasploit installation failed"
            return 1
        fi
        rm -f /tmp/msfinstall
    fi

    # Initialize database if PostgreSQL is available
    if [ "$INSTALL_POSTGRESQL" = "true" ] && command -v msfdb &>/dev/null; then
        log_info "Initializing Metasploit database"
        sudo msfdb init 2>/dev/null && log_ok "Metasploit DB initialized" || log_warn "DB init failed — msf will work without it"
    fi

    # Install pymetasploit3 for automation
    if [ -d "$HOME/venv" ]; then
        source "$HOME/venv/bin/activate"
        pip install --quiet pymetasploit3 2>/dev/null && log_ok "pymetasploit3 installed"
        deactivate 2>/dev/null
    fi
}
