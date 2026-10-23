#!/bin/bash
# Module: GRIMNIR Agents — clone/update agent repos and configure

GRIMNIR_REPO="${GRIMNIR_REPO:-}"  # Set to GitHub URL when available

module_agents_setup() {
    log_section "GRIMNIR Agent Setup"

    local AGENTS_DIR="$HOME/agents"
    # Checkout location. $GRIMNIR_REPO above is the clone URL, not the directory.
    local WORKSPACE_DIR="${GRIMNIR_REPO_DIR:-$HOME/workspace/grimnir}"

    # If we have a GitHub repo, clone/pull it
    if [ -n "$GRIMNIR_REPO" ]; then
        log_info "Syncing from repository: $GRIMNIR_REPO"
        if [ -d "$WORKSPACE_DIR/.git" ]; then
            cd "$WORKSPACE_DIR" && git pull --ff-only 2>/dev/null
            log_ok "Repository updated"
        else
            mkdir -p "$(dirname "$WORKSPACE_DIR")"
            git clone "$GRIMNIR_REPO" "$WORKSPACE_DIR" 2>/dev/null
            log_ok "Repository cloned"
        fi
    fi

    # Setup each enabled agent
    for agent in $AGENTS; do
        log_info "Configuring agent: $agent"

        # Create agent directory structure
        mkdir -p "$AGENTS_DIR/$agent"/{scripts,wordlists,templates,docs,reports}

        # Create symlink in workspace if not exists
        if [ -d "$WORKSPACE_DIR" ] && [ ! -e "$WORKSPACE_DIR/$agent" ]; then
            ln -sf "$AGENTS_DIR/$agent" "$WORKSPACE_DIR/$agent"
            log_ok "  Symlinked $agent → workspace"
        fi

        # Make scripts executable
        chmod +x "$AGENTS_DIR/$agent/scripts/"*.sh 2>/dev/null

        log_ok "  $agent configured"
    done

    # Create engagement directory structure
    mkdir -p "$WORKSPACE_DIR/engagements"

    # Setup SecLists if not present (critical for all agents)
    if [ ! -d "/usr/share/seclists" ] && [ ! -d "/usr/share/wordlists/seclists" ]; then
        log_info "Installing SecLists wordlists"
        sudo apt-get install -y -qq seclists 2>/dev/null || {
            log_info "Cloning SecLists from GitHub"
            sudo git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists 2>/dev/null
        }
    fi

    log_ok "Agent setup complete — enabled: $AGENTS"
}
