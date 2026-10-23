#!/bin/bash
# ============================================================================
# GRIMNIR Setup — Fedora VPS / Workstation Provisioning
# ============================================================================
#
# Usage:
#   ./setup-fedora.sh                          # Interactive — prompts for profile
#   ./setup-fedora.sh --profile full           # Full deployment
#   ./setup-fedora.sh --profile standard       # Standard (Hunter + Specter)
#   ./setup-fedora.sh --profile lite           # Lightweight (recon only)
#   ./setup-fedora.sh --profile full --yes     # Non-interactive
#   ./setup-fedora.sh --dry-run --profile full # Show what would be installed
#
# IMPORTANT: This script adds/enables repos BEFORE installing packages.
#            Run as your normal user (uses sudo internally where needed).
#
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="/tmp/grimnir-setup-fedora-$(date +%Y%m%d_%H%M%S).log"
DRY_RUN=false
AUTO_YES=false
PROFILE="${GRIMNIR_PROFILE:-full}"
GRIMNIR_REPO="${GRIMNIR_REPO:-}"

# ============================================================================
# Logging
# ============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log_info()    { echo -e "${BLUE}[*]${NC} $*" | tee -a "$LOG_FILE"; }
log_ok()      { echo -e "${GREEN}[+]${NC} $*" | tee -a "$LOG_FILE"; }
log_warn()    { echo -e "${YELLOW}[!]${NC} $*" | tee -a "$LOG_FILE"; }
log_error()   { echo -e "${RED}[-]${NC} $*" | tee -a "$LOG_FILE"; }
log_section() { echo -e "\n${BOLD}${CYAN}=== $* ===${NC}\n" | tee -a "$LOG_FILE"; }

# ============================================================================
# Argument parsing
# ============================================================================

while [[ $# -gt 0 ]]; do
    case "$1" in
        --profile)   PROFILE="$2"; shift 2 ;;
        --yes|-y)    AUTO_YES=true; shift ;;
        --dry-run)   DRY_RUN=true; shift ;;
        --repo)      GRIMNIR_REPO="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: $0 [--profile lite|standard|full] [--yes] [--dry-run] [--repo URL]"
            echo ""
            echo "Profiles:"
            echo "  lite      — Recon & enumeration only (2-4GB)"
            echo "  standard  — Hunter + Specter (4-8GB)"
            echo "  full      — All agents including ARTEMIS (8GB+)"
            echo ""
            echo "Options:"
            echo "  --yes       Accept all defaults, non-interactive"
            echo "  --dry-run   Show what would be installed without installing"
            echo "  --repo URL  GitHub repo URL for GRIMNIR agent files"
            exit 0
            ;;
        *) log_error "Unknown option: $1"; exit 1 ;;
    esac
done

# ============================================================================
# Banner
# ============================================================================

echo -e "${BOLD}${CYAN}"
cat << 'BANNER'
  ____ ____  ___ __  __ _   _ ___ ____
 / ___|  _ \|_ _|  \/  | \ | |_ _|  _ \
| |  _| |_) || || |\/| |  \| || || |_) |
| |_| |  _ < | || |  | | |\  || ||  _ <
 \____|_| \_\___|_|  |_|_| \_|___|_| \_\

  Security Engagement Orchestrator
  Fedora Provisioning
BANNER
echo -e "${NC}"
echo "  Log: $LOG_FILE"
echo ""

# ============================================================================
# Pre-flight checks
# ============================================================================

if [ ! -f /etc/fedora-release ]; then
    log_error "This script is for Fedora. Detected OS:"
    cat /etc/os-release 2>/dev/null | head -3
    exit 1
fi

FEDORA_VERSION=$(rpm -E %fedora)
ARCH=$(uname -m)
TOTAL_RAM_MB=$(free -m | awk '/Mem:/{print $2}')
CPU_CORES=$(nproc)

log_info "Fedora $FEDORA_VERSION | Arch: $ARCH | Cores: $CPU_CORES | RAM: ${TOTAL_RAM_MB}MB"

# ============================================================================
# Profile definitions
# ============================================================================

case "$PROFILE" in
    lite)
        PROFILE_NAME="lite"
        PROFILE_DESC="Recon & enumeration only"
        AGENTS="hunter(recon)"
        INSTALL_WEB_TESTING=false
        INSTALL_AI_TESTING=false
        INSTALL_CREDENTIAL_ATTACKS=false
        NUCLEI_CONCURRENCY=15
        NMAP_TIMING=3
        MAX_PARALLEL_SCANS=2
        FFUF_THREADS=20
        ;;
    standard)
        PROFILE_NAME="standard"
        PROFILE_DESC="Network + API/web testing — Hunter and Specter"
        AGENTS="hunter specter"
        INSTALL_WEB_TESTING=true
        INSTALL_AI_TESTING=false
        INSTALL_CREDENTIAL_ATTACKS=true
        NUCLEI_CONCURRENCY=25
        NMAP_TIMING=4
        MAX_PARALLEL_SCANS=4
        FFUF_THREADS=40
        ;;
    full)
        PROFILE_NAME="full"
        PROFILE_DESC="Complete GRIMNIR deployment — all specialist agents"
        AGENTS="hunter specter artemis"
        INSTALL_WEB_TESTING=true
        INSTALL_AI_TESTING=true
        INSTALL_CREDENTIAL_ATTACKS=true
        NUCLEI_CONCURRENCY=50
        NMAP_TIMING=4
        MAX_PARALLEL_SCANS=8
        FFUF_THREADS=80
        ;;
    *)
        log_error "Unknown profile: $PROFILE (use lite, standard, or full)"
        exit 1
        ;;
esac

log_ok "Profile: ${BOLD}$PROFILE_NAME${NC} — $PROFILE_DESC"
log_info "Agents: $AGENTS"

# ============================================================================
# Dry run
# ============================================================================

if [ "$DRY_RUN" = true ]; then
    log_section "Dry Run — What Would Be Installed"
    echo "See full package lists below (scroll down)"
    echo "Profile: $PROFILE_NAME"
    echo "Agents: $AGENTS"
    echo ""
    echo "Phase 1: Repos (RPM Fusion, COPRs)"
    echo "Phase 2: DNF packages"
    echo "Phase 3: Go tools (19+)"
    echo "Phase 4: Python venv tools"
    echo "Phase 5: Git-cloned tools"
    echo "Phase 6: Gf patterns + SecLists"
    echo "Phase 7: Claude Code"
    echo "Phase 9: GRIMNIR agents + Caido Mode skill"
    echo ""
    echo "Omitted (manual): caido desktop, wpscan, exploitdb/searchsploit"
    echo "Omitted (later): zaproxy, beef-xss"
    echo "Omitted (excluded): metasploit"
    exit 0
fi

# ============================================================================
# Confirmation
# ============================================================================

if [ "$AUTO_YES" != true ]; then
    echo ""
    echo -e "${YELLOW}REMINDER:${NC} This script will enable additional repos (RPM Fusion, COPRs)"
    echo "          before installing packages. Review the repo list in the log."
    echo ""
    read -rp "Proceed with '$PROFILE' installation on Fedora $FEDORA_VERSION? [Y/n] " CONFIRM
    case "$CONFIRM" in
        [nN]*) log_info "Aborted."; exit 0 ;;
    esac
fi

START_TIME=$(date +%s)

# ============================================================================
# Phase 0: System prep & passwordless sudo
# ============================================================================

log_section "Phase 0 — System Prep"

log_info "Checking sudo access..."
if ! sudo -n true 2>/dev/null; then
    log_warn "Passwordless sudo not configured."
    log_info "To enable: sudo visudo → add: $USER ALL=(ALL) NOPASSWD: ALL"
    log_info "Continuing with password-prompted sudo..."
fi

mkdir -p "${GRIMNIR_WORKSPACE:-$HOME/workspace}"
mkdir -p "$HOME/tools"
mkdir -p "$HOME/go/bin"
mkdir -p "$HOME/bin"
mkdir -p "$HOME/.gf"
mkdir -p "$HOME/.config/grimnir"

# Ensure PATH in .bashrc
BASHRC="$HOME/.bashrc"
grep -q 'go/bin' "$BASHRC" 2>/dev/null || echo 'export PATH="$HOME/go/bin:$HOME/bin:$PATH"' >> "$BASHRC"
grep -q 'HOME/venv/bin' "$BASHRC" 2>/dev/null || echo '# Activate venv: source ~/venv/bin/activate' >> "$BASHRC"
export PATH="$HOME/go/bin:$HOME/bin:/usr/local/bin:$PATH"

log_ok "Directory structure created"

# ============================================================================
# Phase 1: Repository Setup
# ============================================================================

log_section "Phase 1 — Repository Setup"

log_info "IMPORTANT: Adding repos BEFORE any package installs"

# RPM Fusion (free + nonfree) — needed for some multimedia/network tools
if ! rpm -q rpmfusion-free-release &>/dev/null; then
    log_info "Enabling RPM Fusion (free)"
    sudo dnf install -y \
        "https://mirrors.rpmfusion.org/free/fedora/rpmfusion-free-release-${FEDORA_VERSION}.noarch.rpm" \
        2>>"$LOG_FILE"
    log_ok "RPM Fusion free enabled"
else
    log_ok "RPM Fusion free already enabled"
fi

if ! rpm -q rpmfusion-nonfree-release &>/dev/null; then
    log_info "Enabling RPM Fusion (nonfree)"
    sudo dnf install -y \
        "https://mirrors.rpmfusion.org/nonfree/fedora/rpmfusion-nonfree-release-${FEDORA_VERSION}.noarch.rpm" \
        2>>"$LOG_FILE"
    log_ok "RPM Fusion nonfree enabled"
else
    log_ok "RPM Fusion nonfree already enabled"
fi

# COPR repos for security tools
declare -A COPR_REPOS=(
    ["atim/nmap"]="nmap extras"
    ["sectools/security"]="security tool collection (if available)"
)

# Note: Many security tools are in Fedora "updates" already.
# Only add COPRs we actually need. Check each tool's availability first.
log_info "Checking COPR repos (only adding if needed)..."

# Enable updates-testing if user wants bleeding edge (skip by default)
# sudo dnf config-manager --set-enabled updates-testing

log_ok "Repository setup complete"

# ============================================================================
# Phase 2: DNF Packages
# ============================================================================

log_section "Phase 2 — DNF Packages"

# Base development tools
DEV_PACKAGES=(
    gcc
    gcc-c++
    make
    cmake
    automake
    autoconf
    libtool
    git
    git-lfs
    python3
    python3-devel
    python3-pip
    python3-virtualenv
    golang
    nodejs
    npm
    ruby
    ruby-devel
    rubygems
    libffi-devel
    openssl-devel
    libxml2-devel
    libxslt-devel
    libcurl-devel
    zlib-devel
    readline-devel
    sqlite-devel
    pcre-devel
    libpcap-devel
)

# Network / Infra tools
NETWORK_PACKAGES=(
    nmap
    nmap-ncat
    masscan
    hping3
    fping
    net-tools
    whois
    bind-utils
    tcpdump
    wireshark-cli
    traceroute
    ngrep
    socat
    netcat
    arpwatch
    nbtscan
    smbclient
    openssl
    stunnel
    proxychains-ng
)

# Web / API testing
WEB_PACKAGES=(
    curl
    wget
    jq
    httpie
    nikto
    sqlmap
    mitmproxy
)

# SAST / Secrets / Analysis
SAST_PACKAGES=(
    bandit
    ShellCheck
)

# Tools likely in Fedora updates repo (check availability)
FEDORA_SECURITY_PACKAGES=(
    subfinder
    ffuf
    gobuster
    feroxbuster
    hydra
    medusa
    john
    hashcat
    enum4linux
    dnsenum
    fierce
    theharvester
    sslscan
    sslyze
    whatweb
    wafw00f
    wfuzz
    commix
##    arjun
    wapiti
    dirb
    recon-ng
##    amass
    lynis
)

# Combine based on profile
ALL_DNF_PACKAGES=("${DEV_PACKAGES[@]}" "${NETWORK_PACKAGES[@]}" "${WEB_PACKAGES[@]}" "${SAST_PACKAGES[@]}")

if [ "$INSTALL_WEB_TESTING" = true ]; then
    ALL_DNF_PACKAGES+=("${FEDORA_SECURITY_PACKAGES[@]}")
fi

if [ "$INSTALL_CREDENTIAL_ATTACKS" = true ]; then
    ALL_DNF_PACKAGES+=(hydra medusa john hashcat)
fi

# Deduplicate
mapfile -t ALL_DNF_PACKAGES < <(printf '%s\n' "${ALL_DNF_PACKAGES[@]}" | sort -u)

log_info "Attempting to install ${#ALL_DNF_PACKAGES[@]} packages via dnf"
log_info "(Packages not in repos will be skipped — check log for failures)"

INSTALLED_COUNT=0
SKIPPED_COUNT=0
FAILED_PACKAGES=()

#for pkg in "${ALL_DNF_PACKAGES[@]}"; do
#    if rpm -q "$pkg" &>/dev/null; then
#        ((INSTALLED_COUNT++))
#        continue
#    fi
#
#    if sudo dnf install -y --skip-unavailable "$pkg" 2>>"$LOG_FILE" | tee -a "$LOG_FILE" | grep -q "Installed"; then
#        log_ok "  $pkg"
#       ((INSTALLED_COUNT++))
#    else
#        # Check if it was actually unavailable vs failed
#        if ! dnf info "$pkg" &>/dev/null 2>&1; then
#            FAILED_PACKAGES+=("$pkg")
#            ((SKIPPED_COUNT++))
#        else
#            # Package exists but install failed for another reason
#            sudo dnf install -y "$pkg" 2>>"$LOG_FILE" && {
#                log_ok "  $pkg (retry succeeded)"
#                ((INSTALLED_COUNT++))
#            } || {
#                FAILED_PACKAGES+=("$pkg")
#                ((SKIPPED_COUNT++))
#            }
#        fi
#    fi
#done
#
#log_ok "DNF: $INSTALLED_COUNT installed/present, $SKIPPED_COUNT not in repos"
#if [ ${#FAILED_PACKAGES[@]} -gt 0 ]; then
#    log_warn "Not found in dnf repos (will try other methods): ${FAILED_PACKAGES[*]}"
#    echo "${FAILED_PACKAGES[*]}" > /tmp/grimnir-dnf-missed.txt
#fi

# ============================================================================
# Phase 3: Go Tools
# ============================================================================

log_section "Phase 3 — Go Tools"

if ! command -v go &>/dev/null; then
    log_error "Go not found after dnf install — check golang package"
    exit 1
fi

export GOPATH="$HOME/go"
export PATH="$GOPATH/bin:$PATH"

GO_VERSION=$(go version | awk '{print $3}')
log_info "Go version: $GO_VERSION"

GO_TOOLS=(
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
    "github.com/projectdiscovery/alterx/cmd/alterx@latest"
    "github.com/projectdiscovery/asnmap/cmd/asnmap@latest"
    "github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest"
    "github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
    "github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest"
    "github.com/projectdiscovery/tlsx/cmd/tlsx@latest"
    "github.com/hahwul/dalfox/v2@latest"
    "github.com/tomnomnom/gf@latest"
    "github.com/tomnomnom/anew@latest"
    "github.com/tomnomnom/gron@latest"
    "github.com/tomnomnom/qsreplace@latest"
    "github.com/lc/gau/v2/cmd/gau@latest"
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/tomnomnom/httprobe@latest"
    "github.com/assetnote/kiterunner/cmd/kr@latest"
    "github.com/fullstorydev/grpcurl/cmd/grpcurl@latest"
)

GO_INSTALLED=0
GO_FAILED=0
#for tool in "${GO_TOOLS[@]}"; do
#    TOOL_NAME=$(basename "${tool%%@*}")
#    if command -v "$TOOL_NAME" &>/dev/null; then
#        log_ok "  $TOOL_NAME (already installed)"
#        ((GO_INSTALLED++))
#        continue
#    fi
#
#    log_info "  Installing $TOOL_NAME..."
#    if go install "$tool" 2>>"$LOG_FILE"; then
#        log_ok "  $TOOL_NAME"
#        ((GO_INSTALLED++))
#    else
#        log_warn "  $TOOL_NAME — failed (check $LOG_FILE)"
#        ((GO_FAILED++))
#    fi
#done
#
#log_ok "Go tools: $GO_INSTALLED installed, $GO_FAILED failed"

# ============================================================================
# Phase 4: Python Venv & Packages
# ============================================================================

log_section "Phase 4 — Python Virtual Environment"

if [ ! -d "$HOME/venv" ]; then
    log_info "Creating Python venv at ~/venv"
    python3 -m venv "$HOME/venv"
fi

source "$HOME/venv/bin/activate"
pip install --quiet --upgrade pip setuptools wheel 2>>"$LOG_FILE"

# Core security tools via pip
PIP_TOOLS=(
    uro
    paramspider
    semgrep
    waymore
    jshunter
    porch-pirate
    holehe
    sherlock-project
    apkleaks
    litellm
    playwright
)

# ARTEMIS-specific (full profile only)
if [ "$INSTALL_AI_TESTING" = true ]; then
    PIP_TOOLS+=(
        garak
        langchain
        langgraph
        openai
        ollama
    )
fi

PIP_INSTALLED=0
PIP_FAILED=0
for pkg in "${PIP_TOOLS[@]}"; do
    if pip show "$pkg" &>/dev/null 2>&1; then
        log_ok "  $pkg (already installed)"
        ((PIP_INSTALLED++))
        continue
    fi

    if pip install --quiet "$pkg" 2>>"$LOG_FILE"; then
        log_ok "  $pkg"
        ((PIP_INSTALLED++))
    else
        log_warn "  $pkg — failed (check $LOG_FILE)"
        ((PIP_FAILED++))
    fi
done

# Install playwright browsers if playwright was installed
if command -v playwright &>/dev/null 2>&1 || pip show playwright &>/dev/null 2>&1; then
    log_info "Installing Playwright browsers..."
    python -m playwright install chromium 2>>"$LOG_FILE" && log_ok "Playwright chromium" || log_warn "Playwright browsers failed"
fi

deactivate
log_ok "Python venv: $PIP_INSTALLED installed, $PIP_FAILED failed"

# ============================================================================
# Phase 5: Git-Cloned Tools
# ============================================================================

log_section "Phase 5 — Git-Cloned Tools (~/tools/)"

TOOLS_DIR="$HOME/tools"

declare -A GIT_TOOLS=(
    ["XSStrike"]="https://github.com/s0md3v/XSStrike.git"
    ["GraphQLmap"]="https://github.com/swisskyrepo/GraphQLmap.git"
    ["LinkFinder"]="https://github.com/GerbenJavado/LinkFinder.git"
    ["SecretFinder"]="https://github.com/m4ll0k/SecretFinder.git"
    ["paramspider"]="https://github.com/devanshbatham/ParamSpider.git"
    ["vulnx"]="https://github.com/anouarbensaad/vulnx.git"
    ["waymore"]="https://github.com/xnl-h4ck3r/waymore.git"
    ["porch-pirate"]="https://github.com/MandConsultingGroup/porch-pirate.git"
    ["Gf-Patterns"]="https://github.com/1ndianl33t/Gf-Patterns.git"
    ["graphw00f"]="https://github.com/dolevf/graphw00f.git"
    ["jwt_tool"]="https://github.com/ticarpi/jwt_tool.git"
)

GIT_INSTALLED=0
for tool_name in "${!GIT_TOOLS[@]}"; do
    tool_url="${GIT_TOOLS[$tool_name]}"
    tool_dir="$TOOLS_DIR/$tool_name"

    if [ -d "$tool_dir/.git" ]; then
        log_info "  $tool_name — updating"
        cd "$tool_dir" && git pull --ff-only 2>>"$LOG_FILE" && cd - >/dev/null
        log_ok "  $tool_name (updated)"
    else
        log_info "  Cloning $tool_name..."
        if git clone --depth 1 "$tool_url" "$tool_dir" 2>>"$LOG_FILE"; then
            log_ok "  $tool_name"
        else
            log_warn "  $tool_name — clone failed"
            continue
        fi
    fi
    ((GIT_INSTALLED++))

    # Try to install properly (make install, pip install, setup.py, etc.)
    cd "$tool_dir"

    if [ -f "Makefile" ] && grep -q "install" Makefile 2>/dev/null; then
        log_info "    Attempting make install..."
        sudo make install 2>>"$LOG_FILE" && log_ok "    make install succeeded" || log_info "    make install skipped (no target or failed)"
    elif [ -f "setup.py" ]; then
        log_info "    Attempting pip install..."
        source "$HOME/venv/bin/activate"
        pip install --quiet -e . 2>>"$LOG_FILE" && log_ok "    pip install -e . succeeded" || log_info "    pip install skipped"
        deactivate
    elif [ -f "requirements.txt" ]; then
        log_info "    Installing requirements..."
        source "$HOME/venv/bin/activate"
        pip install --quiet -r requirements.txt 2>>"$LOG_FILE" && log_ok "    requirements installed" || log_info "    requirements install failed"
        deactivate
    fi

    cd - >/dev/null
done

# Create wrapper scripts for git-cloned tools that don't install to PATH
# Only create wrappers as a FALLBACK — check if binary is already accessible first
log_info "Creating wrapper scripts for tools not in PATH..."

create_wrapper() {
    local cmd_name="$1"
    local exec_path="$2"
    local wrapper_path="/usr/local/bin/$cmd_name"

    # Skip if command already exists in PATH
    if command -v "$cmd_name" &>/dev/null; then
        log_ok "  $cmd_name already in PATH — no wrapper needed"
        return 0
    fi

    if [ -f "$exec_path" ]; then
        sudo tee "$wrapper_path" > /dev/null <<WRAPPER
#!/bin/bash
source "$HOME/venv/bin/activate" 2>/dev/null
exec python3 "$exec_path" "\$@"
WRAPPER
        sudo chmod +x "$wrapper_path"
        log_ok "  $cmd_name → $wrapper_path"
    else
        log_warn "  $cmd_name — target not found: $exec_path"
    fi
}

create_wrapper_direct() {
    local cmd_name="$1"
    local exec_path="$2"
    local wrapper_path="/usr/local/bin/$cmd_name"

    if command -v "$cmd_name" &>/dev/null; then
        log_ok "  $cmd_name already in PATH — no wrapper needed"
        return 0
    fi

    if [ -f "$exec_path" ]; then
        sudo tee "$wrapper_path" > /dev/null <<WRAPPER
#!/bin/bash
exec "$exec_path" "\$@"
WRAPPER
        sudo chmod +x "$wrapper_path"
        log_ok "  $cmd_name → $wrapper_path"
    fi
}

create_wrapper "xsstrike" "$TOOLS_DIR/XSStrike/xsstrike.py"
create_wrapper "graphqlmap" "$TOOLS_DIR/GraphQLmap/graphqlmap.py"
create_wrapper "linkfinder" "$TOOLS_DIR/LinkFinder/linkfinder.py"
create_wrapper "secretfinder" "$TOOLS_DIR/SecretFinder/SecretFinder.py"
create_wrapper "vulnx" "$TOOLS_DIR/vulnx/vulnx.py"
create_wrapper "graphw00f" "$TOOLS_DIR/graphw00f/main.py"
create_wrapper "jwt_tool" "$TOOLS_DIR/jwt_tool/jwt_tool.py"

log_ok "Git-cloned tools: $GIT_INSTALLED installed"

# ============================================================================
# Phase 6: Gf Patterns & SecLists
# ============================================================================

log_section "Phase 6 — Gf Patterns & Wordlists"

# Install gf patterns
GF_PATTERNS_DIR="$TOOLS_DIR/Gf-Patterns"
if [ -d "$GF_PATTERNS_DIR" ]; then
    log_info "Copying gf patterns to ~/.gf/"
    cp -n "$GF_PATTERNS_DIR"/*.json "$HOME/.gf/" 2>/dev/null
    PATTERN_COUNT=$(ls "$HOME/.gf/"*.json 2>/dev/null | wc -l)
    log_ok "$PATTERN_COUNT gf patterns installed"
fi

# SecLists
if [ ! -d "/usr/share/seclists" ] && [ ! -d "/opt/seclists" ]; then
    log_info "Installing SecLists (this takes a while on first run)..."
    if sudo dnf install -y seclists 2>>"$LOG_FILE"; then
        log_ok "SecLists installed via dnf"
    else
        log_info "SecLists not in repos — cloning from GitHub"
        sudo git clone --depth 1 https://github.com/danielmiessler/SecLists.git /opt/seclists 2>>"$LOG_FILE"
        sudo ln -sf /opt/seclists /usr/share/seclists 2>/dev/null
        log_ok "SecLists cloned to /opt/seclists"
    fi
else
    log_ok "SecLists already present"
fi

# ============================================================================
# Phase 7: Claude Code
# ============================================================================

log_section "Phase 7 — Claude Code"

if command -v claude &>/dev/null; then
    log_ok "Claude Code already installed: $(claude --version 2>/dev/null || echo 'version unknown')"
else
    log_info "Installing Claude Code..."
    if curl -fsSL https://claude.ai/install.sh | bash 2>>"$LOG_FILE"; then
        log_ok "Claude Code installed"
    else
        log_warn "Claude Code install failed — try manually: curl -fsSL https://claude.ai/install.sh | bash"
    fi
fi

# Install grimnir launcher
GRIMNIR_LAUNCHER="/usr/local/bin/grimnir"
if [ ! -f "$GRIMNIR_LAUNCHER" ]; then
    log_info "Creating grimnir launcher at $GRIMNIR_LAUNCHER"
    sudo tee "$GRIMNIR_LAUNCHER" > /dev/null <<'LAUNCHER'
#!/bin/bash
# Resolved at run time, not install time, so moving the checkout or the engagement
# workspace does not require reinstalling the launcher.
cd "${GRIMNIR_REPO_DIR:-$HOME/workspace/grimnir}" 2>/dev/null \
  || cd "${GRIMNIR_WORKSPACE:-$HOME/workspace}" 2>/dev/null
exec claude "$@"
LAUNCHER
    sudo chmod +x "$GRIMNIR_LAUNCHER"
    log_ok "grimnir launcher created"
fi

# ============================================================================
# Phase 8: Performance Tuning
# ============================================================================

log_section "Phase 8 — Performance Tuning"

# Tuning config
cat > "$HOME/.config/grimnir/tuning.conf" <<TUNING
# GRIMNIR Performance Tuning — auto-generated for Fedora
# Profile: $PROFILE_NAME
# Architecture: $ARCH
# RAM: ${TOTAL_RAM_MB}MB
# Generated: $(date -Iseconds)

NUCLEI_CONCURRENCY=$NUCLEI_CONCURRENCY
NMAP_TIMING=$NMAP_TIMING
MAX_PARALLEL_SCANS=$MAX_PARALLEL_SCANS
FFUF_THREADS=$FFUF_THREADS

NUCLEI_BULK_SIZE=$(( NUCLEI_CONCURRENCY / 5 ))
NUCLEI_TEMPLATE_THREADS=$(( NUCLEI_CONCURRENCY / 2 ))
TUNING
log_ok "Tuning config: ~/.config/grimnir/tuning.conf"

# File descriptor limits
CURRENT_ULIMIT=$(ulimit -n)
if [ "$CURRENT_ULIMIT" -lt 65535 ]; then
    log_info "Increasing file descriptor limit (current: $CURRENT_ULIMIT)"
    if ! grep -q 'grimnir-tuning' /etc/security/limits.conf 2>/dev/null; then
        sudo tee -a /etc/security/limits.conf > /dev/null <<LIMITS
# grimnir-tuning
* soft nofile 65535
* hard nofile 65535
LIMITS
        log_ok "File descriptor limits updated (effective on next login)"
    fi
fi

# SELinux note
if command -v getenforce &>/dev/null; then
    SELINUX_STATUS=$(getenforce 2>/dev/null || echo "Unknown")
    log_info "SELinux status: $SELINUX_STATUS"
    if [ "$SELINUX_STATUS" = "Enforcing" ]; then
        log_warn "SELinux is Enforcing. Some scanning tools may get blocked."
        log_warn "If you hit denials: sudo setenforce 0 (temporary) or configure audit2allow"
        log_warn "For permanent permissive: edit /etc/selinux/config → SELINUX=permissive"
    fi
fi

# Low-RAM swap setup
if [ "$TOTAL_RAM_MB" -lt 4096 ]; then
    log_info "Low-memory system — adjusting swappiness"
    sudo sysctl -w vm.swappiness=10 2>/dev/null
    if ! grep -q 'vm.swappiness=10' /etc/sysctl.conf 2>/dev/null; then
        echo "vm.swappiness=10" | sudo tee -a /etc/sysctl.conf > /dev/null
    fi

    if ! swapon --show | grep -q '/'; then
        log_info "Creating 2GB swap file..."
        sudo fallocate -l 2G /swapfile 2>/dev/null || sudo dd if=/dev/zero of=/swapfile bs=1M count=2048 2>/dev/null
        sudo chmod 600 /swapfile
        sudo mkswap /swapfile 2>/dev/null
        sudo swapon /swapfile 2>/dev/null
        grep -q '/swapfile' /etc/fstab 2>/dev/null || echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab > /dev/null
        log_ok "Swap file created"
    fi
fi

# ============================================================================
# Phase 9: GRIMNIR Agent Setup
# ============================================================================

log_section "Phase 9 — GRIMNIR Agent Config"

# The checkout location. $GRIMNIR_REPO is the clone URL, so the directory needs its
# own name; $GRIMNIR_WORKSPACE is the separate engagement-data root.
WORKSPACE_DIR="${GRIMNIR_REPO_DIR:-$HOME/workspace/grimnir}"

if [ -n "$GRIMNIR_REPO" ]; then
    if [ -d "$WORKSPACE_DIR/.git" ]; then
        cd "$WORKSPACE_DIR" && git pull --ff-only 2>>"$LOG_FILE" && cd - >/dev/null
        log_ok "Repository updated"
    else
        git clone "$GRIMNIR_REPO" "$WORKSPACE_DIR" 2>>"$LOG_FILE"
        log_ok "Repository cloned"
    fi
fi

# Create agent working directories
for agent in hunter specter artemis; do
    mkdir -p "$WORKSPACE_DIR/$agent" 2>/dev/null
done

# Engagement data root (per-engagement dirs are created by /engage, not here)
mkdir -p "${GRIMNIR_WORKSPACE:-$HOME/workspace}" 2>/dev/null

log_ok "Agent directories ready"

# Caido Mode skill (Claude Code <> Caido proxy integration)
CAIDO_SKILL_DIR="$WORKSPACE_DIR/.agents/skills/caido-mode"
if [ -f "$CAIDO_SKILL_DIR/package.json" ]; then
    log_info "Installing Caido Mode skill dependencies..."
    cd "$CAIDO_SKILL_DIR"
    if npm install --quiet 2>>"$LOG_FILE"; then
        log_ok "Caido Mode skill dependencies installed"
    else
        log_warn "Caido Mode npm install failed — check $LOG_FILE"
    fi
    cd - >/dev/null

    # Ensure symlink exists
    SKILL_LINK="$WORKSPACE_DIR/.claude/skills/caido-mode"
    if [ ! -L "$SKILL_LINK" ]; then
        mkdir -p "$(dirname "$SKILL_LINK")"
        ln -sf "../../.agents/skills/caido-mode" "$SKILL_LINK"
        log_ok "Caido Mode symlink created"
    else
        log_ok "Caido Mode symlink already exists"
    fi
else
    log_info "Caido Mode skill not found in repo — skipping"
fi

# ============================================================================
# Summary
# ============================================================================

END_TIME=$(date +%s)
ELAPSED=$(( END_TIME - START_TIME ))

log_section "Setup Complete"

echo -e "${BOLD}Profile:${NC}       $PROFILE_NAME"
echo -e "${BOLD}Agents:${NC}        $AGENTS"
echo -e "${BOLD}Fedora:${NC}        $FEDORA_VERSION"
echo -e "${BOLD}Architecture:${NC}  $ARCH"
echo -e "${BOLD}RAM:${NC}           ${TOTAL_RAM_MB}MB"
echo -e "${BOLD}Duration:${NC}      ${ELAPSED}s"
echo -e "${BOLD}Log:${NC}           $LOG_FILE"
echo ""

if [ -f /tmp/grimnir-dnf-missed.txt ]; then
    echo -e "${YELLOW}Packages not found in dnf repos:${NC}"
    echo "  $(cat /tmp/grimnir-dnf-missed.txt)"
    echo "  These may need: go install, pip install, or manual setup"
    echo ""
fi

echo -e "${BOLD}Manual installs needed:${NC}"
echo "  - caido desktop: Download from https://caido.io/download"
echo "  - caido PAT:     Settings > Developer > Personal Access Tokens (for Caido Mode skill)"
echo "  - wpscan:        gem install wpscan (may need ruby-devel)"
echo "  - exploitdb:     git clone https://gitlab.com/exploit-database/exploitdb.git ~/tools/exploitdb"
echo "  - searchsploit:  symlink from exploitdb/searchsploit to ~/bin/"
echo ""
echo -e "${BOLD}Deferred (install when needed):${NC}"
echo "  - zaproxy:       flatpak install flathub org.zaproxy.ZAP"
echo "  - beef-xss:      https://github.com/beefproject/beef (Ruby + bundler)"
echo ""

echo -e "${BOLD}SELinux:${NC}"
if command -v getenforce &>/dev/null && [ "$(getenforce 2>/dev/null)" = "Enforcing" ]; then
    echo "  Currently Enforcing — watch for denials during scans"
    echo "  Quick fix: sudo setenforce 0"
    echo "  Permanent: edit /etc/selinux/config"
else
    echo "  Not enforcing — no action needed"
fi
echo ""

echo -e "Next steps:"
echo "  1. Source your profile:  source ~/.bashrc"
echo "  2. Activate venv:        source ~/venv/bin/activate"
echo "  3. Verify key tools:     nuclei -version && httpx -version && ffuf -version"
echo "  4. Start grimnir:        grimnir"
echo ""
log_ok "GRIMNIR Fedora provisioning complete."
