#!/bin/bash
# ============================================================================
# GRIMNIR Setup — Unified provisioning for all deployment targets
# ============================================================================
#
# Usage:
#   ./setup.sh                          # Interactive — prompts for profile
#   ./setup.sh --profile full           # Full deployment (workstation)
#   ./setup.sh --profile standard       # Standard (Pi 5 8GB, VPS)
#   ./setup.sh --profile lite           # Lightweight (Pi, drop box)
#   ./setup.sh --profile full --yes     # Non-interactive, accept all defaults
#   ./setup.sh --dry-run --profile lite # Show what would be installed
#
# Environment variables:
#   GRIMNIR_REPO    — GitHub repo URL for agent files (optional)
#   GRIMNIR_PROFILE — Profile name (alternative to --profile)
#
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="/tmp/grimnir-setup-$(date +%Y%m%d_%H%M%S).log"
DRY_RUN=false
AUTO_YES=false
PROFILE="${GRIMNIR_PROFILE:-}"

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
            echo "  lite      — Recon & enumeration only (Pi, drop box, 2-4GB)"
            echo "  standard  — Hunter + Specter (Pi 5, VPS, 4-8GB)"
            echo "  full      — All agents + Metasploit (workstation, 8GB+)"
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
  Provisioning System
BANNER
echo -e "${NC}"
echo "  Log: $LOG_FILE"
echo ""

# ============================================================================
# System detection
# ============================================================================

ARCH=$(uname -m)
OS_ID=$(grep -oP '(?<=^ID=).+' /etc/os-release 2>/dev/null | tr -d '"')
OS_VERSION=$(grep -oP '(?<=^VERSION_ID=).+' /etc/os-release 2>/dev/null | tr -d '"')
TOTAL_RAM_MB=$(free -m | awk '/Mem:/{print $2}')
CPU_CORES=$(nproc)
IS_PI=false
IS_ARM=false

case "$ARCH" in
    aarch64|armv7l|armv6l)
        IS_ARM=true
        # Check if it's a Raspberry Pi
        if grep -qi "raspberry\|bcm2" /proc/cpuinfo 2>/dev/null || grep -qi "raspberry" /proc/device-tree/model 2>/dev/null; then
            IS_PI=true
            PI_MODEL=$(tr -d '\0' < /proc/device-tree/model 2>/dev/null || echo "Unknown Pi")
        fi
        ;;
esac

log_info "System: $OS_ID $OS_VERSION | Arch: $ARCH | Cores: $CPU_CORES | RAM: ${TOTAL_RAM_MB}MB"
if $IS_PI; then
    log_info "Raspberry Pi detected: $PI_MODEL"
fi

# ============================================================================
# Profile selection
# ============================================================================

if [ -z "$PROFILE" ]; then
    echo "Select deployment profile:"
    echo ""
    echo "  ${BOLD}1) lite${NC}      — Recon & enumeration only"
    echo "                 Best for: Pi (2-4GB), drop box, minimal VPS"
    echo "                 Agents: Hunter (recon only)"
    echo ""
    echo "  ${BOLD}2) standard${NC}  — Network + API/web testing"
    echo "                 Best for: Pi 5 (4-8GB), VPS, secondary workstation"
    echo "                 Agents: Hunter, Specter"
    echo ""
    echo "  ${BOLD}3) full${NC}      — Complete GRIMNIR deployment"
    echo "                 Best for: Kali workstation (8GB+), beefy VPS"
    echo "                 Agents: Hunter, Specter, ARTEMIS, Nimbus, Nomad + Metasploit"
    echo ""

    # Auto-suggest based on system
    SUGGESTED="full"
    if [ "$TOTAL_RAM_MB" -lt 4096 ]; then
        SUGGESTED="lite"
    elif [ "$TOTAL_RAM_MB" -lt 8192 ]; then
        SUGGESTED="standard"
    fi

    read -rp "Profile [1/2/3] (suggested: $SUGGESTED): " CHOICE
    case "$CHOICE" in
        1|lite)     PROFILE="lite" ;;
        2|standard) PROFILE="standard" ;;
        3|full)     PROFILE="full" ;;
        "")         PROFILE="$SUGGESTED" ;;
        *)          log_error "Invalid choice: $CHOICE"; exit 1 ;;
    esac
fi

# Load profile
PROFILE_FILE="$SCRIPT_DIR/profiles/${PROFILE}.conf"
if [ ! -f "$PROFILE_FILE" ]; then
    log_error "Profile not found: $PROFILE_FILE"
    log_info "Available profiles: $(ls "$SCRIPT_DIR/profiles/" | sed 's/\.conf//g' | tr '\n' ' ')"
    exit 1
fi

source "$PROFILE_FILE"
log_ok "Profile loaded: ${BOLD}$PROFILE_NAME${NC} — $PROFILE_DESC"
log_info "Agents: $AGENTS"

# ============================================================================
# Confirmation
# ============================================================================

if [ "$DRY_RUN" = true ]; then
    log_section "Dry Run — What Would Be Installed"
    echo "APT packages (${#APT_PACKAGES[@]}): ${APT_PACKAGES[*]}"
    echo ""
    echo "Go tools (${#GO_TOOLS[@]}):"
    for t in "${GO_TOOLS[@]}"; do echo "  - $(basename "${t%%@*}")"; done
    echo ""
    echo "Python packages (${#PIP_PACKAGES[@]}): ${PIP_PACKAGES[*]}"
    echo ""
    echo "Metasploit: $INSTALL_METASPLOIT"
    echo "PostgreSQL: $INSTALL_POSTGRESQL"
    echo ""
    echo "Optional: ${OPTIONAL_TOOLS[*]:-none}"
    exit 0
fi

if [ "$AUTO_YES" != true ]; then
    echo ""
    read -rp "Proceed with '$PROFILE' installation? [Y/n] " CONFIRM
    case "$CONFIRM" in
        [nN]*) log_info "Aborted."; exit 0 ;;
    esac
fi

# ============================================================================
# Run modules
# ============================================================================

START_TIME=$(date +%s)

# Source all modules
for module in "$SCRIPT_DIR"/modules/*.sh; do
    source "$module"
done

# Execute in order
module_system_setup
module_apt_install
module_go_install
module_pip_install
module_metasploit_install
module_cloud_install
module_mobile_install
module_agents_setup
module_performance_tuning

# ============================================================================
# Optional tools prompt
# ============================================================================

if [ ${#OPTIONAL_TOOLS[@]} -gt 0 ] && [ "$AUTO_YES" != true ]; then
    log_section "Optional Tools"
    for tool in "${OPTIONAL_TOOLS[@]}"; do
        read -rp "Install $tool? [y/N] " OPT_CONFIRM
        case "$OPT_CONFIRM" in
            [yY]*)
                case "$tool" in
                    metasploit)
                        INSTALL_METASPLOIT=true
                        module_metasploit_install
                        ;;
                    postgresql)
                        sudo apt-get install -y -qq postgresql postgresql-client 2>/dev/null
                        log_ok "$tool installed"
                        ;;
                    nessus)
                        log_info "Nessus requires manual download from tenable.com"
                        log_info "Visit: https://www.tenable.com/products/nessus/nessus-essentials"
                        ;;
                    *)
                        sudo apt-get install -y -qq "$tool" 2>/dev/null && log_ok "$tool installed" || log_warn "$tool — manual install required"
                        ;;
                esac
                ;;
        esac
    done
fi

# ============================================================================
# Summary
# ============================================================================

END_TIME=$(date +%s)
ELAPSED=$(( END_TIME - START_TIME ))

log_section "Setup Complete"

echo -e "${BOLD}Profile:${NC}       $PROFILE_NAME"
echo -e "${BOLD}Agents:${NC}        $AGENTS"
echo -e "${BOLD}Architecture:${NC}  $ARCH"
echo -e "${BOLD}RAM:${NC}           ${TOTAL_RAM_MB}MB"
echo -e "${BOLD}Duration:${NC}      ${ELAPSED}s"
echo -e "${BOLD}Log:${NC}           $LOG_FILE"
echo ""

if $IS_PI; then
    echo -e "${YELLOW}Pi-specific notes:${NC}"
    echo "  - Use ethernet for scanning (WiFi has throughput limits)"
    echo "  - Monitor temperature: vcgencmd measure_temp"
    echo "  - Consider a heatsink/fan for sustained scanning"
    echo ""
fi

echo -e "Next steps:"
echo "  1. Source your profile:  source ~/.bashrc"
echo "  2. Start an engagement:  cd ${GRIMNIR_REPO_DIR:-~/workspace/grimnir} && /engage <target>"
echo ""
log_ok "GRIMNIR is ready."
