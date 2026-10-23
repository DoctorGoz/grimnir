#!/bin/bash
# Module: Cloud Tools — install Nimbus (cloud) testing tooling.
# Gated on INSTALL_CLOUD_TESTING (set in the profile). Best-effort: cloud
# provider CLIs vary by distro, so failures are warnings, not fatal.

module_cloud_install() {
    if [ "${INSTALL_CLOUD_TESTING:-false}" != true ]; then
        return 0
    fi
    log_section "Cloud Tools (Nimbus)"

    # Provider CLIs
    if ! command -v aws &>/dev/null; then
        log_info "  Installing aws-cli..."
        pipx install awscli 2>/dev/null || pip install --user awscli 2>/dev/null \
            || log_warn "  aws-cli — install manually (https://aws.amazon.com/cli/)"
    else log_ok "  aws-cli (present)"; fi

    command -v az &>/dev/null && log_ok "  az-cli (present)" \
        || log_warn "  az-cli not found — install via Microsoft script (https://aka.ms/InstallAzureCli)"
    command -v gcloud &>/dev/null && log_ok "  gcloud (present)" \
        || log_warn "  gcloud not found — install via Google SDK (https://cloud.google.com/sdk/docs/install)"

    # Python-based assessment tools (best-effort)
    local PY_CLOUD=(scoutsuite prowler cloudsplaining pacu)
    for pkg in "${PY_CLOUD[@]}"; do
        if pipx install "$pkg" 2>/dev/null || pip install --user "$pkg" 2>/dev/null; then
            log_ok "  $pkg"
        else
            log_warn "  $pkg — failed (pip/pipx)"
        fi
    done

    # Trivy (container/image/fs scanner)
    if ! command -v trivy &>/dev/null; then
        log_info "  Installing trivy..."
        sudo apt-get install -y -qq trivy 2>/dev/null \
            || log_warn "  trivy — install manually (https://aquasecurity.github.io/trivy/)"
    else log_ok "  trivy (present)"; fi

    # Kubernetes
    command -v kubectl &>/dev/null && log_ok "  kubectl (present)" \
        || log_warn "  kubectl not found — install for Kubernetes testing"

    log_ok "Cloud tools: best-effort install complete (verify with: aws --version, scout --help, prowler -v)"
}
