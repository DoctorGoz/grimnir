#!/bin/bash
# Module: Mobile Tools — install Nomad (mobile) testing tooling.
# Gated on INSTALL_MOBILE_TESTING (set in the profile). Best-effort.

module_mobile_install() {
    if [ "${INSTALL_MOBILE_TESTING:-false}" != true ]; then
        return 0
    fi
    log_section "Mobile Tools (Nomad)"

    # Android platform tools (adb) + apktool
    command -v adb &>/dev/null && log_ok "  adb (present)" \
        || { log_info "  installing android platform-tools..."; sudo apt-get install -y -qq adb 2>/dev/null || log_warn "  adb — install android platform-tools manually"; }
    command -v apktool &>/dev/null && log_ok "  apktool (present)" \
        || { sudo apt-get install -y -qq apktool 2>/dev/null && log_ok "  apktool" || log_warn "  apktool — install manually"; }

    # jadx (decompiler) — operator may already have it at ~/tools/jadx
    if [ -x "$HOME/tools/jadx/bin/jadx" ] || command -v jadx &>/dev/null; then
        log_ok "  jadx (present)"
    else
        log_warn "  jadx not found — install to ~/tools/jadx (see reference-jadx-install)"
    fi

    # Frida + objection (pip/pipx)
    for pkg in frida-tools objection; do
        if pipx install "$pkg" 2>/dev/null || pip install --user "$pkg" 2>/dev/null; then
            log_ok "  $pkg"
        else
            log_warn "  $pkg — failed (pip/pipx)"
        fi
    done

    # MobSF (optional, heavy — note only)
    log_info "  MobSF: optional, run via Docker when needed (owasp/mobsf)"
    # scrcpy for device viewing
    command -v scrcpy &>/dev/null && log_ok "  scrcpy (present)" \
        || { sudo apt-get install -y -qq scrcpy 2>/dev/null && log_ok "  scrcpy" || log_warn "  scrcpy — optional, install manually"; }

    log_ok "Mobile tools: best-effort install complete (verify: adb version, frida --version, objection version)"
}
