#!/bin/bash
# Module: Performance Tuning — adjust system settings for profile

module_performance_tuning() {
    log_section "Performance Tuning"

    ARCH=$(uname -m)
    TOTAL_RAM_MB=$(free -m | awk '/Mem:/{print $2}')

    # Create GRIMNIR config with tuning values
    local CONFIG_DIR="$HOME/.config/grimnir"
    mkdir -p "$CONFIG_DIR"

    cat > "$CONFIG_DIR/tuning.conf" <<TUNING
# GRIMNIR Performance Tuning — auto-generated
# Profile: $PROFILE_NAME
# Architecture: $ARCH
# RAM: ${TOTAL_RAM_MB}MB
# Generated: $(date -Iseconds)

NUCLEI_CONCURRENCY=$NUCLEI_CONCURRENCY
NMAP_TIMING=$NMAP_TIMING
MAX_PARALLEL_SCANS=$MAX_PARALLEL_SCANS
FFUF_THREADS=$FFUF_THREADS

# Computed values
NUCLEI_BULK_SIZE=$(( NUCLEI_CONCURRENCY / 5 ))
NUCLEI_TEMPLATE_THREADS=$(( NUCLEI_CONCURRENCY / 2 ))
TUNING

    log_ok "Tuning config written to $CONFIG_DIR/tuning.conf"

    # Adjust ulimits for scanning (file descriptors)
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

    # Disable swap thrashing on low-memory systems
    if [ "$TOTAL_RAM_MB" -lt 4096 ]; then
        log_info "Low-memory system detected — adjusting swappiness"
        sudo sysctl -w vm.swappiness=10 2>/dev/null
        if ! grep -q 'vm.swappiness=10' /etc/sysctl.conf 2>/dev/null; then
            echo "vm.swappiness=10" | sudo tee -a /etc/sysctl.conf > /dev/null
        fi

        # Create swap file if none exists (important for Pi)
        if ! swapon --show | grep -q '/'; then
            log_info "No swap detected — creating 2GB swap file"
            sudo fallocate -l 2G /swapfile 2>/dev/null || sudo dd if=/dev/zero of=/swapfile bs=1M count=2048 2>/dev/null
            sudo chmod 600 /swapfile
            sudo mkswap /swapfile 2>/dev/null
            sudo swapon /swapfile 2>/dev/null
            if ! grep -q '/swapfile' /etc/fstab 2>/dev/null; then
                echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab > /dev/null
            fi
            log_ok "Swap file created"
        fi
    fi

    log_ok "Performance tuning complete"
}
