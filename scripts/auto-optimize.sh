#!/bin/bash
# ClaudeOS Auto-Optimizer
# Automatically tunes system based on actual usage patterns
# Runs weekly via cron

CLAUDEOS_DIR="/opt/claudeos"
LOG="$CLAUDEOS_DIR/logs/actions.log"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

log() {
    echo "[$TIMESTAMP] [$1] [optimizer] $2" >> "$LOG"
}

RAM_MB=$(free -m | awk '/Mem:/{print $2}')

# MySQL/MariaDB auto-tuning
if command -v mysqld &>/dev/null; then
    MYCNF="/etc/mysql/conf.d/claudeos-tuning.cnf"

    # Calculate optimal settings based on RAM
    BUFFER_POOL=$((RAM_MB * 50 / 100))M  # 50% of RAM for dedicated DB, 25% for mixed
    if systemctl is-active --quiet nginx 2>/dev/null; then
        BUFFER_POOL=$((RAM_MB * 25 / 100))M  # Mixed workload
    fi

    MAX_CONNECTIONS=150
    if [ "$RAM_MB" -lt 2048 ]; then MAX_CONNECTIONS=50; fi
    if [ "$RAM_MB" -gt 8192 ]; then MAX_CONNECTIONS=300; fi

    cat > "$MYCNF" << MYEOF
[mysqld]
# ClaudeOS Auto-Tuned ($(date +%Y-%m-%d))
# Based on ${RAM_MB}MB RAM
innodb_buffer_pool_size = $BUFFER_POOL
max_connections = $MAX_CONNECTIONS
innodb_log_file_size = 256M
innodb_flush_method = O_DIRECT
innodb_flush_log_at_trx_commit = 2
query_cache_type = 0
skip_name_resolve = 1
MYEOF

    log "INFO" "MySQL tuned: buffer_pool=$BUFFER_POOL, max_connections=$MAX_CONNECTIONS"
fi

# PHP-FPM auto-tuning
for PHP_FPM in /etc/php/*/fpm/pool.d/www.conf; do
    if [ -f "$PHP_FPM" ]; then
        # Calculate max children based on RAM and average PHP process size (~30MB)
        PHP_MAX=$((RAM_MB / 30 / 3))  # Use 1/3 of RAM for PHP
        if [ "$PHP_MAX" -lt 5 ]; then PHP_MAX=5; fi
        if [ "$PHP_MAX" -gt 100 ]; then PHP_MAX=100; fi

        sed -i "s/^pm.max_children.*/pm.max_children = $PHP_MAX/" "$PHP_FPM"
        sed -i "s/^pm.start_servers.*/pm.start_servers = $((PHP_MAX / 4))/" "$PHP_FPM"
        sed -i "s/^pm.min_spare_servers.*/pm.min_spare_servers = $((PHP_MAX / 4))/" "$PHP_FPM"
        sed -i "s/^pm.max_spare_servers.*/pm.max_spare_servers = $((PHP_MAX / 2))/" "$PHP_FPM"

        log "INFO" "PHP-FPM tuned: max_children=$PHP_MAX"
    fi
done

# Nginx auto-tuning
if [ -f /etc/nginx/nginx.conf ]; then
    CORES=$(nproc)
    WORKERS=$CORES
    CONNECTIONS=$((CORES * 1024))

    sed -i "s/worker_processes.*/worker_processes $WORKERS;/" /etc/nginx/nginx.conf

    log "INFO" "Nginx tuned: workers=$WORKERS"
fi

# Sysctl tuning based on role
if [ "$RAM_MB" -gt 4096 ]; then
    cat > /etc/sysctl.d/99-claudeos-performance.conf << SYSEOF
# ClaudeOS Performance Tuning ($(date +%Y-%m-%d))
vm.swappiness = 10
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_keepalive_time = 300
fs.file-max = 2097152
SYSEOF
    sysctl -p /etc/sysctl.d/99-claudeos-performance.conf 2>/dev/null
    log "INFO" "Sysctl performance tuning applied"
fi

# Clean up
apt-get autoremove -y -qq 2>/dev/null
journalctl --vacuum-time=7d 2>/dev/null

log "INFO" "Auto-optimization complete"
echo "Auto-optimization complete"
