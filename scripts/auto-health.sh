#!/bin/bash
# ClaudeOS Auto-Health Check
# Runs via cron every 5 minutes
# Logs to /opt/claudeos/logs/health.log

LOG="/opt/claudeos/logs/health.log"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

log() {
    echo "[$TIMESTAMP] [$1] [health] $2" >> "$LOG"
}

# CPU Check
LOAD=$(cat /proc/loadavg | awk '{print $1}')
CORES=$(nproc)
CPU_PCT=$(echo "$LOAD $CORES" | awk '{printf "%.0f", ($1/$2)*100}')

if [ "$CPU_PCT" -gt 95 ]; then
    log "CRITICAL" "CPU at ${CPU_PCT}% (load: $LOAD)"
elif [ "$CPU_PCT" -gt 80 ]; then
    log "WARNING" "CPU at ${CPU_PCT}% (load: $LOAD)"
else
    log "INFO" "CPU: ${CPU_PCT}%"
fi

# RAM Check
RAM_TOTAL=$(free -m | awk '/Mem:/{print $2}')
RAM_USED=$(free -m | awk '/Mem:/{print $3}')
RAM_PCT=$((RAM_USED * 100 / RAM_TOTAL))

if [ "$RAM_PCT" -gt 95 ]; then
    log "CRITICAL" "RAM at ${RAM_PCT}% (${RAM_USED}MB/${RAM_TOTAL}MB)"
    # Auto-fix: find top memory consumer and log it
    TOP_PROC=$(ps aux --sort=-%mem | awk 'NR==2{print $11, $4"%"}')
    log "INFO" "Top memory consumer: $TOP_PROC"
elif [ "$RAM_PCT" -gt 90 ]; then
    log "WARNING" "RAM at ${RAM_PCT}%"
else
    log "INFO" "RAM: ${RAM_PCT}%"
fi

# Disk Check
DISK_PCT=$(df / | awk 'NR==2{print $5}' | tr -d '%')

if [ "$DISK_PCT" -gt 95 ]; then
    log "CRITICAL" "Disk at ${DISK_PCT}% — emergency cleanup"
    apt-get autoremove -y -qq 2>/dev/null
    apt-get clean -qq 2>/dev/null
    journalctl --vacuum-time=3d 2>/dev/null
    find /tmp -type f -atime +2 -delete 2>/dev/null
    find /var/log -name "*.gz" -mtime +7 -delete 2>/dev/null
    NEW_DISK=$(df / | awk 'NR==2{print $5}' | tr -d '%')
    log "INFO" "Cleanup done — disk now at ${NEW_DISK}%"
elif [ "$DISK_PCT" -gt 85 ]; then
    log "WARNING" "Disk at ${DISK_PCT}% — light cleanup"
    apt-get autoremove -y -qq 2>/dev/null
    apt-get clean -qq 2>/dev/null
    NEW_DISK=$(df / | awk 'NR==2{print $5}' | tr -d '%')
    log "INFO" "Cleanup done — disk now at ${NEW_DISK}%"
else
    log "INFO" "Disk: ${DISK_PCT}%"
fi

# Service Check — restart failed critical services
for SVC in nginx mysql mariadb postgresql ssh; do
    if systemctl is-active --quiet "$SVC" 2>/dev/null; then
        : # running, fine
    elif systemctl list-unit-files | grep -q "^${SVC}"; then
        log "WARNING" "Service $SVC is down — attempting restart"
        systemctl restart "$SVC" 2>/dev/null
        if systemctl is-active --quiet "$SVC" 2>/dev/null; then
            log "INFO" "Service $SVC restarted successfully"
        else
            log "CRITICAL" "Service $SVC failed to restart!"
        fi
    fi
done
