#!/bin/bash
# ClaudeOS Security Watchdog
# Runs via cron every 15 minutes
# Auto-bans brute force IPs

LOG="/opt/claudeos/logs/security.log"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
BAN_THRESHOLD=10

log() {
    echo "[$TIMESTAMP] [$1] [security] $2" >> "$LOG"
}

# Check for brute force SSH attempts
if [ -f /var/log/auth.log ]; then
    # Find IPs with more than threshold failed attempts in last 15 min
    ATTACKERS=$(grep "Failed password" /var/log/auth.log | \
        grep "$(date -d '15 minutes ago' '+%b %e %H' 2>/dev/null || date '+%b %e %H')" | \
        awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | \
        awk -v threshold=$BAN_THRESHOLD '$1 > threshold {print $2}')

    for IP in $ATTACKERS; do
        # Check if already banned
        if ! ufw status | grep -q "$IP"; then
            ufw deny from "$IP" 2>/dev/null
            log "ALERT" "Banned IP $IP — exceeded $BAN_THRESHOLD failed login attempts"
        fi
    done

    # Count total failed attempts
    FAIL_COUNT=$(grep "Failed password" /var/log/auth.log | wc -l)
    log "INFO" "Total failed login attempts: $FAIL_COUNT"
fi

# Check firewall status
if command -v ufw &>/dev/null; then
    UFW_STATUS=$(ufw status | head -1)
    if echo "$UFW_STATUS" | grep -q "inactive"; then
        log "CRITICAL" "Firewall is INACTIVE!"
    else
        log "INFO" "Firewall: active"
    fi
fi

# Check for unexpected listening ports
EXPECTED_PORTS="22 80 443 3306"
ACTUAL_PORTS=$(ss -tlnp | awk 'NR>1{print $4}' | grep -oP ':\K[0-9]+' | sort -u)

for PORT in $ACTUAL_PORTS; do
    if ! echo "$EXPECTED_PORTS" | grep -qw "$PORT"; then
        PROC=$(ss -tlnp | grep ":${PORT}" | awk '{print $NF}')
        log "WARNING" "Unexpected port $PORT open — process: $PROC"
    fi
done

# Check for root logins
if [ -f /var/log/auth.log ]; then
    ROOT_LOGINS=$(grep "Accepted.*root" /var/log/auth.log 2>/dev/null | tail -5)
    if [ -n "$ROOT_LOGINS" ]; then
        log "WARNING" "Root login detected: $(echo "$ROOT_LOGINS" | tail -1)"
    fi
fi
