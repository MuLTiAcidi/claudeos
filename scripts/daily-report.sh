#!/bin/bash
# ClaudeOS Daily Report Generator
# Runs via cron daily at 7 AM

REPORT_DIR="/opt/claudeos/logs"
DATE=$(date '+%Y-%m-%d')
REPORT="$REPORT_DIR/daily-report-$DATE.md"

# Determine overall health
DISK_PCT=$(df / | awk 'NR==2{print $5}' | tr -d '%')
RAM_PCT=$(free | awk '/Mem:/{printf "%.0f", $3/$2*100}')
LOAD=$(cat /proc/loadavg | awk '{print $1}')
CORES=$(nproc)
CPU_PCT=$(echo "$LOAD $CORES" | awk '{printf "%.0f", ($1/$2)*100}')

if [ "$DISK_PCT" -gt 90 ] || [ "$RAM_PCT" -gt 95 ] || [ "$CPU_PCT" -gt 95 ]; then
    HEALTH="CRITICAL"
elif [ "$DISK_PCT" -gt 80 ] || [ "$RAM_PCT" -gt 85 ] || [ "$CPU_PCT" -gt 80 ]; then
    HEALTH="WARNING"
else
    HEALTH="OK"
fi

cat > "$REPORT" << EOF
# ClaudeOS Daily Report — $DATE

## System Health: $HEALTH

| Metric | Value | Status |
|--------|-------|--------|
| CPU | ${CPU_PCT}% (load: $LOAD) | $([ "$CPU_PCT" -gt 80 ] && echo "WARNING" || echo "OK") |
| RAM | ${RAM_PCT}% | $([ "$RAM_PCT" -gt 85 ] && echo "WARNING" || echo "OK") |
| Disk | ${DISK_PCT}% | $([ "$DISK_PCT" -gt 80 ] && echo "WARNING" || echo "OK") |
| Uptime | $(uptime -p) | |

## Services
$(systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | awk '{print "- " $1 ": RUNNING"}' | head -15)

$(systemctl list-units --type=service --state=failed --no-pager --no-legend 2>/dev/null | awk '{print "- " $1 ": FAILED"}')

## Security
- Failed SSH logins today: $(grep "Failed password" /var/log/auth.log 2>/dev/null | grep "$DATE" | wc -l)
- IPs banned: $(ufw status 2>/dev/null | grep DENY | wc -l)
- Firewall: $(ufw status 2>/dev/null | head -1 | awk '{print $2}')

## Disk Usage
$(df -h | awk 'NR==1 || /^\/dev/' | head -5)

## Recent Alerts
$(grep -E "\[WARNING\]|\[CRITICAL\]|\[ALERT\]" /opt/claudeos/logs/health.log 2>/dev/null | tail -10)
$(grep -E "\[WARNING\]|\[CRITICAL\]|\[ALERT\]" /opt/claudeos/logs/security.log 2>/dev/null | tail -10)

## Backup Status
$(tail -5 /opt/claudeos/logs/backup.log 2>/dev/null)

---
*Generated automatically by ClaudeOS at $(date '+%H:%M')*
EOF

echo "Daily report generated: $REPORT"
