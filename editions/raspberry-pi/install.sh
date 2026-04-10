#!/bin/bash
# Install ClaudeOS Raspberry Pi Edition
# Optimized for ARM and low resources

set -e

if [ "$EUID" -ne 0 ]; then
    echo "Run as root: sudo bash install.sh"
    exit 1
fi

CLAUDEOS_DIR="/opt/claudeos"

echo "Installing ClaudeOS Pi Edition..."

# Optimize for SD card (reduce writes)
cat > /etc/sysctl.d/99-claudeos-pi.conf << 'EOF'
vm.swappiness = 1
vm.dirty_ratio = 10
vm.dirty_background_ratio = 5
EOF
sysctl -p /etc/sysctl.d/99-claudeos-pi.conf

# Reduce monitoring frequency
cat > /etc/cron.d/claudeos << EOF
# ClaudeOS Pi Edition — Reduced Intervals
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Health check every 15 minutes (instead of 5)
*/15 * * * * root $CLAUDEOS_DIR/scripts/auto-health.sh

# Security watchdog every 30 minutes (instead of 15)
*/30 * * * * root $CLAUDEOS_DIR/scripts/auto-security.sh

# Daily backup at 3 AM
0 3 * * * root $CLAUDEOS_DIR/scripts/auto-backup.sh

# Daily report at 8 AM
0 8 * * * root $CLAUDEOS_DIR/scripts/daily-report.sh
EOF

# Reduce log retention
cat > /etc/logrotate.d/claudeos << 'EOF'
/opt/claudeos/logs/*.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
}
EOF

# Install CLI
ln -sf "$CLAUDEOS_DIR/scripts/claudeos-cli.sh" /usr/local/bin/claudeos
chmod +x "$CLAUDEOS_DIR/scripts/"*.sh

echo ""
echo "ClaudeOS Pi Edition installed!"
echo "  Optimized for: low memory, SD card, ARM"
echo "  Monitoring: every 15 min (reduced for Pi)"
echo "  Log retention: 7 days"
echo ""
echo "Type 'claudeos' to start!"
