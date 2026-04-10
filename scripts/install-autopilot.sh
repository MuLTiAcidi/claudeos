#!/bin/bash
# ClaudeOS — Install Auto-Pilot (cron jobs)
# Run once to set up autonomous monitoring

set -e

if [ "$EUID" -ne 0 ]; then
    echo "Run as root: sudo bash install-autopilot.sh"
    exit 1
fi

CLAUDEOS_DIR="/opt/claudeos"

# Make all scripts executable
chmod +x "$CLAUDEOS_DIR/scripts/"*.sh

# Create log directory
mkdir -p "$CLAUDEOS_DIR/logs"
mkdir -p /backups

# Install claudeos CLI command
ln -sf "$CLAUDEOS_DIR/scripts/claudeos-cli.sh" /usr/local/bin/claudeos
echo "  ✓ 'claudeos' command installed"

# Install cron jobs
CRON_FILE="/etc/cron.d/claudeos"
cat > "$CRON_FILE" << EOF
# ClaudeOS Autonomous Tasks
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Health check every 5 minutes
*/5 * * * * root $CLAUDEOS_DIR/scripts/auto-health.sh

# Security watchdog every 15 minutes
*/15 * * * * root $CLAUDEOS_DIR/scripts/auto-security.sh

# Daily backup at 2 AM
0 2 * * * root $CLAUDEOS_DIR/scripts/auto-backup.sh

# Daily report at 7 AM
0 7 * * * root $CLAUDEOS_DIR/scripts/daily-report.sh

# Weekly auto-optimization (Sunday 4 AM)
0 4 * * 0 root $CLAUDEOS_DIR/scripts/auto-optimize.sh

# Weekly self-update check (Sunday 5 AM)
0 5 * * 0 root $CLAUDEOS_DIR/scripts/self-update.sh
EOF

chmod 644 "$CRON_FILE"

echo "================================"
echo "  ClaudeOS Auto-Pilot Installed"
echo "================================"
echo ""
echo "Scheduled tasks:"
echo "  Every 5 min  — Health check (CPU, RAM, disk, services)"
echo "  Every 15 min — Security watchdog (brute force, ports, firewall)"
echo "  Daily 2:00   — Automated backups with rotation"
echo "  Daily 7:00   — Daily summary report"
echo "  Weekly Sun    — Auto-optimize (MySQL, Nginx, PHP-FPM tuning)"
echo "  Weekly Sun    — Self-update (Claude Code CLI + security patches)"
echo ""
echo "Logs at: $CLAUDEOS_DIR/logs/"
echo "  health.log   — system health events"
echo "  security.log — security events and bans"
echo "  backup.log   — backup operations"
echo "  daily-report-*.md — daily summaries"
echo ""
echo "Auto-fix capabilities:"
echo "  ✓ Restart crashed services (max 3 retries)"
echo "  ✓ Clean disk when >85% full"
echo "  ✓ Ban brute-force IPs automatically"
echo "  ✓ Rotate old backups"
echo "  ✓ Compress old logs"
echo ""
echo "To disable: rm /etc/cron.d/claudeos"
