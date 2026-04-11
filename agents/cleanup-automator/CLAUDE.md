# Cleanup Automator Agent

Scheduled cleanup of temporary files, stale logs, package caches, journal entries, and orphaned Docker resources. Uses `find -mtime/-atime`, `logrotate`, `journalctl --vacuum-*`, `apt clean`, and `docker system prune` to free disk space safely on a cron or systemd timer schedule.

---

## Safety Rules

- NEVER delete files outside of explicitly allow-listed paths.
- NEVER use `rm -rf /` or paths with unverified variables (`rm -rf $VAR/`).
- ALWAYS dry-run with `-print` or `--dry-run` before destructive operations.
- ALWAYS create a snapshot or list of files about to be removed (audit log).
- NEVER delete files from `/etc`, `/bin`, `/sbin`, `/lib`, `/usr/bin`, `/usr/sbin`, `/boot`, `/home/*/`.
- NEVER stop services to clean their data without explicit consent.
- ALWAYS log every cleanup action to `/var/log/cleanup-automator.log` with byte counts freed.
- For Docker cleanups, NEVER prune volumes without confirming none belong to running stacks.

---

## 1. Disk Space Inventory (Before/After)

### Free Space Snapshot

```bash
df -hT --output=source,fstype,size,used,avail,pcent,target | grep -vE '^tmpfs|^devtmpfs'
```

### Top Space Consumers

```bash
sudo du -h --max-depth=1 /var 2>/dev/null | sort -h | tail -15
sudo du -h --max-depth=1 / 2>/dev/null | sort -h | tail -15
```

### Largest Files on Disk

```bash
sudo find / -xdev -type f -size +100M -exec ls -lh {} \; 2>/dev/null \
    | awk '{print $5, $9}' | sort -h | tail -20
```

### Inode Usage

```bash
df -i | grep -vE '^tmpfs|^devtmpfs'
```

### Capture Baseline

```bash
df -B1 / | awk 'NR==2{print $4}' > /tmp/cleanup-before.bytes
```

---

## 2. /tmp Cleanup

### Files Older Than 7 Days (dry run)

```bash
find /tmp -xdev -type f -mtime +7 -print
```

### Delete Old /tmp Files

```bash
find /tmp -xdev -type f -mtime +7 -delete
find /tmp -xdev -type d -empty -mtime +7 -delete
```

### Delete Files Not Accessed in 14 Days

```bash
find /tmp -xdev -type f -atime +14 -delete
```

### systemd-tmpfiles (preferred for /tmp on systemd)

```bash
sudo systemd-tmpfiles --clean
```

### Clean /var/tmp (older than 30 days)

```bash
find /var/tmp -xdev -type f -mtime +30 -delete
find /var/tmp -xdev -type d -empty -mtime +30 -delete
```

---

## 3. Log Rotation and Cleanup

### Force Logrotate Run

```bash
sudo logrotate -f /etc/logrotate.conf
```

### Logrotate Dry Run

```bash
sudo logrotate -d /etc/logrotate.conf 2>&1 | head -50
```

### Sample logrotate Config (`/etc/logrotate.d/myapp`)

```
/var/log/myapp/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    sharedscripts
    postrotate
        systemctl reload myapp.service > /dev/null 2>&1 || true
    endscript
}
```

### Find Big Old Logs

```bash
sudo find /var/log -type f -name "*.log" -mtime +30 -size +50M -ls
```

### Compress Old Uncompressed Logs

```bash
sudo find /var/log -type f -name "*.log.[0-9]*" ! -name "*.gz" -exec gzip {} \;
```

### Delete Logs Older Than 60 Days

```bash
sudo find /var/log -type f \( -name "*.gz" -o -name "*.[0-9]" \) -mtime +60 -delete
```

### Truncate Active Log Without Restart

```bash
sudo truncate -s 0 /var/log/myapp/app.log
```

### Empty Old Auth Logs

```bash
sudo find /var/log -type f -name "auth.log.*" -mtime +30 -delete
sudo find /var/log -type f -name "syslog.*" -mtime +30 -delete
```

---

## 4. systemd journal Vacuum

### Show Journal Disk Usage

```bash
journalctl --disk-usage
```

### Vacuum by Time (keep last 7 days)

```bash
sudo journalctl --vacuum-time=7d
```

### Vacuum by Size (cap at 500M)

```bash
sudo journalctl --vacuum-size=500M
```

### Vacuum by File Count

```bash
sudo journalctl --vacuum-files=5
```

### Persistent Cap via Config

```bash
sudo sed -i 's/^#SystemMaxUse=.*/SystemMaxUse=500M/' /etc/systemd/journald.conf
sudo systemctl restart systemd-journald
```

### Verify After Vacuum

```bash
journalctl --disk-usage
```

---

## 5. APT Package Cache Cleanup

### Show APT Cache Size

```bash
sudo du -sh /var/cache/apt/archives
```

### Clean Downloaded .deb Files

```bash
sudo apt clean
```

### Remove Only Obsolete Packages

```bash
sudo apt autoclean
```

### Remove Orphaned Packages

```bash
sudo apt autoremove --purge -y
```

### Remove Old Kernels (keep current + 1)

```bash
CURRENT=$(uname -r)
dpkg -l 'linux-image-*' | awk '/^ii/{print $2}' \
    | grep -v "$CURRENT" \
    | grep -v "$(uname -r | sed 's/-generic//')" \
    | head -n -1 \
    | xargs -r sudo apt purge -y
```

### Remove Residual Config Files

```bash
dpkg -l | awk '/^rc/ {print $2}' | xargs -r sudo dpkg --purge
```

---

## 6. Docker Cleanup

### Disk Usage Summary

```bash
docker system df
docker system df -v
```

### Remove Stopped Containers

```bash
docker container prune -f
```

### Remove Dangling Images

```bash
docker image prune -f
```

### Remove ALL Unused Images (not just dangling)

```bash
docker image prune -af
```

### Remove Unused Networks

```bash
docker network prune -f
```

### Remove Unused Volumes (CAREFUL)

```bash
docker volume prune -f
```

### Full Prune (everything unused, including volumes)

```bash
docker system prune -af --volumes
```

### Full Prune Excluding Volumes

```bash
docker system prune -af
```

### Remove Build Cache

```bash
docker builder prune -af
```

### Remove Containers Older Than 24h

```bash
docker container prune -f --filter "until=24h"
```

### Identify Large Images

```bash
docker images --format '{{.Repository}}:{{.Tag}}\t{{.Size}}' \
    | sort -k2 -h | tail -20
```

---

## 7. User Cache Cleanup

### Per-User Thumbnail Cache

```bash
for U in $(getent passwd | awk -F: '$3>=1000 && $3<60000 {print $1}'); do
    HOME_DIR=$(getent passwd "$U" | cut -d: -f6)
    [ -d "$HOME_DIR/.cache/thumbnails" ] && \
        find "$HOME_DIR/.cache/thumbnails" -type f -mtime +30 -delete
done
```

### Clean ~/.cache Older Than 30 Days

```bash
find /home/*/.cache -type f -mtime +30 -delete 2>/dev/null
find /root/.cache -type f -mtime +30 -delete 2>/dev/null
```

### Clean Trash

```bash
find /home/*/.local/share/Trash -type f -mtime +30 -delete 2>/dev/null
```

### Clean pip / npm / cargo Caches

```bash
sudo -u www-data pip cache purge 2>/dev/null || true
npm cache clean --force 2>/dev/null || true
cargo cache --autoclean 2>/dev/null || true
```

### Clean Snap Old Revisions

```bash
sudo snap list --all | awk '/disabled/{print $1, $3}' \
    | while read snapname rev; do
        sudo snap remove "$snapname" --revision="$rev"
    done
```

---

## 8. Application-Specific Cleanups

### Nginx Cache

```bash
sudo find /var/cache/nginx -type f -mtime +7 -delete
sudo systemctl reload nginx
```

### PHP Session Files

```bash
sudo find /var/lib/php/sessions -type f -mmin +1440 -delete
```

### MySQL Binary Logs (older than 7 days)

```bash
mysql -e "PURGE BINARY LOGS BEFORE DATE_SUB(NOW(), INTERVAL 7 DAY);"
```

### Redis FLUSHDB Selected DB (only if confirmed)

```bash
redis-cli -n 1 FLUSHDB
```

### Old Backups

```bash
find /var/backups -type f -name "*.tar.gz" -mtime +30 -delete
```

### Crash Dumps

```bash
sudo find /var/crash -type f -mtime +14 -delete
sudo rm -f /var/lib/systemd/coredump/core.*
```

---

## 9. Orphaned Files Cleanup

### Files Owned by Removed Users

```bash
sudo find / -xdev -nouser -ls 2>/dev/null | head -50
sudo find / -xdev -nouser -delete 2>/dev/null
```

### Files With Removed Groups

```bash
sudo find / -xdev -nogroup -ls 2>/dev/null | head -50
```

### Empty Directories Under /var/log

```bash
sudo find /var/log -type d -empty -delete
```

### Broken Symlinks in /etc

```bash
sudo find /etc -xtype l -ls
```

---

## 10. Master Cleanup Script

### Save as `/usr/local/bin/cleanup-automator.sh`

```bash
#!/bin/bash
set -uo pipefail

LOG=/var/log/cleanup-automator.log
DRY_RUN=${DRY_RUN:-0}

log() { echo "[$(date '+%F %T')] $*" | tee -a "$LOG"; }
run() {
    if [ "$DRY_RUN" = "1" ]; then
        log "DRY: $*"
    else
        log "RUN: $*"
        eval "$@" 2>&1 | tee -a "$LOG"
    fi
}

BEFORE=$(df -B1 / | awk 'NR==2{print $4}')
log "=== Cleanup started ==="
log "Free space before: $(numfmt --to=iec $BEFORE)"

# /tmp
run "find /tmp -xdev -type f -mtime +7 -delete"
run "find /var/tmp -xdev -type f -mtime +30 -delete"

# Logs
run "logrotate -f /etc/logrotate.conf"
run "find /var/log -type f -name '*.gz' -mtime +60 -delete"
run "find /var/log -type f -name '*.[0-9]' -mtime +60 -delete"

# Journal
run "journalctl --vacuum-time=7d"
run "journalctl --vacuum-size=500M"

# APT
run "apt clean"
run "apt autoremove --purge -y"

# Docker (only if installed)
if command -v docker >/dev/null; then
    run "docker container prune -f"
    run "docker image prune -af"
    run "docker network prune -f"
    run "docker builder prune -af"
    # NOTE: omit volume prune unless confirmed safe
fi

# Caches
run "find /home/*/.cache -type f -mtime +30 -delete 2>/dev/null || true"
run "find /root/.cache -type f -mtime +30 -delete 2>/dev/null || true"

# Crash dumps
run "find /var/crash -type f -mtime +14 -delete 2>/dev/null || true"

AFTER=$(df -B1 / | awk 'NR==2{print $4}')
FREED=$((AFTER - BEFORE))
log "Free space after:  $(numfmt --to=iec $AFTER)"
log "Freed:             $(numfmt --to=iec $FREED)"
log "=== Cleanup finished ==="
```

### Make Executable

```bash
sudo chmod +x /usr/local/bin/cleanup-automator.sh
```

### Run in Dry-Run Mode

```bash
sudo DRY_RUN=1 /usr/local/bin/cleanup-automator.sh
```

### Run For Real

```bash
sudo /usr/local/bin/cleanup-automator.sh
```

---

## 11. Cron Scheduling

### Daily at 03:30

```bash
sudo crontab -e
# Add:
30 3 * * * /usr/local/bin/cleanup-automator.sh >/dev/null 2>&1
```

### Weekly Deeper Clean Sundays at 04:00

```bash
0 4 * * 0 DEEP=1 /usr/local/bin/cleanup-automator.sh >/dev/null 2>&1
```

### systemd Timer Alternative

```bash
sudo tee /etc/systemd/system/cleanup-automator.service <<'EOF'
[Unit]
Description=ClaudeOS cleanup automator

[Service]
Type=oneshot
ExecStart=/usr/local/bin/cleanup-automator.sh
Nice=10
IOSchedulingClass=best-effort
IOSchedulingPriority=7
EOF

sudo tee /etc/systemd/system/cleanup-automator.timer <<'EOF'
[Unit]
Description=Daily cleanup timer

[Timer]
OnCalendar=*-*-* 03:30:00
Persistent=true
RandomizedDelaySec=600

[Install]
WantedBy=timers.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now cleanup-automator.timer
```

### Verify

```bash
systemctl list-timers | grep cleanup
```

---

## 12. Pre-Cleanup Audit (List Before Delete)

### Capture What Will Be Removed

```bash
TS=$(date +%F-%H%M)
AUDIT=/var/log/cleanup-audit-$TS.list
{
    echo "## /tmp candidates"
    find /tmp -xdev -type f -mtime +7
    echo "## /var/tmp candidates"
    find /var/tmp -xdev -type f -mtime +30
    echo "## old log archives"
    find /var/log -type f -name "*.gz" -mtime +60
} > "$AUDIT"
wc -l "$AUDIT"
```

### Confirm Before Running Real Cleanup

```bash
echo "Audit at $AUDIT — review then run cleanup-automator.sh"
```

---

## 13. Disk Pressure Triggered Cleanup

### Trigger Cleanup When > 85% Full

```bash
USED=$(df / | awk 'NR==2{gsub("%","",$5); print $5}')
if [ "$USED" -gt 85 ]; then
    /usr/local/bin/cleanup-automator.sh
fi
```

### Cron Every 15 Minutes

```bash
*/15 * * * * /usr/local/bin/cleanup-if-full.sh
```

### Save as `/usr/local/bin/cleanup-if-full.sh`

```bash
#!/bin/bash
THRESHOLD=85
USED=$(df / | awk 'NR==2{gsub("%","",$5); print $5}')
if [ "$USED" -gt "$THRESHOLD" ]; then
    logger -t cleanup-automator "Disk at ${USED}% — running cleanup"
    /usr/local/bin/cleanup-automator.sh
fi
```

---

## 14. Whitelisting and Excludes

### find with Multiple Excludes

```bash
find /var/log \
    \( -path /var/log/audit -prune \) -o \
    \( -path /var/log/journal -prune \) -o \
    \( -type f -name "*.gz" -mtime +60 -print \)
```

### Logrotate Exclude

```
# /etc/logrotate.d/skip-audit
/var/log/audit/*.log {
    rotate 0
    missingok
    notifempty
}
```

---

## 15. Common Workflows

### "Clean up disk space, I'm at 95%"

```bash
df -h /
sudo /usr/local/bin/cleanup-automator.sh
df -h /
```

### "Free up Docker space"

```bash
docker system df
docker system prune -af
docker system df
```

### "Vacuum the journal to 200M"

```bash
sudo journalctl --vacuum-size=200M
journalctl --disk-usage
```

### "Remove old kernels"

```bash
dpkg -l 'linux-image-*' | awk '/^ii/{print $2}'
sudo apt autoremove --purge -y
```

### "What's the biggest junk on this server?"

```bash
sudo du -h /var --max-depth=2 2>/dev/null | sort -h | tail -20
sudo find /var -xdev -type f -size +500M -ls 2>/dev/null
```

### "Clean /tmp without breaking running apps"

```bash
sudo systemd-tmpfiles --clean
```

---

## 16. Troubleshooting

### find Returns "Permission Denied"

```bash
sudo find /var -type f -mtime +30 2>/dev/null
```

### apt autoremove Wants to Remove Something Important

```bash
sudo apt autoremove --dry-run --purge
# Check the list before confirming
```

### Docker Prune Removed Needed Images

```bash
# Re-pull from registry
docker pull <image>:<tag>
```

### journalctl Vacuum Has No Effect

```bash
# Check if journal is volatile (RAM only)
cat /etc/systemd/journald.conf | grep Storage
sudo mkdir -p /var/log/journal
sudo systemd-tmpfiles --create --prefix /var/log/journal
sudo systemctl restart systemd-journald
```

---

## Output Format

When cleanup runs, always show:

1. **Free space BEFORE** (path + bytes + human)
2. **Categories cleaned** (tmp, logs, journal, apt, docker, cache)
3. **Files/items removed per category**
4. **Free space AFTER** + delta freed
5. **Audit log path** (`/var/log/cleanup-automator.log`)
6. **Next scheduled run** (cron or timer)
