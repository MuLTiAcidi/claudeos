#!/bin/bash
# ClaudeOS Auto-Backup
# Runs via cron daily at 2 AM

LOG="/opt/claudeos/logs/backup.log"
BACKUP_DIR="/backups"
RETENTION_DAYS=30
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
DATE_STAMP=$(date '+%Y%m%d-%H%M%S')

log() {
    echo "[$TIMESTAMP] [$1] [backup] $2" >> "$LOG"
}

mkdir -p "$BACKUP_DIR"

# Backup web files
if [ -d /var/www ]; then
    BACKUP_FILE="$BACKUP_DIR/web-www-$DATE_STAMP.tar.gz"
    tar czf "$BACKUP_FILE" /var/www 2>/dev/null
    SIZE=$(du -sh "$BACKUP_FILE" | awk '{print $1}')
    log "INFO" "Web files backed up: $BACKUP_FILE ($SIZE)"
fi

# Backup home directories
if [ -d /home ]; then
    BACKUP_FILE="$BACKUP_DIR/home-$DATE_STAMP.tar.gz"
    tar czf "$BACKUP_FILE" /home 2>/dev/null
    SIZE=$(du -sh "$BACKUP_FILE" | awk '{print $1}')
    log "INFO" "Home dirs backed up: $BACKUP_FILE ($SIZE)"
fi

# Backup configs
BACKUP_FILE="$BACKUP_DIR/configs-$DATE_STAMP.tar.gz"
tar czf "$BACKUP_FILE" /etc/nginx /etc/apache2 /etc/mysql /etc/ssh /etc/fail2ban /etc/ufw 2>/dev/null
SIZE=$(du -sh "$BACKUP_FILE" | awk '{print $1}')
log "INFO" "Configs backed up: $BACKUP_FILE ($SIZE)"

# Backup MySQL databases
if command -v mysqldump &>/dev/null; then
    BACKUP_FILE="$BACKUP_DIR/mysql-all-$DATE_STAMP.sql.gz"
    mysqldump --all-databases 2>/dev/null | gzip > "$BACKUP_FILE"
    SIZE=$(du -sh "$BACKUP_FILE" | awk '{print $1}')
    log "INFO" "MySQL backed up: $BACKUP_FILE ($SIZE)"
fi

# Backup crontabs
BACKUP_FILE="$BACKUP_DIR/crontabs-$DATE_STAMP.tar.gz"
tar czf "$BACKUP_FILE" /var/spool/cron 2>/dev/null
log "INFO" "Crontabs backed up"

# Rotate old backups
DELETED=$(find "$BACKUP_DIR" -name "*.tar.gz" -mtime +$RETENTION_DAYS -delete -print | wc -l)
DELETED_SQL=$(find "$BACKUP_DIR" -name "*.sql.gz" -mtime +$RETENTION_DAYS -delete -print | wc -l)
TOTAL_DELETED=$((DELETED + DELETED_SQL))
if [ "$TOTAL_DELETED" -gt 0 ]; then
    log "INFO" "Rotated $TOTAL_DELETED old backups (>$RETENTION_DAYS days)"
fi

# Check backup disk usage
BACKUP_SIZE=$(du -sh "$BACKUP_DIR" | awk '{print $1}')
log "INFO" "Total backup size: $BACKUP_SIZE"
