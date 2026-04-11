# Audit Logger

Automated audit trail agent for maintaining immutable logs, detecting tampering, enforcing chain-of-custody, and generating compliance reports using system-level auditing infrastructure.

## Safety Rules

- Never disable or bypass audit logging on any system, even temporarily
- Protect audit logs from modification — logs must be append-only with restricted permissions
- Ensure log rotation policies retain evidence for the required compliance period (minimum 90 days)
- Always test new audit rules in a staging environment before deploying to production
- Never overwrite or truncate existing audit logs; archive before any maintenance
- Verify audit daemon health continuously — silent failures mean invisible gaps
- Store audit log backups on a separate, hardened system with restricted access
- Encrypt audit logs in transit and at rest when forwarding to remote collectors
- Maintain separation of duties — operators should not be able to modify their own audit trails
- Document all changes to audit configuration with change management tickets

---

## 1. Auditd Setup

### 1.1 Installation and Initial Configuration

```bash
# Install auditd (Debian/Ubuntu)
sudo apt-get update && sudo apt-get install -y auditd audispd-plugins

# Install auditd (RHEL/CentOS/Fedora)
# sudo dnf install -y audit audit-libs

# Enable and start auditd
sudo systemctl enable auditd
sudo systemctl start auditd

# Verify auditd is running
sudo systemctl status auditd
sudo auditctl -s

# Backup existing audit configuration
sudo cp /etc/audit/auditd.conf /etc/audit/auditd.conf.backup.$(date +%Y%m%d)
sudo cp /etc/audit/rules.d/audit.rules /etc/audit/rules.d/audit.rules.backup.$(date +%Y%m%d) 2>/dev/null

# Configure auditd main settings
sudo tee /etc/audit/auditd.conf > /dev/null <<'EOF'
# Audit daemon configuration
log_file = /var/log/audit/audit.log
log_format = ENRICHED
log_group = adm
priority_boost = 4
flush = INCREMENTAL_ASYNC
freq = 50
num_logs = 10
max_log_file = 50
max_log_file_action = ROTATE
space_left = 75
space_left_action = SYSLOG
admin_space_left = 50
admin_space_left_action = SUSPEND
disk_full_action = SUSPEND
disk_error_action = SUSPEND
tcp_listen_queue = 5
tcp_max_per_addr = 1
tcp_client_max_idle = 0
enable_krb5 = no
krb5_principal = auditd
distribute_network = no
EOF

# Restart auditd to apply configuration
sudo systemctl restart auditd
sudo auditctl -s
```

### 1.2 Core Audit Rules

```bash
# Remove all existing rules (start clean)
sudo auditctl -D

# Set buffer size and failure mode
sudo auditctl -b 8192
sudo auditctl -f 1  # 0=silent, 1=printk, 2=panic

# === File Access Auditing ===

# Monitor /etc/passwd and /etc/shadow changes
sudo auditctl -w /etc/passwd -p wa -k user_accounts
sudo auditctl -w /etc/shadow -p wa -k user_accounts
sudo auditctl -w /etc/group -p wa -k user_accounts
sudo auditctl -w /etc/gshadow -p wa -k user_accounts

# Monitor sudoers file
sudo auditctl -w /etc/sudoers -p wa -k sudo_changes
sudo auditctl -w /etc/sudoers.d/ -p wa -k sudo_changes

# Monitor SSH configuration
sudo auditctl -w /etc/ssh/sshd_config -p wa -k ssh_config
sudo auditctl -w /etc/ssh/ -p wa -k ssh_config

# Monitor cron jobs
sudo auditctl -w /etc/crontab -p wa -k cron_changes
sudo auditctl -w /etc/cron.d/ -p wa -k cron_changes
sudo auditctl -w /etc/cron.daily/ -p wa -k cron_changes
sudo auditctl -w /etc/cron.hourly/ -p wa -k cron_changes
sudo auditctl -w /var/spool/cron/ -p wa -k cron_changes

# Monitor startup scripts and kernel modules
sudo auditctl -w /etc/init.d/ -p wa -k startup_scripts
sudo auditctl -w /etc/systemd/ -p wa -k startup_scripts
sudo auditctl -w /etc/modprobe.d/ -p wa -k kernel_modules

# === Execution Auditing ===

# Monitor privileged command execution
sudo auditctl -a always,exit -F arch=b64 -S execve -F euid=0 -k root_exec

# Monitor privilege escalation and user management commands
sudo auditctl -w /usr/bin/sudo -p x -k priv_escalation
sudo auditctl -w /usr/bin/su -p x -k priv_escalation
sudo auditctl -w /usr/sbin/useradd -p x -k user_mgmt
sudo auditctl -w /usr/sbin/userdel -p x -k user_mgmt
sudo auditctl -w /usr/sbin/usermod -p x -k user_mgmt

# === User Changes ===

# Monitor login/logout events and PAM configuration
sudo auditctl -w /var/log/wtmp -p wa -k login_events
sudo auditctl -w /var/log/btmp -p wa -k login_events
sudo auditctl -w /etc/pam.d/ -p wa -k pam_config

# === Network Auditing ===

# Monitor network config, firewall, and socket creation
sudo auditctl -w /etc/hosts -p wa -k network_config
sudo auditctl -w /etc/resolv.conf -p wa -k network_config
sudo auditctl -w /etc/iptables/ -p wa -k firewall_changes
sudo auditctl -a always,exit -F arch=b64 -S connect -S accept -S bind -k network_connections

# Verify all rules are loaded
sudo auditctl -l
echo "Total audit rules: $(sudo auditctl -l | wc -l)"
```

### 1.3 Persist Audit Rules

```bash
# Write all rules from section 1.2 to persistent configuration
# (mirrors the runtime rules above so they survive reboot)
sudo tee /etc/audit/rules.d/99-custom.rules > /dev/null <<'EOF'
-b 8192
-f 1
-w /etc/passwd -p wa -k user_accounts
-w /etc/shadow -p wa -k user_accounts
-w /etc/group -p wa -k user_accounts
-w /etc/sudoers -p wa -k sudo_changes
-w /etc/sudoers.d/ -p wa -k sudo_changes
-w /etc/ssh/sshd_config -p wa -k ssh_config
-w /etc/crontab -p wa -k cron_changes
-w /etc/cron.d/ -p wa -k cron_changes
-w /var/spool/cron/ -p wa -k cron_changes
-w /usr/bin/sudo -p x -k priv_escalation
-w /usr/bin/su -p x -k priv_escalation
-w /usr/sbin/useradd -p x -k user_mgmt
-w /usr/sbin/userdel -p x -k user_mgmt
-w /usr/sbin/usermod -p x -k user_mgmt
-w /var/log/wtmp -p wa -k login_events
-w /var/log/btmp -p wa -k login_events
-w /etc/hosts -p wa -k network_config
-w /etc/resolv.conf -p wa -k network_config
-a always,exit -F arch=b64 -S execve -F euid=0 -k root_exec
-a always,exit -F arch=b64 -S connect -S accept -S bind -k network_connections
# Make rules immutable (requires reboot to change)
-e 2
EOF

# Load the persistent rules
sudo augenrules --load
sudo auditctl -l | wc -l
```

---

## 2. AIDE File Integrity

### 2.1 AIDE Installation and Database Initialization

```bash
# Install AIDE (Debian/Ubuntu)
sudo apt-get update && sudo apt-get install -y aide

# Install AIDE (RHEL/CentOS)
# sudo dnf install -y aide

# Backup default AIDE configuration
sudo cp /etc/aide/aide.conf /etc/aide/aide.conf.backup.$(date +%Y%m%d) 2>/dev/null
sudo cp /etc/aide.conf /etc/aide.conf.backup.$(date +%Y%m%d) 2>/dev/null

# Configure AIDE rules (append to existing config)
AIDE_CONF="/etc/aide/aide.conf"
[ ! -f "$AIDE_CONF" ] && AIDE_CONF="/etc/aide.conf"

sudo tee -a "$AIDE_CONF" > /dev/null <<'EOF'
# Critical system binaries and configuration
/usr/bin CONTENT_EX
/usr/sbin CONTENT_EX
/etc/passwd CONTENT_EX
/etc/shadow CONTENT_EX
/etc/sudoers CONTENT_EX
/etc/ssh CONTENT_EX
/etc/pam.d CONTENT_EX
/boot CONTENT_EX
# Exclude volatile directories
!/var/log
!/var/cache
!/tmp
!/run
!/proc
!/sys
EOF

# Initialize the AIDE database (this takes several minutes)
sudo aideinit 2>/dev/null || sudo aide --init

# Move the new database into place
sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db 2>/dev/null
sudo cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz 2>/dev/null

echo "AIDE database initialized at $(date -Iseconds)"
```

### 2.2 AIDE Checks and Updates

```bash
# Run an AIDE integrity check
sudo aide --check 2>&1 | tee /tmp/aide_check_$(date +%Y%m%d_%H%M%S).txt
AIDE_EXIT=$?
[ $AIDE_EXIT -eq 0 ] && echo "[OK] No changes detected"
[ $AIDE_EXIT -le 7 ] && [ $AIDE_EXIT -gt 0 ] && echo "[ALERT] Changes detected!"

# Update AIDE database after verifying changes are legitimate
sudo aide --update
sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db 2>/dev/null

# Schedule daily AIDE checks via cron
CRON_ENTRY="0 3 * * * /usr/bin/aide --check 2>&1 | mail -s 'AIDE Report' admin@yourdomain.com"
(sudo crontab -l 2>/dev/null | grep -v "aide --check"; echo "$CRON_ENTRY") | sudo crontab -
```

---

## 3. Custom Audit Rules

### 3.1 Watch Specific Directories

```bash
# Watch a custom application directory for all changes
APP_DIR="/opt/myapp"
sudo auditctl -w "$APP_DIR" -p rwxa -k app_changes

# Watch configuration directory (read + write + attribute changes)
sudo auditctl -w /etc/nginx/ -p wa -k nginx_config
sudo auditctl -w /etc/apache2/ -p wa -k apache_config

# Watch sensitive data directories
sudo auditctl -w /srv/data/ -p rwa -k sensitive_data_access
sudo auditctl -w /var/lib/mysql/ -p wa -k database_changes

# Watch backup, SSL, and Docker directories
sudo auditctl -w /var/backups/ -p rwxa -k backup_access
sudo auditctl -w /etc/ssl/private/ -p rwa -k ssl_cert_access
sudo auditctl -w /etc/docker/ -p wa -k docker_config
```

### 3.2 Syscall Auditing

```bash
# Audit file deletion syscalls (64-bit and 32-bit)
sudo auditctl -a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -k file_deletion

# Audit file permission and ownership changes
sudo auditctl -a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -k file_permissions
sudo auditctl -a always,exit -F arch=b64 -S chown -S fchown -S lchown -S fchownat -k file_ownership

# Audit kernel module loading, mount operations, time changes
sudo auditctl -a always,exit -F arch=b64 -S init_module -S finit_module -S delete_module -k kernel_module_load
sudo auditctl -a always,exit -F arch=b64 -S mount -S umount2 -k mount_operations
sudo auditctl -a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k time_change

# Audit ptrace (debugging/injection)
sudo auditctl -a always,exit -F arch=b64 -S ptrace -k process_injection
```

### 3.3 User Activity Auditing

```bash
# Audit commands run by a specific user
TARGET_UID=$(id -u targetuser 2>/dev/null || echo 1001)
sudo auditctl -a always,exit -F arch=b64 -S execve -F uid=$TARGET_UID -k user_commands_${TARGET_UID}

# Audit all failed access attempts
sudo auditctl -a always,exit -F arch=b64 -S open -S openat -F exit=-EACCES -k access_denied
sudo auditctl -a always,exit -F arch=b64 -S open -S openat -F exit=-EPERM -k access_denied

# Audit failed logins and session tracking
sudo auditctl -w /var/log/faillog -p wa -k failed_logins
sudo auditctl -w /var/run/utmp -p wa -k session_tracking

# Audit administrative tools
sudo auditctl -w /usr/bin/passwd -p x -k passwd_change
sudo auditctl -w /usr/bin/chage -p x -k account_mgmt
```

---

## 4. Log Integrity

### 4.1 Append-Only Log Configuration

```bash
# Set audit log and critical logs to append-only
sudo chattr +a /var/log/audit/audit.log
sudo chattr +a /var/log/syslog /var/log/auth.log /var/log/kern.log 2>/dev/null

# Verify attributes
lsattr /var/log/audit/audit.log /var/log/syslog /var/log/auth.log 2>/dev/null

# Set restrictive permissions
sudo chmod 640 /var/log/audit/audit.log
sudo chown root:adm /var/log/audit/audit.log
```

### 4.2 Remote Syslog Forwarding

```bash
# Configure rsyslog to forward logs to a remote collector (TCP for reliability)
sudo tee /etc/rsyslog.d/50-remote-audit.conf > /dev/null <<'EOF'
*.* @@remote-syslog.yourdomain.com:514
$ActionQueueType LinkedList
$ActionQueueFileName remote_fwd
$ActionResumeRetryCount -1
$ActionQueueSaveOnShutdown on
$ActionQueueMaxDiskSpace 1g
auth,authpriv.* @@remote-syslog.yourdomain.com:514
local6.* @@remote-syslog.yourdomain.com:514
EOF

sudo systemctl restart rsyslog

# Test remote forwarding
logger -t audit-test "Test message from $(hostname) at $(date -Iseconds)"

# Configure journald to persist and forward to syslog
sudo tee -a /etc/systemd/journald.conf > /dev/null <<'EOF'
[Journal]
ForwardToSyslog=yes
Storage=persistent
Compress=yes
SystemMaxUse=2G
MaxFileSec=1month
EOF

sudo systemctl restart systemd-journald
```

### 4.3 Log Signing and Verification

```bash
# Create signing key directory and generate HMAC key
LOG_SIGN_DIR="/etc/audit/signing"
sudo mkdir -p "$LOG_SIGN_DIR" && sudo chmod 700 "$LOG_SIGN_DIR"
sudo openssl rand -hex 32 > "$LOG_SIGN_DIR/hmac_key"
sudo chmod 600 "$LOG_SIGN_DIR/hmac_key"

# Sign an audit log file
LOGFILE="/var/log/audit/audit.log"
sudo openssl dgst -sha256 -hmac "$(sudo cat $LOG_SIGN_DIR/hmac_key)" "$LOGFILE" \
  | sudo tee "${LOGFILE}.sig" > /dev/null
sudo chmod 400 "${LOGFILE}.sig"

# Verify a signed log file
CURRENT=$(sudo openssl dgst -sha256 -hmac "$(sudo cat $LOG_SIGN_DIR/hmac_key)" "$LOGFILE")
STORED=$(sudo cat "${LOGFILE}.sig")
if [ "$CURRENT" = "$STORED" ]; then
  echo "[VERIFIED] Log file integrity confirmed"
else
  echo "[TAMPERED] Log file has been modified!"
fi

# Schedule hourly log signing
CRON_ENTRY="0 * * * * /usr/local/bin/sign-audit-logs.sh >> /var/log/audit/signing.log 2>&1"
(sudo crontab -l 2>/dev/null | grep -v "sign-audit-logs"; echo "$CRON_ENTRY") | sudo crontab -
```

---

## 5. Tamper Detection

### 5.1 Verify Log Integrity

```bash
# Check audit log for integrity issues
sudo aureport --integrity 2>/dev/null || echo "aureport integrity check not available"

# Detect time gaps in audit logs (gaps > 60 seconds indicate potential deletion)
sudo awk -F'[=: .]' '/^type=/ {
  ts = $2 + 0;
  if (prev_ts > 0 && ts - prev_ts > 60) {
    printf "[GAP DETECTED] %.0f second gap at epoch %d\n", ts - prev_ts, prev_ts
  }
  prev_ts = ts
}' /var/log/audit/audit.log

# Check for truncated or empty log files
for logfile in /var/log/audit/audit.log*; do
  [ -f "$logfile" ] || continue
  SIZE=$(stat -c%s "$logfile" 2>/dev/null || stat -f%z "$logfile")
  if [ "$SIZE" -eq 0 ]; then
    echo "[ALERT] Empty log file: $logfile"
  else
    echo "$logfile: $(wc -l < "$logfile") lines, $SIZE bytes"
  fi
done
```

### 5.2 Detect Audit Daemon Disruptions

```bash
# Check for unexpected auditd stops, config changes, and rule modifications
sudo ausearch -m DAEMON_END -ts recent 2>/dev/null | head -10
sudo ausearch -m CONFIG_CHANGE -ts today 2>/dev/null | head -10
sudo journalctl -u auditd --since "24 hours ago" --no-pager | head -20

# Verify chattr append-only flag is still set
if lsattr /var/log/audit/audit.log 2>/dev/null | grep -q "a"; then
  echo "[OK] Append-only attribute is set on audit.log"
else
  echo "[ALERT] Append-only attribute is NOT set — possible tampering!"
fi
```

### 5.3 Check Log Rotation Configuration

```bash
# Review current logrotate config
cat /etc/logrotate.d/audit 2>/dev/null || echo "No logrotate config for audit"

# Create a safe logrotate config that preserves evidence (365 day retention)
sudo tee /etc/logrotate.d/audit > /dev/null <<'EOF'
/var/log/audit/audit.log {
    rotate 365
    daily
    compress
    delaycompress
    notifempty
    missingok
    dateext
    dateformat -%Y%m%d
    create 0640 root adm
    postrotate
        /usr/bin/killall -USR1 auditd 2>/dev/null || true
        /usr/local/bin/sign-audit-logs.sh 2>/dev/null || true
    endscript
}
EOF
```

---

## 6. Compliance Logging

### 6.1 Who Did What, When, Where

```bash
# Search for all actions by a specific user
sudo ausearch -ua admin -ts today --interpret 2>/dev/null | head -30

# Search by key: sudo usage, user changes, SSH, network, failed access
sudo ausearch -k priv_escalation -ts today --interpret 2>/dev/null | head -20
sudo ausearch -k user_mgmt -ts this-week --interpret 2>/dev/null | head -20
sudo ausearch -k ssh_config -ts this-week --interpret 2>/dev/null | head -20
sudo ausearch -k access_denied -ts today --interpret 2>/dev/null | head -20

# Search for file access events on a specific file
sudo ausearch -f /etc/passwd -ts today --interpret 2>/dev/null | head -20

# List all unique executables run as root today
sudo ausearch -k root_exec -ts today 2>/dev/null \
  | grep "exe=" | sed 's/.*exe="\([^"]*\)".*/\1/' \
  | sort -u | head -20
```

### 6.2 Session Tracking

```bash
# Track user sessions via journald
sudo journalctl _COMM=sshd --since "24 hours ago" --no-pager \
  | grep -E "(Accepted|Failed|session opened|session closed)" | head -20

# Show current sessions, login history, and failed attempts
who -a
last -n 20
sudo lastb -n 20 2>/dev/null

# Detect concurrent sessions from the same user
who | awk '{print $1}' | sort | uniq -c | sort -rn \
  | awk '$1 > 1 {print "[NOTICE] " $2 " has " $1 " concurrent sessions"}'
```

---

## 7. Report Generation

### 7.1 Audit Summary Reports

```bash
# Quick summary using aureport
echo "=== AUDIT SUMMARY REPORT — $(date -Iseconds) ==="
sudo aureport -au --summary -ts today 2>/dev/null || echo "No auth events"
sudo aureport -au --failed -ts today 2>/dev/null || echo "No failed auth"
sudo aureport -l --summary -ts today 2>/dev/null || echo "No login events"
sudo aureport -f --summary -ts today 2>/dev/null || echo "No file events"
sudo aureport -x --summary -ts today 2>/dev/null || echo "No exec events"
sudo aureport --anomaly -ts today 2>/dev/null || echo "No anomalies"
sudo aureport -k --summary -ts today 2>/dev/null || echo "No key events"
```

### 7.2 Full Audit Report Generation

```bash
# Generate a comprehensive daily audit report
REPORT_DIR="/var/log/audit/reports"
sudo mkdir -p "$REPORT_DIR"
REPORT_FILE="${REPORT_DIR}/audit-report-$(date +%Y-%m-%d).txt"

sudo bash -c "cat > '$REPORT_FILE'" <<REPORT_EOF
================================================================
  DAILY AUDIT LOG REPORT — $(date -Iseconds) — $(hostname)
================================================================
--- AUDIT STATUS ---
$(sudo auditctl -s 2>/dev/null)
Rules: $(sudo auditctl -l 2>/dev/null | wc -l)

--- AUTH SUMMARY ---
$(sudo aureport -au --summary -ts today 2>/dev/null || echo "N/A")

--- FAILED LOGINS ---
$(sudo aureport -au --failed -ts today 2>/dev/null || echo "N/A")

--- USER CHANGES ---
$(sudo ausearch -k user_mgmt -ts today --interpret 2>/dev/null | head -20 || echo "None")

--- PRIVILEGE ESCALATION ---
$(sudo ausearch -k priv_escalation -ts today --interpret 2>/dev/null | head -20 || echo "None")

--- FILE INTEGRITY ---
$(sudo aide --check 2>/dev/null | tail -15 || echo "AIDE not available")

--- LOG INTEGRITY ---
Size: $(ls -lh /var/log/audit/audit.log 2>/dev/null | awk '{print $5}')
Append-only: $(lsattr /var/log/audit/audit.log 2>/dev/null | awk '{print $1}')

--- ANOMALIES ---
$(sudo aureport --anomaly -ts today 2>/dev/null | head -15 || echo "None")
================================================================
REPORT_EOF

sudo chmod 640 "$REPORT_FILE"
echo "Report saved to: $REPORT_FILE"

# Schedule daily report generation
CRON_ENTRY="0 6 * * * /usr/local/bin/generate-audit-report.sh >> /var/log/audit/report-gen.log 2>&1"
(sudo crontab -l 2>/dev/null | grep -v "generate-audit-report"; echo "$CRON_ENTRY") | sudo crontab -
```

---

## Quick Reference

| Task | Tool | Command |
|------|------|---------|
| Check auditd status | auditctl | `sudo auditctl -s` |
| List audit rules | auditctl | `sudo auditctl -l` |
| Watch a file | auditctl | `sudo auditctl -w /path/file -p wa -k key_name` |
| Watch a directory | auditctl | `sudo auditctl -w /path/dir/ -p rwxa -k key_name` |
| Audit a syscall | auditctl | `sudo auditctl -a always,exit -F arch=b64 -S syscall -k key_name` |
| Search by key | ausearch | `sudo ausearch -k key_name -ts today --interpret` |
| Search by user | ausearch | `sudo ausearch -ua username -ts today --interpret` |
| Search by file | ausearch | `sudo ausearch -f /path/file -ts today --interpret` |
| Auth report | aureport | `sudo aureport -au --summary -ts today` |
| Failed logins | aureport | `sudo aureport -au --failed -ts today` |
| Anomaly report | aureport | `sudo aureport --anomaly -ts today` |
| Key hit summary | aureport | `sudo aureport -k --summary -ts today` |
| Init AIDE database | aide | `sudo aideinit` or `sudo aide --init` |
| Run AIDE check | aide | `sudo aide --check` |
| Update AIDE database | aide | `sudo aide --update` |
| Set append-only | chattr | `sudo chattr +a /var/log/audit/audit.log` |
| Verify attributes | lsattr | `lsattr /var/log/audit/audit.log` |
| Forward logs | rsyslog | `*.* @@remote-syslog:514` in rsyslog config |
| Check journal | journalctl | `sudo journalctl -u auditd --since "24 hours ago"` |
| Make rules immutable | auditctl | Add `-e 2` as last rule (requires reboot to change) |
| Load persistent rules | augenrules | `sudo augenrules --load` |
