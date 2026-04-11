# Log Forensics Agent

Detect suspicious patterns in system logs. Analyzes auth.log, syslog, kern.log, and application logs for indicators of compromise, brute force attacks, privilege escalation, and other security events.

## Safety Rules

- NEVER modify or delete log files — read-only analysis
- NEVER tamper with audit trails
- NEVER expose sensitive data found in logs
- Preserve evidence integrity at all times
- Store analysis results with restricted permissions (0600)
- Maintain chain of custody for forensic findings
- Document all analysis steps for reproducibility

---

## 1. Authentication Log Analysis

### Brute Force Detection

```bash
# Failed SSH login attempts
grep "Failed password" /var/log/auth.log | tail -50

# Count failed logins by IP
grep "Failed password" /var/log/auth.log | grep -oP 'from \K[\d.]+' | sort | uniq -c | sort -rn | head -20

# Count failed logins by username
grep "Failed password" /var/log/auth.log | grep -oP 'for (invalid user )?\K\S+' | sort | uniq -c | sort -rn | head -20

# Detect brute force (more than 10 failures from same IP)
grep "Failed password" /var/log/auth.log | grep -oP 'from \K[\d.]+' | sort | uniq -c | sort -rn | awk '$1 > 10 {print "BRUTE FORCE: " $1 " attempts from " $2}'

# Failed logins in the last hour
grep "Failed password" /var/log/auth.log | awk -v date="$(date -d '1 hour ago' '+%b %d %H')" '$0 >= date'

# Successful logins after failed attempts (potential compromise)
for ip in $(grep "Failed password" /var/log/auth.log | grep -oP 'from \K[\d.]+' | sort -u); do
  failures=$(grep "Failed password" /var/log/auth.log | grep -c "$ip")
  success=$(grep "Accepted" /var/log/auth.log | grep -c "$ip")
  if [ "$failures" -gt 5 ] && [ "$success" -gt 0 ]; then
    echo "ALERT: $ip had $failures failures then $success successful logins"
  fi
done

# Invalid user attempts (username scanning)
grep "Invalid user" /var/log/auth.log | grep -oP 'Invalid user \K\S+' | sort | uniq -c | sort -rn | head -20
```

### Successful Login Analysis

```bash
# All successful SSH logins
grep "Accepted" /var/log/auth.log | tail -30

# Successful logins by user
grep "Accepted" /var/log/auth.log | grep -oP 'for \K\S+' | sort | uniq -c | sort -rn

# Logins from unusual IPs
grep "Accepted" /var/log/auth.log | grep -oP 'from \K[\d.]+' | sort -u

# Logins at unusual hours (outside business hours)
grep "Accepted" /var/log/auth.log | awk '{
  split($3, t, ":");
  hour = t[1];
  if (hour < 6 || hour > 22) print "OFF-HOURS LOGIN: " $0
}'

# Root logins (should be rare)
grep "Accepted" /var/log/auth.log | grep "for root"

# Key-based vs password logins
echo "Key-based: $(grep -c 'Accepted publickey' /var/log/auth.log)"
echo "Password: $(grep -c 'Accepted password' /var/log/auth.log)"

# Last login for all users
lastlog

# Login history
last -20

# Failed login history
lastb -20 2>/dev/null
```

---

## 2. Privilege Escalation Detection

### Sudo Activity

```bash
# All sudo commands
grep "sudo:" /var/log/auth.log | tail -30

# Failed sudo attempts
grep "sudo:.*authentication failure\|sudo:.*incorrect password\|sudo:.*NOT in sudoers" /var/log/auth.log

# Users not in sudoers trying sudo
grep "NOT in sudoers" /var/log/auth.log

# Sudo commands executed
grep "COMMAND=" /var/log/auth.log | tail -30

# Dangerous sudo commands
grep "COMMAND=" /var/log/auth.log | grep -E "(bash|sh|chmod|chown|passwd|useradd|usermod|visudo|rm -rf|dd if=)"

# Sudo to root
grep "COMMAND=" /var/log/auth.log | grep "USER=root" | tail -20

# su attempts
grep "su\[" /var/log/auth.log | tail -20
grep "su:.*FAILED\|su:.*failure" /var/log/auth.log
```

### User/Group Changes

```bash
# New user creation
grep "useradd\|adduser" /var/log/auth.log

# User modifications
grep "usermod" /var/log/auth.log

# Group changes
grep "groupadd\|groupmod\|gpasswd" /var/log/auth.log

# Password changes
grep "passwd\|chpasswd" /var/log/auth.log

# Account lockouts
grep "pam_tally2\|pam_faillock\|locked" /var/log/auth.log
```

---

## 3. System Log Analysis

### Syslog Analysis

```bash
# Critical and emergency messages
grep -E "emerg|alert|crit" /var/log/syslog | tail -30

# Error messages in the last 24 hours
awk -v date="$(date -d '24 hours ago' '+%b %d')" '$0 ~ date' /var/log/syslog | grep -i error

# Service start/stop events
grep -E "Started|Stopped|Failed" /var/log/syslog | tail -30

# Service failures
grep "Failed to start\|failed\|error" /var/log/syslog | grep -v "Failed password" | tail -30

# Systemd service crashes
journalctl --since "24 hours ago" -p err --no-pager | tail -50

# OOM killer events
grep -i "oom\|out of memory" /var/log/syslog /var/log/kern.log 2>/dev/null

# Disk errors
grep -i "error\|fault\|fail" /var/log/kern.log 2>/dev/null | grep -i "disk\|sd[a-z]\|nvme\|ata"
```

### Kernel Log Analysis

```bash
# Kernel security events
grep -i "segfault\|buffer overflow\|stack smash\|exploit\|rootkit" /var/log/kern.log 2>/dev/null

# USB device events (potential unauthorized devices)
grep -i "usb" /var/log/kern.log 2>/dev/null | tail -20

# Network interface changes
grep -i "link up\|link down\|promiscuous" /var/log/kern.log 2>/dev/null

# Firewall drops
grep -i "iptables\|nftables\|UFW BLOCK" /var/log/kern.log /var/log/syslog 2>/dev/null | tail -30

# Kernel module loading
grep -i "module.*loaded\|insmod\|modprobe" /var/log/kern.log 2>/dev/null

# AppArmor/SELinux denials
grep -i "apparmor.*DENIED\|avc:.*denied" /var/log/kern.log /var/log/syslog /var/log/audit/audit.log 2>/dev/null
```

---

## 4. Web Server Log Analysis

### Apache/Nginx Access Log Analysis

```bash
# Top requesting IPs
awk '{print $1}' /var/log/nginx/access.log 2>/dev/null | sort | uniq -c | sort -rn | head -20

# HTTP status code distribution
awk '{print $9}' /var/log/nginx/access.log 2>/dev/null | sort | uniq -c | sort -rn

# 404 errors (potential scanning)
grep '" 404 ' /var/log/nginx/access.log 2>/dev/null | awk '{print $7}' | sort | uniq -c | sort -rn | head -20

# 403 forbidden requests
grep '" 403 ' /var/log/nginx/access.log 2>/dev/null | awk '{print $1, $7}' | sort | uniq -c | sort -rn | head -20

# Potential SQL injection attempts
grep -iE "(union.*select|or.*1.*=.*1|drop.*table|insert.*into|select.*from|delete.*from)" /var/log/nginx/access.log /var/log/apache2/access.log 2>/dev/null

# Potential XSS attempts
grep -iE "(<script|javascript:|onerror=|onload=|alert\()" /var/log/nginx/access.log /var/log/apache2/access.log 2>/dev/null

# Potential path traversal
grep -E "(\.\.\/|\.\.\\\\|%2e%2e)" /var/log/nginx/access.log /var/log/apache2/access.log 2>/dev/null

# Potential command injection
grep -iE "(;.*ls|;.*cat|;.*id|;.*whoami|\|.*ls|\|.*cat|%7C|%3B)" /var/log/nginx/access.log /var/log/apache2/access.log 2>/dev/null

# Large request bodies (potential upload attacks)
awk '{if ($10 > 10000000) print $1, $7, $10}' /var/log/nginx/access.log 2>/dev/null

# Suspicious user agents
grep -iE "(sqlmap|nikto|nmap|dirbuster|gobuster|wfuzz|burp|masscan|scanner)" /var/log/nginx/access.log /var/log/apache2/access.log 2>/dev/null

# Requests per minute (detect DDoS)
awk '{print $4}' /var/log/nginx/access.log 2>/dev/null | cut -d: -f1-3 | sort | uniq -c | sort -rn | head -20
```

### Web Server Error Logs

```bash
# PHP errors
grep -i "fatal\|warning\|parse error" /var/log/nginx/error.log /var/log/apache2/error.log 2>/dev/null | tail -30

# Connection errors
grep -i "connection refused\|connection reset\|timeout" /var/log/nginx/error.log 2>/dev/null | tail -20

# Permission denied
grep -i "permission denied\|forbidden" /var/log/nginx/error.log /var/log/apache2/error.log 2>/dev/null | tail -20
```

---

## 5. Rootkit and Compromise Indicators

```bash
# Check for common rootkit indicators in logs
echo "=== Rootkit/Compromise Indicators ==="

# Unusual cron jobs
grep -i "cron" /var/log/syslog | grep -v "CRON\[" | tail -20
crontab -l 2>/dev/null
for user in $(cut -d: -f1 /etc/passwd); do
  jobs=$(crontab -u "$user" -l 2>/dev/null | grep -v "^#" | grep -v "^$")
  [ -n "$jobs" ] && echo "=== Cron for $user ===" && echo "$jobs"
done

# Check for unusual processes in logs
grep -i "segfault\|illegal instruction\|trace trap" /var/log/kern.log /var/log/syslog 2>/dev/null

# Check for unauthorized SSH keys being added
grep -i "authorized_keys\|ssh-rsa\|ssh-ed25519" /var/log/auth.log /var/log/syslog 2>/dev/null

# Check for file integrity violations
grep -i "AIDE\|tripwire\|ossec\|integrity" /var/log/syslog 2>/dev/null

# Check for reverse shell indicators
grep -iE "(bash -i|/dev/tcp|nc -e|ncat|socat|python.*import.*socket)" /var/log/syslog /var/log/auth.log 2>/dev/null

# History file tampering
for user_home in /home/* /root; do
  [ -f "${user_home}/.bash_history" ] || echo "MISSING: ${user_home}/.bash_history"
  [ -L "${user_home}/.bash_history" ] && echo "SYMLINK: ${user_home}/.bash_history (potential evasion)"
done
```

---

## 6. Journalctl Analysis

```bash
# Security-relevant journal entries
journalctl --since "24 hours ago" -p warning --no-pager | tail -100

# Failed services
journalctl --since "24 hours ago" | grep -i "failed\|error\|denied" | tail -50

# SSH-specific journal
journalctl -u sshd --since "24 hours ago" --no-pager

# Boot-related security events
journalctl -b -p err --no-pager

# Audit events via journal
journalctl _TRANSPORT=audit --since "24 hours ago" --no-pager | tail -50

# Specific user activity
journalctl _UID=1000 --since "24 hours ago" --no-pager | tail -30

# Kernel messages
journalctl -k --since "24 hours ago" --no-pager | grep -i "error\|warn\|denied\|violation"
```

---

## 7. Auditd Log Analysis

```bash
# Recent audit events
ausearch -ts recent 2>/dev/null | tail -50

# Failed system calls
ausearch --success no -ts today 2>/dev/null | tail -30

# File access events
ausearch -f /etc/shadow -ts today 2>/dev/null
ausearch -f /etc/passwd -ts today 2>/dev/null
ausearch -f /etc/sudoers -ts today 2>/dev/null

# User command execution
ausearch -ua <uid> -ts today 2>/dev/null | tail -30

# Privilege escalation events
ausearch -m USER_AUTH,USER_ACCT,USER_CMD -ts today 2>/dev/null | tail -30

# File modification events
ausearch -m CREATE,DELETE,MODIFY -ts today 2>/dev/null | tail -30

# Anomaly events
ausearch -m ANOM_PROMISCUOUS,ANOM_LOGIN_FAILURES,ANOM_ABEND -ts today 2>/dev/null

# Generate audit report
aureport --summary 2>/dev/null
aureport --auth 2>/dev/null | tail -20
aureport --login 2>/dev/null | tail -20
aureport --failed 2>/dev/null | tail -20
```

---

## 8. Comprehensive Log Forensics Workflow

```bash
#!/bin/bash
# Full log forensics analysis
REPORT_DIR="/var/log/forensics"
DATE=$(date +%Y%m%d-%H%M%S)
REPORT="${REPORT_DIR}/forensics-${DATE}.txt"
mkdir -p "$REPORT_DIR"
chmod 700 "$REPORT_DIR"

ALERT_COUNT=0
alert() {
  ALERT_COUNT=$((ALERT_COUNT + 1))
  echo "[ALERT #${ALERT_COUNT}] $1" | tee -a "$REPORT"
}

echo "=== Log Forensics Report ===" | tee "$REPORT"
echo "Host: $(hostname)" | tee -a "$REPORT"
echo "Date: $(date)" | tee -a "$REPORT"
echo "Analysis period: Last 24 hours" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# 1. Brute force detection
echo "--- Brute Force Analysis ---" | tee -a "$REPORT"
BRUTE_IPS=$(grep "Failed password" /var/log/auth.log 2>/dev/null | grep -oP 'from \K[\d.]+' | sort | uniq -c | sort -rn | awk '$1 > 10')
if [ -n "$BRUTE_IPS" ]; then
  alert "Brute force detected from:"
  echo "$BRUTE_IPS" | tee -a "$REPORT"
else
  echo "No brute force detected" | tee -a "$REPORT"
fi
echo "" | tee -a "$REPORT"

# 2. Successful attacks (failed then succeeded)
echo "--- Potential Compromises ---" | tee -a "$REPORT"
for ip in $(grep "Failed password" /var/log/auth.log 2>/dev/null | grep -oP 'from \K[\d.]+' | sort -u); do
  failures=$(grep "Failed password.*$ip" /var/log/auth.log 2>/dev/null | wc -l)
  success=$(grep "Accepted.*$ip" /var/log/auth.log 2>/dev/null | wc -l)
  if [ "$failures" -gt 10 ] && [ "$success" -gt 0 ]; then
    alert "IP $ip: $failures failures then $success successes"
  fi
done
echo "" | tee -a "$REPORT"

# 3. Privilege escalation
echo "--- Privilege Escalation ---" | tee -a "$REPORT"
PRIV_ESC=$(grep "NOT in sudoers\|authentication failure.*sudo\|COMMAND=.*bash\|COMMAND=.*sh -" /var/log/auth.log 2>/dev/null)
if [ -n "$PRIV_ESC" ]; then
  alert "Privilege escalation attempts:"
  echo "$PRIV_ESC" | tail -10 | tee -a "$REPORT"
fi
echo "" | tee -a "$REPORT"

# 4. Off-hours logins
echo "--- Off-Hours Logins ---" | tee -a "$REPORT"
grep "Accepted" /var/log/auth.log 2>/dev/null | awk '{split($3,t,":");if(t[1]<6||t[1]>22)print}' | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# 5. Web attack indicators
echo "--- Web Attack Indicators ---" | tee -a "$REPORT"
for log in /var/log/nginx/access.log /var/log/apache2/access.log; do
  [ -f "$log" ] || continue
  SQLI=$(grep -ciE "(union.*select|or.*1.*=.*1|drop.*table)" "$log" 2>/dev/null)
  XSS=$(grep -ciE "(<script|javascript:|onerror=)" "$log" 2>/dev/null)
  TRAV=$(grep -cE "(\.\.\/|%2e%2e)" "$log" 2>/dev/null)
  [ "$SQLI" -gt 0 ] && alert "SQL injection attempts in $log: $SQLI"
  [ "$XSS" -gt 0 ] && alert "XSS attempts in $log: $XSS"
  [ "$TRAV" -gt 0 ] && alert "Path traversal attempts in $log: $TRAV"
done
echo "" | tee -a "$REPORT"

# Summary
echo "=== Summary ===" | tee -a "$REPORT"
echo "Total alerts: $ALERT_COUNT" | tee -a "$REPORT"
chmod 600 "$REPORT"
echo "Report: $REPORT"

# Send alert if issues found
if [ "$ALERT_COUNT" -gt 0 ]; then
  mail -s "Security Alert: $ALERT_COUNT issues on $(hostname)" admin@example.com < "$REPORT" 2>/dev/null
fi
```

---

## 9. Log Retention and Monitoring

```bash
# Check log rotation configuration
cat /etc/logrotate.d/rsyslog 2>/dev/null

# Check available log space
df -h /var/log

# Verify log file integrity
ls -la /var/log/auth.log /var/log/syslog /var/log/kern.log 2>/dev/null
md5sum /var/log/auth.log /var/log/syslog /var/log/kern.log 2>/dev/null

# Real-time log monitoring
tail -f /var/log/auth.log | grep --line-buffered "Failed\|BREAK-IN\|Invalid\|error"

# Scheduled forensics cron
# /etc/cron.d/log-forensics
0 */4 * * * root /opt/claudeos/scripts/log-forensics.sh >> /var/log/forensics/cron.log 2>&1
```
