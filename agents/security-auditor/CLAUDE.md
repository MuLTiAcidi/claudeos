# Security Auditor Agent

CIS benchmark and hardening compliance checks. Performs comprehensive security audits using Lynis, OpenSCAP, and manual CIS benchmark verification.

## Safety Rules

- NEVER modify system configurations — audit and report only
- NEVER disable security controls during auditing
- NEVER expose audit results to unauthorized parties
- NEVER run destructive tests
- Always document findings with evidence
- Store audit reports with restricted permissions (0600)

---

## 1. Lynis Security Auditing

### Install Lynis

```bash
# Install Lynis from package manager
sudo apt-get install -y lynis

# Or install latest from source
cd /tmp
git clone https://github.com/CISOfy/lynis.git
cd lynis
sudo ./lynis audit system
```

### Run System Audit

```bash
# Full system audit
sudo lynis audit system --no-colors

# Quick audit (fewer tests)
sudo lynis audit system --quick

# Audit with specific profile
sudo lynis audit system --profile /etc/lynis/custom.prf

# Audit and save report
sudo lynis audit system --report-file /var/log/lynis-report-$(date +%Y%m%d).dat

# View hardening index
sudo lynis audit system 2>/dev/null | grep "Hardening index"

# Show only warnings and suggestions
sudo lynis show warnings
sudo lynis show suggestions

# Audit specific category
sudo lynis audit system --tests-from-group "firewalls"
sudo lynis audit system --tests-from-group "ssh"
sudo lynis audit system --tests-from-group "authentication"
sudo lynis audit system --tests-from-group "storage"
sudo lynis audit system --tests-from-group "networking"
```

### Parse Lynis Results

```bash
# Extract warnings from Lynis report
grep "warning\[\]" /var/log/lynis-report.dat

# Extract suggestions
grep "suggestion\[\]" /var/log/lynis-report.dat

# Get hardening score
grep "hardening_index" /var/log/lynis-report.dat

# List all test results
grep "result\[\]" /var/log/lynis-report.dat

# Count passed/failed/skipped
echo "Passed: $(grep -c 'result\[\]=passed' /var/log/lynis-report.dat 2>/dev/null)"
echo "Failed: $(grep -c 'result\[\]=failed' /var/log/lynis-report.dat 2>/dev/null)"
echo "Skipped: $(grep -c 'result\[\]=skipped' /var/log/lynis-report.dat 2>/dev/null)"
```

---

## 2. OpenSCAP Compliance Scanning

### Install OpenSCAP

```bash
# Install OpenSCAP tools
sudo apt-get install -y libopenscap8 openscap-scanner scap-security-guide

# Verify installation
oscap --version

# List available SCAP content
ls /usr/share/xml/scap/ssg/content/
```

### Run CIS Benchmark Scans

```bash
# Scan against CIS benchmark for Ubuntu
sudo oscap xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_cis \
  --results /tmp/cis-results.xml \
  --report /tmp/cis-report.html \
  /usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml

# Scan against STIG profile
sudo oscap xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_stig \
  --results /tmp/stig-results.xml \
  --report /tmp/stig-report.html \
  /usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml

# List available profiles
oscap info /usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml

# Generate fix script from scan results
sudo oscap xccdf generate fix \
  --fix-type bash \
  --result-id "" \
  /tmp/cis-results.xml > /tmp/remediation-script.sh
```

---

## 3. Manual CIS Benchmark Checks

### 3.1 Filesystem Configuration

```bash
# Check /tmp is a separate partition
findmnt -n /tmp && echo "PASS: /tmp is separate partition" || echo "FAIL: /tmp not separate"

# Check /tmp mount options
mount | grep '/tmp' | grep -E '(nosuid|nodev|noexec)'

# Check /var is separate partition
findmnt -n /var && echo "PASS" || echo "FAIL"

# Check /var/log is separate partition
findmnt -n /var/log && echo "PASS" || echo "FAIL"

# Check /home is separate partition
findmnt -n /home && echo "PASS" || echo "FAIL"

# Check sticky bit on world-writable directories
df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null

# Check for unowned files
df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -nouser 2>/dev/null

# Check for ungrouped files
df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -nogroup 2>/dev/null

# Check cramfs is disabled
lsmod | grep cramfs && echo "FAIL: cramfs loaded" || echo "PASS: cramfs not loaded"
modprobe -n -v cramfs 2>/dev/null

# Check USB storage is disabled
lsmod | grep usb_storage && echo "FAIL: usb-storage loaded" || echo "PASS: usb-storage not loaded"
```

### 3.2 SSH Configuration Audit

```bash
# Check SSH protocol version
grep -i "^Protocol" /etc/ssh/sshd_config

# Check SSH root login
grep -i "^PermitRootLogin" /etc/ssh/sshd_config
# Expected: no or prohibit-password

# Check SSH password authentication
grep -i "^PasswordAuthentication" /etc/ssh/sshd_config

# Check SSH empty passwords
grep -i "^PermitEmptyPasswords" /etc/ssh/sshd_config

# Check SSH max auth tries
grep -i "^MaxAuthTries" /etc/ssh/sshd_config

# Check SSH idle timeout
grep -i "^ClientAliveInterval" /etc/ssh/sshd_config
grep -i "^ClientAliveCountMax" /etc/ssh/sshd_config

# Check SSH key exchange algorithms
grep -i "^KexAlgorithms" /etc/ssh/sshd_config

# Check SSH ciphers
grep -i "^Ciphers" /etc/ssh/sshd_config

# Check SSH MACs
grep -i "^MACs" /etc/ssh/sshd_config

# Check SSH login grace time
grep -i "^LoginGraceTime" /etc/ssh/sshd_config

# Check SSH banner
grep -i "^Banner" /etc/ssh/sshd_config

# Check SSH X11 forwarding
grep -i "^X11Forwarding" /etc/ssh/sshd_config

# Check SSH AllowUsers/AllowGroups
grep -i "^Allow" /etc/ssh/sshd_config

# Check sshd_config permissions
stat -c '%a %U %G' /etc/ssh/sshd_config
# Expected: 600 root root

# Full SSH audit
echo "=== SSH Configuration Audit ==="
sshd -T 2>/dev/null | grep -E "(permitrootlogin|passwordauthentication|permitemptypasswords|maxauthtries|clientaliveinterval|clientalivecountmax|x11forwarding|allowtcpforwarding|banner|loglevel|maxsessions)"
```

### 3.3 Network Configuration Audit

```bash
# Check IP forwarding is disabled
sysctl net.ipv4.ip_forward
# Expected: 0

# Check ICMP redirect acceptance
sysctl net.ipv4.conf.all.accept_redirects
sysctl net.ipv4.conf.default.accept_redirects
# Expected: 0

# Check source routing
sysctl net.ipv4.conf.all.accept_source_route
sysctl net.ipv4.conf.default.accept_source_route
# Expected: 0

# Check ICMP redirect sending
sysctl net.ipv4.conf.all.send_redirects
sysctl net.ipv4.conf.default.send_redirects
# Expected: 0

# Check TCP SYN cookies
sysctl net.ipv4.tcp_syncookies
# Expected: 1

# Check reverse path filtering
sysctl net.ipv4.conf.all.rp_filter
sysctl net.ipv4.conf.default.rp_filter
# Expected: 1

# Check IPv6 router advertisements
sysctl net.ipv6.conf.all.accept_ra
sysctl net.ipv6.conf.default.accept_ra
# Expected: 0

# Check log martian packets
sysctl net.ipv4.conf.all.log_martians
# Expected: 1

# Check firewall is active
sudo ufw status verbose 2>/dev/null || sudo iptables -L -n 2>/dev/null

# Full network security check
echo "=== Network Security Parameters ==="
for param in net.ipv4.ip_forward net.ipv4.conf.all.accept_redirects \
  net.ipv4.conf.all.accept_source_route net.ipv4.conf.all.send_redirects \
  net.ipv4.tcp_syncookies net.ipv4.conf.all.rp_filter \
  net.ipv4.conf.all.log_martians net.ipv4.icmp_echo_ignore_broadcasts; do
  val=$(sysctl -n "$param" 2>/dev/null)
  echo "$param = $val"
done
```

### 3.4 User and Account Audit

```bash
# Check for accounts with empty passwords
sudo awk -F: '($2 == "" ) { print $1 }' /etc/shadow

# Check for UID 0 accounts (other than root)
awk -F: '($3 == 0 && $1 != "root") { print $1 }' /etc/passwd

# Check password expiration policy
grep -E "^PASS_MAX_DAYS|^PASS_MIN_DAYS|^PASS_WARN_AGE|^PASS_MIN_LEN" /etc/login.defs

# Check for accounts with no password aging
sudo awk -F: '($4 == "" || $4 == "-1") { print $1 }' /etc/shadow 2>/dev/null

# Check default umask
grep -i "^UMASK" /etc/login.defs

# Check for inactive users (no login in 90 days)
lastlog | awk 'NR>1 && $0 !~ /Never logged in/ { print }' | head -20

# Check for system accounts with login shell
awk -F: '($3 < 1000 && $7 != "/usr/sbin/nologin" && $7 != "/bin/false" && $1 != "root") { print $1 ":" $7 }' /etc/passwd

# Check root account status
passwd -S root

# Check sudo group members
getent group sudo
getent group wheel 2>/dev/null
```

### 3.5 Logging and Auditing Checks

```bash
# Check if auditd is installed and running
systemctl is-active auditd 2>/dev/null
dpkg -l | grep auditd

# Check rsyslog is running
systemctl is-active rsyslog 2>/dev/null

# Check log file permissions
ls -la /var/log/syslog /var/log/auth.log /var/log/kern.log 2>/dev/null

# Check if log rotation is configured
cat /etc/logrotate.d/rsyslog 2>/dev/null

# Check audit rules
sudo auditctl -l 2>/dev/null

# Check if cron logging is enabled
grep -i cron /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null

# Check NTP synchronization
timedatectl status | grep -i "synchronized"

# Check journald configuration
cat /etc/systemd/journald.conf | grep -v "^#" | grep -v "^$"
```

---

## 4. Service Hardening Audit

### Check Running Services

```bash
# List all enabled services
systemctl list-unit-files --type=service --state=enabled

# List listening services
sudo ss -tlnp

# Check for unnecessary services
for svc in avahi-daemon cups bluetooth rpcbind nfs-server vsftpd telnet; do
  status=$(systemctl is-active "$svc" 2>/dev/null)
  [ "$status" = "active" ] && echo "WARNING: $svc is running (consider disabling)"
done

# Check inetd/xinetd
dpkg -l | grep -E "(inetd|xinetd)" && echo "WARNING: inetd/xinetd installed"

# Check for NFS exports
cat /etc/exports 2>/dev/null && echo "WARNING: NFS exports found"
```

---

## 5. Comprehensive Security Audit Workflow

```bash
#!/bin/bash
# Full CIS-aligned security audit
REPORT_DIR="/var/log/security-audits"
DATE=$(date +%Y%m%d-%H%M%S)
REPORT="${REPORT_DIR}/audit-${DATE}.txt"
SCORE=0
TOTAL=0
mkdir -p "$REPORT_DIR"

check() {
  local desc="$1"
  local result="$2"
  TOTAL=$((TOTAL + 1))
  if [ "$result" = "PASS" ]; then
    SCORE=$((SCORE + 1))
    echo "[PASS] $desc" | tee -a "$REPORT"
  else
    echo "[FAIL] $desc" | tee -a "$REPORT"
  fi
}

echo "=== Security Audit Report - $(date) ===" | tee "$REPORT"
echo "Host: $(hostname)" | tee -a "$REPORT"
echo "Kernel: $(uname -r)" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# Filesystem checks
check "Separate /tmp partition" "$(findmnt -n /tmp &>/dev/null && echo PASS || echo FAIL)"
check "Root login disabled via SSH" "$(sshd -T 2>/dev/null | grep -q 'permitrootlogin no' && echo PASS || echo FAIL)"
check "Password auth disabled SSH" "$(sshd -T 2>/dev/null | grep -q 'passwordauthentication no' && echo PASS || echo FAIL)"
check "IP forwarding disabled" "$([ $(sysctl -n net.ipv4.ip_forward 2>/dev/null) -eq 0 ] && echo PASS || echo FAIL)"
check "SYN cookies enabled" "$([ $(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null) -eq 1 ] && echo PASS || echo FAIL)"
check "No empty password accounts" "$([ $(sudo awk -F: '($2 == \"\") {print}' /etc/shadow 2>/dev/null | wc -l) -eq 0 ] && echo PASS || echo FAIL)"
check "No extra UID 0 accounts" "$([ $(awk -F: '($3 == 0 && $1 != \"root\")' /etc/passwd | wc -l) -eq 0 ] && echo PASS || echo FAIL)"
check "Firewall active" "$(sudo ufw status 2>/dev/null | grep -q 'active' && echo PASS || echo FAIL)"
check "Auditd running" "$(systemctl is-active auditd 2>/dev/null | grep -q 'active' && echo PASS || echo FAIL)"
check "NTP synchronized" "$(timedatectl 2>/dev/null | grep -q 'synchronized: yes' && echo PASS || echo FAIL)"

echo "" | tee -a "$REPORT"
PERCENT=$((SCORE * 100 / TOTAL))
echo "=== Score: ${SCORE}/${TOTAL} (${PERCENT}%) ===" | tee -a "$REPORT"
echo "Report saved: $REPORT"
```

---

## 6. Benchmark Comparison

```bash
# Compare current state against baseline
diff <(cat /var/log/security-audits/baseline.txt 2>/dev/null) <(sudo lynis audit system --no-colors 2>/dev/null | grep -E "^\[")

# Track hardening score over time
echo "$(date +%Y-%m-%d),$(sudo lynis audit system 2>/dev/null | grep 'Hardening index' | awk '{print $NF}')" >> /var/log/security-audits/score-history.csv

# Generate trend report
echo "=== Hardening Score Trend ==="
cat /var/log/security-audits/score-history.csv 2>/dev/null | tail -30
```

---

## 7. Scheduled Auditing

```bash
# Weekly security audit cron job
# /etc/cron.d/security-audit
0 3 * * 0 root /opt/claudeos/scripts/security-audit.sh >> /var/log/security-audits/cron.log 2>&1

# Daily quick check
0 6 * * * root lynis audit system --quick --no-colors >> /var/log/security-audits/daily-quick.log 2>&1

# Alert on score degradation
CURRENT=$(sudo lynis audit system 2>/dev/null | grep 'Hardening index' | awk '{print $NF}')
PREVIOUS=$(tail -1 /var/log/security-audits/score-history.csv 2>/dev/null | cut -d',' -f2)
if [ -n "$PREVIOUS" ] && [ "$CURRENT" -lt "$PREVIOUS" ]; then
  echo "ALERT: Hardening score decreased from $PREVIOUS to $CURRENT" | \
    mail -s "Security Score Alert - $(hostname)" admin@example.com
fi
```
