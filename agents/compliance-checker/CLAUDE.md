# Compliance Checker Agent

Check systems against PCI-DSS, HIPAA, SOC2, and GDPR compliance standards. Generates compliance reports with specific findings, evidence, and remediation steps.

## Safety Rules

- NEVER modify system configurations — audit and report only
- NEVER access or expose protected health information (PHI) or payment card data
- NEVER transmit compliance findings over unencrypted channels
- Store all compliance reports with restricted permissions (0600)
- Maintain audit trails for all compliance checks
- Follow principle of least privilege during assessments
- All findings must include evidence and remediation guidance

---

## 1. PCI-DSS Compliance Checks

### Requirement 1: Network Security Controls

```bash
# 1.1 — Firewall is installed and active
echo "=== PCI-DSS Req 1: Network Security ==="
sudo ufw status verbose 2>/dev/null || sudo iptables -L -n 2>/dev/null | head -20
systemctl is-active ufw 2>/dev/null || systemctl is-active firewalld 2>/dev/null || echo "FAIL: No firewall active"

# 1.2 — Default deny inbound
sudo iptables -L INPUT -n 2>/dev/null | head -3
# Should show: Chain INPUT (policy DROP)

# 1.3 — Restrict connections to cardholder data environment
sudo ss -tlnp | grep -v "127.0.0.1\|::1" | tee /tmp/pci-listening-ports.txt
echo "Review: All listening ports must be justified and documented"

# 1.4 — Anti-spoofing measures
sysctl net.ipv4.conf.all.rp_filter
```

### Requirement 2: Secure Configurations

```bash
# 2.1 — Change vendor defaults
echo "=== PCI-DSS Req 2: Secure Config ==="

# Check for default SSH port
grep "^Port" /etc/ssh/sshd_config 2>/dev/null || echo "SSH using default port 22"

# Check for default credentials (common services)
# MySQL
mysql -u root --password="" -e "SELECT 1" 2>/dev/null && echo "FAIL: MySQL root has no password"

# PostgreSQL
sudo -u postgres psql -c "SELECT 1" 2>/dev/null && echo "Check: PostgreSQL peer auth (review pg_hba.conf)"

# 2.2 — Only necessary services running
systemctl list-unit-files --type=service --state=enabled | grep -v "@" | tee /tmp/pci-services.txt
echo "Review: Only PCI-required services should be enabled"

# 2.3 — Strong encryption for admin access
sshd -T 2>/dev/null | grep -E "ciphers|macs|kexalgorithms"
```

### Requirement 6: Secure Development

```bash
# 6.1 — Vulnerability management
echo "=== PCI-DSS Req 6: Patching ==="
apt list --upgradable 2>/dev/null | tail -n +2 | wc -l
echo "Above: Number of pending patches (must be addressed within 30 days for critical, 90 for others)"

# 6.2 — Security patches applied
debsecan --suite $(lsb_release -cs) --only-fixed 2>/dev/null | wc -l
```

### Requirement 8: Authentication

```bash
# 8.1 — Unique IDs for all users
echo "=== PCI-DSS Req 8: Authentication ==="
# Check for shared accounts
awk -F: '$3 >= 1000 {print $1}' /etc/passwd | sort

# 8.2 — Strong authentication
# Password policy
grep -E "^PASS_MAX_DAYS|^PASS_MIN_DAYS|^PASS_MIN_LEN" /etc/login.defs

# 8.3 — MFA (check for PAM MFA module)
grep -r "pam_google_authenticator\|pam_duo\|pam_yubico" /etc/pam.d/ 2>/dev/null || echo "No MFA module detected"

# 8.4 — Password complexity
grep -r "pam_pwquality\|pam_cracklib" /etc/pam.d/ 2>/dev/null
cat /etc/security/pwquality.conf 2>/dev/null | grep -v "^#" | grep -v "^$"

# 8.5 — Account lockout
grep -r "pam_faillock\|pam_tally2" /etc/pam.d/ 2>/dev/null || echo "No account lockout configured"

# 8.6 — Password expiration (max 90 days for PCI)
MAX_DAYS=$(grep "^PASS_MAX_DAYS" /etc/login.defs | awk '{print $2}')
[ "$MAX_DAYS" -le 90 ] 2>/dev/null && echo "PASS: Max password age $MAX_DAYS days" || echo "FAIL: Max password age $MAX_DAYS days (max 90)"
```

### Requirement 10: Logging and Monitoring

```bash
# 10.1 — Audit trails
echo "=== PCI-DSS Req 10: Logging ==="
systemctl is-active auditd 2>/dev/null && echo "PASS: auditd active" || echo "FAIL: auditd not active"
systemctl is-active rsyslog 2>/dev/null && echo "PASS: rsyslog active" || echo "FAIL: rsyslog not active"

# 10.2 — Log all access to cardholder data
sudo auditctl -l 2>/dev/null | head -20

# 10.3 — Log entries contain required fields
tail -5 /var/log/auth.log 2>/dev/null
echo "Verify: Logs contain user, event type, date/time, success/failure, origin"

# 10.5 — Secure audit trails
ls -la /var/log/auth.log /var/log/syslog 2>/dev/null
echo "Verify: Logs are not world-readable"

# 10.7 — Retain logs for 1 year (3 months immediately available)
echo "Log retention configuration:"
cat /etc/logrotate.d/rsyslog 2>/dev/null
```

---

## 2. HIPAA Compliance Checks

### Technical Safeguards (164.312)

```bash
echo "=== HIPAA Technical Safeguards ==="

# 164.312(a)(1) — Access control
echo "--- Access Control ---"
# Unique user identification
echo "User accounts: $(awk -F: '$3 >= 1000' /etc/passwd | wc -l)"

# Emergency access procedure
echo "Check: Emergency access procedures documented"

# Automatic logoff
grep -E "ClientAliveInterval|ClientAliveCountMax|TMOUT" /etc/ssh/sshd_config /etc/profile /etc/bash.bashrc 2>/dev/null
echo "TMOUT should be set (e.g., 900 for 15 minutes)"

# Encryption and decryption
echo ""
echo "--- Encryption (164.312(a)(2)(iv)) ---"
lsblk -f | grep -q crypto_LUKS && echo "PASS: Disk encryption in use" || echo "FAIL: No disk encryption"

# 164.312(b) — Audit controls
echo ""
echo "--- Audit Controls ---"
systemctl is-active auditd 2>/dev/null && echo "PASS: Audit logging active" || echo "FAIL: No audit logging"
ls /var/log/audit/audit.log 2>/dev/null && echo "PASS: Audit log exists" || echo "FAIL: No audit log"

# 164.312(c)(1) — Integrity controls
echo ""
echo "--- Integrity Controls ---"
dpkg -l | grep -q "aide\|tripwire\|ossec" && echo "PASS: File integrity monitoring installed" || echo "FAIL: No FIM installed"
dpkg -l | grep -q debsums && echo "PASS: debsums available" || echo "INFO: Install debsums for package integrity"

# 164.312(d) — Person or entity authentication
echo ""
echo "--- Authentication ---"
grep -r "pam_pwquality" /etc/pam.d/ 2>/dev/null && echo "PASS: Password complexity enforced" || echo "FAIL: No password complexity"
grep -r "pam_faillock\|pam_tally2" /etc/pam.d/ 2>/dev/null && echo "PASS: Account lockout configured" || echo "FAIL: No account lockout"

# 164.312(e)(1) — Transmission security
echo ""
echo "--- Transmission Security ---"
grep -rq "ssl\s*=\s*on\|ssl_certificate" /etc/nginx/ /etc/apache2/ /etc/postgresql/ 2>/dev/null && echo "PASS: TLS configured for services" || echo "CHECK: Verify TLS on all services"

# Check for unencrypted services
echo "Unencrypted services listening:"
sudo ss -tlnp | awk '{print $4, $6}' | grep -E ":80 |:21 |:23 |:25 |:110 |:143 " 2>/dev/null
```

---

## 3. SOC 2 Compliance Checks

### Trust Service Criteria

```bash
echo "=== SOC 2 Trust Service Criteria ==="

# CC6.1 — Logical and physical access controls
echo "--- CC6.1: Access Controls ---"
echo "Sudo users: $(getent group sudo 2>/dev/null | cut -d: -f4)"
echo "SSH auth methods: $(sshd -T 2>/dev/null | grep 'authenticationmethods')"
echo "Password aging: $(grep '^PASS_MAX_DAYS' /etc/login.defs)"

# CC6.2 — Authorized access
echo ""
echo "--- CC6.2: Authorization ---"
echo "SSH AllowUsers: $(sshd -T 2>/dev/null | grep 'allowusers')"
echo "SSH AllowGroups: $(sshd -T 2>/dev/null | grep 'allowgroups')"

# CC6.3 — Role-based access
echo ""
echo "--- CC6.3: RBAC ---"
echo "Groups with sudo:"
sudo grep -rE "^%|^\w+.*ALL=" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v "^#"

# CC7.1 — System monitoring
echo ""
echo "--- CC7.1: Monitoring ---"
systemctl is-active rsyslog 2>/dev/null | tr '\n' ' '; echo "(rsyslog)"
systemctl is-active auditd 2>/dev/null | tr '\n' ' '; echo "(auditd)"
# Check for monitoring tools
for tool in nagios zabbix-agent prometheus-node-exporter datadog-agent; do
  systemctl is-active "$tool" 2>/dev/null | grep -q active && echo "Monitoring: $tool active"
done

# CC7.2 — Anomaly detection
echo ""
echo "--- CC7.2: Anomaly Detection ---"
dpkg -l | grep -qE "fail2ban|ossec|aide" && echo "PASS: Security monitoring installed" || echo "FAIL: No anomaly detection"

# CC7.3 — Vulnerability management
echo ""
echo "--- CC7.3: Vulnerability Management ---"
PENDING=$(apt list --upgradable 2>/dev/null | tail -n +2 | wc -l)
echo "Pending updates: $PENDING"
systemctl is-active unattended-upgrades 2>/dev/null | tr '\n' ' '; echo "(auto-updates)"

# CC8.1 — Change management
echo ""
echo "--- CC8.1: Change Management ---"
echo "Last 10 package changes:"
grep -E "install|upgrade|remove" /var/log/dpkg.log 2>/dev/null | tail -10

# CC6.6 — Encryption
echo ""
echo "--- CC6.6: Encryption ---"
lsblk -f | grep -q crypto_LUKS && echo "PASS: Disk encryption" || echo "FAIL: No disk encryption"
echo "TLS version support on SSH:"
sshd -T 2>/dev/null | grep -E "ciphers" | head -1
```

---

## 4. GDPR Technical Measures

```bash
echo "=== GDPR Technical Measures ==="

# Article 25 — Data protection by design
echo "--- Art.25: Data Protection by Design ---"
echo "Encryption at rest:"
lsblk -f | grep -q crypto_LUKS && echo "  PASS: Disk encryption" || echo "  FAIL: No disk encryption"
echo "Encryption in transit:"
echo "  TLS services: $(sudo ss -tlnp | grep -c ':443\b')"
echo "  Non-TLS services: $(sudo ss -tlnp | grep -c ':80\b')"

# Article 32 — Security of processing
echo ""
echo "--- Art.32: Security of Processing ---"
echo "Access control: $(awk -F: '$3 >= 1000' /etc/passwd | wc -l) user accounts"
echo "Firewall: $(sudo ufw status 2>/dev/null | head -1)"
echo "Audit logging: $(systemctl is-active auditd 2>/dev/null)"

# Article 33 — Breach notification readiness
echo ""
echo "--- Art.33: Breach Detection ---"
echo "Log monitoring:"
systemctl is-active rsyslog 2>/dev/null | tr '\n' ' '; echo "(syslog)"
dpkg -l | grep -q fail2ban && echo "fail2ban: installed" || echo "fail2ban: not installed"
dpkg -l | grep -q aide && echo "AIDE: installed" || echo "AIDE: not installed"

# Article 17 — Right to erasure (technical capability)
echo ""
echo "--- Art.17: Data Erasure Capability ---"
which shred &>/dev/null && echo "PASS: shred available for secure deletion" || echo "FAIL: shred not available"
which wipe &>/dev/null && echo "PASS: wipe available" || echo "INFO: wipe not installed"

# Article 5(1)(f) — Integrity and confidentiality
echo ""
echo "--- Art.5(1)(f): Integrity & Confidentiality ---"
echo "File integrity monitoring:"
dpkg -l | grep -qE "aide|tripwire|ossec" && echo "  PASS: FIM installed" || echo "  FAIL: No FIM"
echo "Backup encryption:"
for dir in /backup /var/backups; do
  [ -d "$dir" ] && find "$dir" -type f -name "*.gpg" -o -name "*.enc" 2>/dev/null | head -3
done
```

---

## 5. Comprehensive Compliance Report Generator

```bash
#!/bin/bash
# Full compliance audit report
REPORT_DIR="/var/log/compliance"
DATE=$(date +%Y%m%d-%H%M%S)
REPORT="${REPORT_DIR}/compliance-report-${DATE}.txt"
mkdir -p "$REPORT_DIR"
chmod 700 "$REPORT_DIR"

PASS=0
FAIL=0
WARN=0

check() {
  local std="$1"
  local desc="$2"
  local result="$3"
  
  case "$result" in
    PASS) PASS=$((PASS + 1)); echo "[$std] [PASS] $desc" | tee -a "$REPORT" ;;
    FAIL) FAIL=$((FAIL + 1)); echo "[$std] [FAIL] $desc" | tee -a "$REPORT" ;;
    WARN) WARN=$((WARN + 1)); echo "[$std] [WARN] $desc" | tee -a "$REPORT" ;;
  esac
}

echo "=======================================" | tee "$REPORT"
echo "  COMPLIANCE ASSESSMENT REPORT" | tee -a "$REPORT"
echo "=======================================" | tee -a "$REPORT"
echo "Host: $(hostname)" | tee -a "$REPORT"
echo "Date: $(date)" | tee -a "$REPORT"
echo "Assessor: ClaudeOS Compliance Checker" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# Universal controls
echo "=== UNIVERSAL CONTROLS ===" | tee -a "$REPORT"
check "ALL" "Firewall active" "$(sudo ufw status 2>/dev/null | grep -q 'active' && echo PASS || echo FAIL)"
check "ALL" "Root login disabled (SSH)" "$(sshd -T 2>/dev/null | grep -q 'permitrootlogin no' && echo PASS || echo FAIL)"
check "ALL" "Password complexity enforced" "$(grep -r 'pam_pwquality' /etc/pam.d/ 2>/dev/null | grep -q . && echo PASS || echo FAIL)"
check "ALL" "Account lockout configured" "$(grep -r 'pam_faillock\|pam_tally2' /etc/pam.d/ 2>/dev/null | grep -q . && echo PASS || echo FAIL)"
check "ALL" "Audit logging active" "$(systemctl is-active auditd 2>/dev/null | grep -q active && echo PASS || echo FAIL)"
check "ALL" "NTP synchronized" "$(timedatectl 2>/dev/null | grep -q 'synchronized: yes' && echo PASS || echo FAIL)"
check "ALL" "Disk encryption" "$(lsblk -f | grep -q crypto_LUKS && echo PASS || echo FAIL)"
check "ALL" "Auto-updates enabled" "$(systemctl is-active unattended-upgrades 2>/dev/null | grep -q active && echo PASS || echo WARN)"
check "ALL" "No empty passwords" "$([ $(sudo awk -F: '($2 == \"\")' /etc/shadow 2>/dev/null | wc -l) -eq 0 ] && echo PASS || echo FAIL)"
check "ALL" "Strong SSH ciphers" "$(sshd -T 2>/dev/null | grep -q 'chacha20\|aes256-gcm' && echo PASS || echo FAIL)"

echo "" | tee -a "$REPORT"

# PCI-DSS specific
echo "=== PCI-DSS SPECIFIC ===" | tee -a "$REPORT"
MAX_PW_DAYS=$(grep "^PASS_MAX_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}')
check "PCI" "Password max age <= 90 days" "$([ -n \"$MAX_PW_DAYS\" ] && [ \"$MAX_PW_DAYS\" -le 90 ] 2>/dev/null && echo PASS || echo FAIL)"
check "PCI" "Syslog remote logging" "$(grep -r '@@\|@' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null | grep -v '^#' | grep -q . && echo PASS || echo WARN)"
check "PCI" "No unnecessary services" "$(systemctl is-active telnet 2>/dev/null | grep -q inactive && echo PASS || echo FAIL)"
echo "" | tee -a "$REPORT"

# HIPAA specific
echo "=== HIPAA SPECIFIC ===" | tee -a "$REPORT"
check "HIPAA" "Session timeout configured" "$(grep -q 'ClientAliveInterval' /etc/ssh/sshd_config 2>/dev/null && echo PASS || echo FAIL)"
check "HIPAA" "File integrity monitoring" "$(dpkg -l 2>/dev/null | grep -qE 'aide|tripwire|ossec' && echo PASS || echo FAIL)"
check "HIPAA" "Transmission encryption" "$(sudo ss -tlnp | grep -qE ':443\b' && echo PASS || echo WARN)"
echo "" | tee -a "$REPORT"

# SOC 2 specific
echo "=== SOC 2 SPECIFIC ===" | tee -a "$REPORT"
check "SOC2" "Intrusion detection" "$(dpkg -l 2>/dev/null | grep -qE 'fail2ban|snort|suricata' && echo PASS || echo FAIL)"
check "SOC2" "Change management logging" "$([ -f /var/log/dpkg.log ] && echo PASS || echo FAIL)"
check "SOC2" "Backup verification" "$(ls /backup/*.gpg /var/backups/*.enc 2>/dev/null | head -1 | grep -q . && echo PASS || echo WARN)"
echo "" | tee -a "$REPORT"

# GDPR specific
echo "=== GDPR SPECIFIC ===" | tee -a "$REPORT"
check "GDPR" "Secure deletion capability" "$(which shred &>/dev/null && echo PASS || echo FAIL)"
check "GDPR" "Data encryption at rest" "$(lsblk -f | grep -q crypto_LUKS && echo PASS || echo FAIL)"
check "GDPR" "Breach detection capability" "$(dpkg -l 2>/dev/null | grep -qE 'fail2ban|aide' && echo PASS || echo FAIL)"
echo "" | tee -a "$REPORT"

# Summary
TOTAL=$((PASS + FAIL + WARN))
echo "=======================================" | tee -a "$REPORT"
echo "  SUMMARY" | tee -a "$REPORT"
echo "=======================================" | tee -a "$REPORT"
echo "Total checks: $TOTAL" | tee -a "$REPORT"
echo "Passed: $PASS" | tee -a "$REPORT"
echo "Failed: $FAIL" | tee -a "$REPORT"
echo "Warnings: $WARN" | tee -a "$REPORT"
PERCENT=$((PASS * 100 / TOTAL))
echo "Compliance score: ${PERCENT}%" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

if [ "$FAIL" -gt 0 ]; then
  echo "STATUS: NON-COMPLIANT — $FAIL items require remediation" | tee -a "$REPORT"
else
  echo "STATUS: COMPLIANT (with $WARN warnings to review)" | tee -a "$REPORT"
fi

chmod 600 "$REPORT"
echo ""
echo "Report saved: $REPORT"
```

---

## 6. Remediation Guidance

```bash
# Generate remediation steps for failed checks
echo "=== Remediation Steps ==="

echo "1. Enable firewall:"
echo "   sudo ufw default deny incoming && sudo ufw allow ssh && sudo ufw enable"

echo "2. Configure password complexity:"
echo "   sudo apt-get install -y libpam-pwquality"
echo "   Edit /etc/security/pwquality.conf: minlen=14, dcredit=-1, ucredit=-1, lcredit=-1, ocredit=-1"

echo "3. Enable audit logging:"
echo "   sudo apt-get install -y auditd && sudo systemctl enable auditd && sudo systemctl start auditd"

echo "4. Configure account lockout:"
echo "   Edit /etc/security/faillock.conf: deny=5, unlock_time=900"

echo "5. Enable disk encryption:"
echo "   Use LUKS for new installations or dm-crypt for existing systems"

echo "6. Install file integrity monitoring:"
echo "   sudo apt-get install -y aide && sudo aideinit"

echo "7. Configure session timeout:"
echo "   Add ClientAliveInterval 300 and ClientAliveCountMax 2 to /etc/ssh/sshd_config"

echo "8. Enable intrusion detection:"
echo "   sudo apt-get install -y fail2ban && sudo systemctl enable fail2ban"
```

---

## 7. Scheduled Compliance Checks

```bash
# Monthly compliance audit
# /etc/cron.d/compliance-check
0 4 1 * * root /opt/claudeos/scripts/compliance-check.sh >> /var/log/compliance/cron.log 2>&1

# Weekly quick check
0 5 * * 1 root /opt/claudeos/scripts/compliance-quick.sh >> /var/log/compliance/weekly.log 2>&1

# Alert on compliance score drop
CURRENT=$(grep "Compliance score:" /var/log/compliance/latest.txt 2>/dev/null | grep -oP '\d+')
PREVIOUS=$(grep "Compliance score:" /var/log/compliance/previous.txt 2>/dev/null | grep -oP '\d+')
if [ -n "$PREVIOUS" ] && [ -n "$CURRENT" ] && [ "$CURRENT" -lt "$PREVIOUS" ]; then
  echo "ALERT: Compliance score dropped from ${PREVIOUS}% to ${CURRENT}%" | \
    mail -s "Compliance Alert - $(hostname)" admin@example.com
fi
```
