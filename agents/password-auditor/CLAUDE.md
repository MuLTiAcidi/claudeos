# Password Auditor Agent

Test password strength across system accounts. Audits password policies, checks for weak passwords, and enforces password hygiene using industry-standard tools.

## Safety Rules

- NEVER store or log cracked passwords in plaintext
- NEVER transmit password hashes or cracked passwords over the network
- NEVER modify user passwords without explicit authorization
- NEVER run password cracking against systems you do not own
- Always restrict access to audit results (chmod 0600)
- Delete temporary wordlists and hash files after auditing
- All operations require root or sudo privileges

---

## 1. Password Policy Analysis

### Check System Password Policies

```bash
# Check PAM password quality settings
cat /etc/pam.d/common-password
grep -v "^#" /etc/pam.d/common-password | grep -v "^$"

# Check password aging defaults
grep -E "^PASS_MAX_DAYS|^PASS_MIN_DAYS|^PASS_WARN_AGE|^PASS_MIN_LEN" /etc/login.defs

# Check individual user password aging
sudo chage -l <username>

# List all users and their password aging info
for user in $(awk -F: '($3 >= 1000 && $7 != "/usr/sbin/nologin" && $7 != "/bin/false") {print $1}' /etc/passwd); do
  echo "=== $user ==="
  sudo chage -l "$user" 2>/dev/null
done

# Check PAM password complexity (pam_pwquality)
grep -r "pam_pwquality" /etc/pam.d/ 2>/dev/null
cat /etc/security/pwquality.conf 2>/dev/null | grep -v "^#" | grep -v "^$"

# Check pam_cracklib settings (older systems)
grep -r "pam_cracklib" /etc/pam.d/ 2>/dev/null

# Check account lockout policy
grep -r "pam_tally2\|pam_faillock" /etc/pam.d/ 2>/dev/null
cat /etc/security/faillock.conf 2>/dev/null | grep -v "^#" | grep -v "^$"
```

### Check for Password Policy Compliance

```bash
# Check if password complexity is enforced
echo "=== Password Policy Compliance ==="

# Minimum length
MIN_LEN=$(grep "^PASS_MIN_LEN" /etc/login.defs 2>/dev/null | awk '{print $2}')
echo "Min length (login.defs): ${MIN_LEN:-NOT SET}"

PWQUALITY_MINLEN=$(grep "minlen" /etc/security/pwquality.conf 2>/dev/null | grep -v "^#" | awk -F= '{print $2}' | tr -d ' ')
echo "Min length (pwquality): ${PWQUALITY_MINLEN:-NOT SET}"

# Max age
MAX_DAYS=$(grep "^PASS_MAX_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}')
echo "Max age (days): ${MAX_DAYS:-NOT SET}"

# Min age
MIN_DAYS=$(grep "^PASS_MIN_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}')
echo "Min age (days): ${MIN_DAYS:-NOT SET}"

# Warning age
WARN_AGE=$(grep "^PASS_WARN_AGE" /etc/login.defs 2>/dev/null | awk '{print $2}')
echo "Warning (days): ${WARN_AGE:-NOT SET}"

# Password history
grep "remember=" /etc/pam.d/common-password 2>/dev/null
```

---

## 2. Shadow File Analysis

### Analyze Password Hashes

```bash
# Check hash algorithm in use
sudo awk -F: '{print $1, substr($2,1,3)}' /etc/shadow 2>/dev/null | while read user hash; do
  case "$hash" in
    '$1$') algo="MD5 (WEAK)" ;;
    '$2a'|'$2b'|'$2y') algo="Blowfish" ;;
    '$5$') algo="SHA-256" ;;
    '$6$') algo="SHA-512 (recommended)" ;;
    '$y$') algo="yescrypt (strong)" ;;
    '!!'|'!') algo="LOCKED" ;;
    '*') algo="DISABLED" ;;
    '') algo="NO PASSWORD (CRITICAL)" ;;
    *) algo="UNKNOWN" ;;
  esac
  echo "$user: $algo"
done

# Find accounts with empty passwords
sudo awk -F: '($2 == "") {print $1 " has EMPTY password"}' /etc/shadow

# Find accounts with locked passwords
sudo awk -F: '($2 ~ /^!/) {print $1 " is LOCKED"}' /etc/shadow

# Find accounts with disabled passwords
sudo awk -F: '($2 == "*") {print $1 " is DISABLED"}' /etc/shadow

# Check for accounts using weak hash algorithms (MD5)
sudo awk -F: '($2 ~ /^\$1\$/) {print $1 " uses MD5 (UPGRADE NEEDED)"}' /etc/shadow

# Check accounts with password never expires
sudo awk -F: '($5 == "" || $5 == "99999") {print $1 " password never expires"}' /etc/shadow

# Find accounts with expired passwords
sudo awk -F: '{if ($3 != "" && $5 != "" && $5 != "99999") { age=(systime()/86400)-$3; if (age > $5) print $1 " password EXPIRED"}}' /etc/shadow 2>/dev/null
```

---

## 3. John the Ripper Password Testing

### Install John the Ripper

```bash
# Install from package manager
sudo apt-get install -y john

# Or install jumbo version for more features
sudo apt-get install -y build-essential libssl-dev libgmp-dev
cd /tmp
git clone https://github.com/openwall/john.git
cd john/src
./configure && make -s clean && make -sj$(nproc)
sudo cp ../run/john /usr/local/bin/
```

### Extract and Test Password Hashes

```bash
# Combine passwd and shadow for John
sudo unshadow /etc/passwd /etc/shadow > /tmp/audit-hashes.txt
chmod 600 /tmp/audit-hashes.txt

# Quick dictionary attack (default wordlist)
sudo john /tmp/audit-hashes.txt

# Use a specific wordlist
sudo john --wordlist=/usr/share/wordlists/rockyou.txt /tmp/audit-hashes.txt

# Single crack mode (uses account info for guessing)
sudo john --single /tmp/audit-hashes.txt

# Incremental mode (brute force — short passwords only)
sudo john --incremental --max-length=8 /tmp/audit-hashes.txt

# Show cracked passwords
sudo john --show /tmp/audit-hashes.txt

# Show cracked password count
sudo john --show /tmp/audit-hashes.txt | tail -1

# Test with rules (password mutations)
sudo john --wordlist=/usr/share/wordlists/rockyou.txt --rules /tmp/audit-hashes.txt

# Run for limited time (5 minutes)
timeout 300 sudo john --wordlist=/usr/share/wordlists/rockyou.txt /tmp/audit-hashes.txt

# Test specific user
sudo john --users=<username> /tmp/audit-hashes.txt

# Clean up sensitive files
shred -u /tmp/audit-hashes.txt
```

---

## 4. Hashcat Password Testing

### Install Hashcat

```bash
# Install hashcat
sudo apt-get install -y hashcat

# Check available hash modes
hashcat --help | grep -i "sha512\|sha256\|md5\|bcrypt\|yescrypt"
```

### Run Password Audits

```bash
# Extract hashes for hashcat (SHA-512 crypt format = mode 1800)
sudo awk -F: '($2 ~ /^\$6\$/) {print $2}' /etc/shadow > /tmp/hashes.txt
chmod 600 /tmp/hashes.txt

# Dictionary attack with hashcat
hashcat -m 1800 /tmp/hashes.txt /usr/share/wordlists/rockyou.txt

# Dictionary attack with rules
hashcat -m 1800 /tmp/hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Brute force short passwords (up to 6 chars)
hashcat -m 1800 -a 3 /tmp/hashes.txt '?a?a?a?a?a?a'

# Show cracked results
hashcat -m 1800 /tmp/hashes.txt --show

# For MD5 crypt (mode 500)
sudo awk -F: '($2 ~ /^\$1\$/) {print $2}' /etc/shadow > /tmp/md5-hashes.txt
hashcat -m 500 /tmp/md5-hashes.txt /usr/share/wordlists/rockyou.txt

# For SHA-256 crypt (mode 7400)
sudo awk -F: '($2 ~ /^\$5\$/) {print $2}' /etc/shadow > /tmp/sha256-hashes.txt
hashcat -m 7400 /tmp/sha256-hashes.txt /usr/share/wordlists/rockyou.txt

# Clean up
shred -u /tmp/hashes.txt /tmp/md5-hashes.txt /tmp/sha256-hashes.txt 2>/dev/null
```

---

## 5. cracklib Password Quality Testing

### Install and Use cracklib

```bash
# Install cracklib
sudo apt-get install -y cracklib-runtime libpam-cracklib

# Test a password (interactive — pipe in the password)
echo "password123" | cracklib-check
echo "Tr0ub4dor&3" | cracklib-check
echo "correct horse battery staple" | cracklib-check

# Test multiple passwords from a file
while read -r pw; do
  result=$(echo "$pw" | cracklib-check)
  echo "$result"
done < /tmp/test-passwords.txt

# Verify cracklib dictionary is installed
ls /usr/share/cracklib/
```

---

## 6. PAM Password Policy Configuration Audit

### Audit PAM Configuration

```bash
# Check all PAM password-related configs
echo "=== PAM Password Configuration ==="

# common-password (Debian/Ubuntu)
echo "--- /etc/pam.d/common-password ---"
grep -v "^#" /etc/pam.d/common-password | grep -v "^$"

# common-auth
echo "--- /etc/pam.d/common-auth ---"
grep -v "^#" /etc/pam.d/common-auth | grep -v "^$"

# Check pwquality configuration
echo "--- /etc/security/pwquality.conf ---"
if [ -f /etc/security/pwquality.conf ]; then
  grep -v "^#" /etc/security/pwquality.conf | grep -v "^$"
else
  echo "NOT FOUND — pwquality not configured"
fi

# Check for account lockout configuration
echo "--- Account Lockout ---"
grep -r "pam_faillock\|pam_tally2\|deny=" /etc/pam.d/ 2>/dev/null
if [ -f /etc/security/faillock.conf ]; then
  grep -v "^#" /etc/security/faillock.conf | grep -v "^$"
fi

# Check password history
echo "--- Password History ---"
grep "remember=" /etc/pam.d/common-password 2>/dev/null || echo "No password history enforced"
```

### Recommended PAM Configuration

```bash
# Example pwquality.conf for strong passwords
cat <<'EOF'
# /etc/security/pwquality.conf
minlen = 14
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
minclass = 3
maxrepeat = 3
maxclassrepeat = 4
gecoscheck = 1
dictcheck = 1
usercheck = 1
enforcing = 1
retry = 3
EOF

# Example common-password PAM line
# password requisite pam_pwquality.so retry=3 minlen=14 dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1
# password sufficient pam_unix.so sha512 shadow remember=12 rounds=65536
```

---

## 7. Service Account Password Audit

### Check Service Account Security

```bash
# List service accounts with login shells
awk -F: '($3 < 1000 && $3 != 0 && $7 != "/usr/sbin/nologin" && $7 != "/bin/false") {
  print "WARNING: " $1 " (UID " $3 ") has shell: " $7
}' /etc/passwd

# Check for service accounts with password set
sudo awk -F: '($3 < 1000 && $3 != 0 && $2 != "!" && $2 != "*" && $2 != "!!") {
  print "WARNING: " $1 " has a password set"
}' /etc/shadow

# Check database user passwords
# MySQL
mysql -e "SELECT user, host, plugin FROM mysql.user WHERE plugin='mysql_native_password';" 2>/dev/null

# PostgreSQL
sudo -u postgres psql -c "SELECT usename, passwd IS NOT NULL as has_password FROM pg_shadow;" 2>/dev/null

# Check for default/weak credentials in common services
echo "=== Checking Default Credentials ==="
# Redis (no auth by default)
redis-cli ping 2>/dev/null && echo "WARNING: Redis accessible without password"

# MongoDB (no auth by default)
mongo --eval "db.adminCommand('listDatabases')" 2>/dev/null && echo "WARNING: MongoDB accessible without auth"
```

---

## 8. Comprehensive Password Audit Workflow

```bash
#!/bin/bash
# Full password audit workflow
REPORT_DIR="/var/log/password-audits"
DATE=$(date +%Y%m%d-%H%M%S)
REPORT="${REPORT_DIR}/audit-${DATE}.txt"
mkdir -p "$REPORT_DIR"
chmod 700 "$REPORT_DIR"

echo "=== Password Audit Report - $(date) ===" | tee "$REPORT"
echo "Host: $(hostname)" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# 1. Policy check
echo "--- Password Policy ---" | tee -a "$REPORT"
grep -E "^PASS_" /etc/login.defs | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# 2. Hash algorithm check
echo "--- Hash Algorithms in Use ---" | tee -a "$REPORT"
sudo awk -F: '{
  if ($2 ~ /^\$1\$/) algo="MD5 (WEAK)";
  else if ($2 ~ /^\$5\$/) algo="SHA-256";
  else if ($2 ~ /^\$6\$/) algo="SHA-512";
  else if ($2 ~ /^\$y\$/) algo="yescrypt";
  else if ($2 ~ /^!/ || $2 == "*") algo="LOCKED/DISABLED";
  else if ($2 == "") algo="EMPTY (CRITICAL)";
  else algo="OTHER";
  print $1 ": " algo
}' /etc/shadow 2>/dev/null | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# 3. Empty passwords
echo "--- Empty Passwords ---" | tee -a "$REPORT"
EMPTY=$(sudo awk -F: '($2 == "") {print $1}' /etc/shadow 2>/dev/null)
if [ -n "$EMPTY" ]; then
  echo "CRITICAL: $EMPTY" | tee -a "$REPORT"
else
  echo "None found" | tee -a "$REPORT"
fi
echo "" | tee -a "$REPORT"

# 4. Password expiration issues
echo "--- Password Expiration Issues ---" | tee -a "$REPORT"
sudo awk -F: '($5 == "" || $5 == "99999") && $2 !~ /^[!*]/ && $2 != "" {
  print $1 " — password never expires"
}' /etc/shadow 2>/dev/null | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# 5. Quick crack attempt (single mode — uses usernames)
echo "--- Quick Password Strength Test ---" | tee -a "$REPORT"
sudo unshadow /etc/passwd /etc/shadow > /tmp/audit-pw.txt 2>/dev/null
chmod 600 /tmp/audit-pw.txt
timeout 60 john --single /tmp/audit-pw.txt 2>/dev/null
CRACKED=$(john --show /tmp/audit-pw.txt 2>/dev/null | tail -1)
echo "$CRACKED" | tee -a "$REPORT"
shred -u /tmp/audit-pw.txt 2>/dev/null
echo "" | tee -a "$REPORT"

# 6. PAM configuration
echo "--- PAM Password Config ---" | tee -a "$REPORT"
grep -v "^#" /etc/pam.d/common-password 2>/dev/null | grep -v "^$" | tee -a "$REPORT"

chmod 600 "$REPORT"
echo "" | tee -a "$REPORT"
echo "=== Audit Complete ===" | tee -a "$REPORT"
echo "Report saved: $REPORT (permissions: 0600)"
```

---

## 9. Wordlist Management

```bash
# Download common wordlists
sudo mkdir -p /usr/share/wordlists

# Download rockyou (most common wordlist)
cd /usr/share/wordlists
sudo wget -q https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt

# Download SecLists
sudo git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/wordlists/seclists

# Generate custom wordlist from system info
# (company name, usernames, hostnames — common password patterns)
{
  hostname
  cat /etc/hostname
  awk -F: '{print $1}' /etc/passwd
  awk -F: '{print $5}' /etc/passwd | tr ',' '\n'
} | sort -u > /tmp/custom-wordlist.txt
```

---

## 10. Remediation Commands

```bash
# Force password change on next login
sudo chage -d 0 <username>

# Set password expiration policy
sudo chage -M 90 -m 7 -W 14 <username>

# Lock an account with weak password
sudo passwd -l <username>

# Upgrade hash algorithm to SHA-512
# In /etc/pam.d/common-password ensure:
# password [success=1 default=ignore] pam_unix.so sha512 shadow rounds=65536

# Force all users to change passwords
for user in $(awk -F: '($3 >= 1000 && $7 != "/usr/sbin/nologin") {print $1}' /etc/passwd); do
  sudo chage -d 0 "$user"
  echo "Forced password change for: $user"
done

# Set secure password policy via pwquality
sudo tee /etc/security/pwquality.conf > /dev/null <<'EOF'
minlen = 14
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
minclass = 3
maxrepeat = 3
dictcheck = 1
usercheck = 1
enforcing = 1
EOF
```
