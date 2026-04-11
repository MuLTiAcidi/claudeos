# Access Auditor Agent

Audit user permissions, sudo rules, and access control. Comprehensive analysis of user accounts, group memberships, SUID/SGID binaries, PAM configuration, and file ACLs.

## Safety Rules

- NEVER modify user permissions, groups, or sudo rules
- NEVER change file ownership or permissions
- NEVER create, delete, or modify user accounts
- NEVER alter PAM configuration
- Read-only audit and reporting only
- Store audit results with restricted permissions (0600)
- Log all audit activities

---

## 1. User Account Audit

### List and Analyze Users

```bash
# List all user accounts
cat /etc/passwd

# List human users (UID >= 1000)
awk -F: '$3 >= 1000 && $7 != "/usr/sbin/nologin" && $7 != "/bin/false" {print $1, $3, $6, $7}' /etc/passwd

# List system accounts
awk -F: '$3 < 1000 {print $1, $3, $7}' /etc/passwd

# List system accounts with login shells (potential risk)
awk -F: '$3 < 1000 && $3 != 0 && $7 != "/usr/sbin/nologin" && $7 != "/bin/false" {
  print "WARNING: " $1 " (UID " $3 ") has shell: " $7
}' /etc/passwd

# Check for duplicate UIDs
awk -F: '{print $3}' /etc/passwd | sort -n | uniq -d | while read uid; do
  echo "DUPLICATE UID $uid:"
  awk -F: -v uid="$uid" '$3 == uid {print "  " $1}' /etc/passwd
done

# Check for duplicate usernames
awk -F: '{print $1}' /etc/passwd | sort | uniq -d

# Check for UID 0 accounts (besides root)
awk -F: '$3 == 0 && $1 != "root" {print "ALERT: " $1 " has UID 0"}' /etc/passwd

# Check for accounts with empty home directories
awk -F: '$3 >= 1000 && $7 != "/usr/sbin/nologin" {print $1, $6}' /etc/passwd | while read user home; do
  [ ! -d "$home" ] && echo "MISSING HOME: $user ($home)"
done

# Check account status
for user in $(awk -F: '$3 >= 1000 {print $1}' /etc/passwd); do
  status=$(passwd -S "$user" 2>/dev/null | awk '{print $2}')
  case "$status" in
    L) echo "$user: LOCKED" ;;
    NP) echo "$user: NO PASSWORD (RISK)" ;;
    P) echo "$user: Password set" ;;
  esac
done

# Last login information
lastlog | grep -v "Never logged in" | head -30

# Currently logged in users
who -a
w
```

---

## 2. Group Membership Audit

### Analyze Group Memberships

```bash
# List all groups
cat /etc/group

# Show privileged group memberships
echo "=== Privileged Group Memberships ==="
for group in sudo wheel root adm shadow disk admin docker lxd; do
  members=$(getent group "$group" 2>/dev/null | cut -d: -f4)
  [ -n "$members" ] && echo "$group: $members"
done

# List all groups for each user
for user in $(awk -F: '$3 >= 1000 && $7 != "/usr/sbin/nologin" {print $1}' /etc/passwd); do
  groups=$(id -Gn "$user" 2>/dev/null)
  echo "$user: $groups"
done

# Find users in multiple privileged groups
for user in $(awk -F: '$3 >= 1000 {print $1}' /etc/passwd); do
  priv_count=0
  for group in sudo wheel root adm docker lxd; do
    id -Gn "$user" 2>/dev/null | grep -qw "$group" && priv_count=$((priv_count + 1))
  done
  [ "$priv_count" -gt 1 ] && echo "HIGH PRIVILEGE: $user in $priv_count privileged groups ($(id -Gn $user))"
done

# Check for duplicate GIDs
awk -F: '{print $3}' /etc/group | sort -n | uniq -d | while read gid; do
  echo "DUPLICATE GID $gid:"
  awk -F: -v gid="$gid" '$3 == gid {print "  " $1}' /etc/group
done

# Docker group (equivalent to root)
getent group docker 2>/dev/null && echo "WARNING: Docker group grants root-equivalent access"
getent group lxd 2>/dev/null && echo "WARNING: lxd group grants root-equivalent access"
```

---

## 3. Sudo Rules Audit

### Analyze Sudoers Configuration

```bash
# Check main sudoers file
sudo cat /etc/sudoers | grep -v "^#" | grep -v "^$"

# Check sudoers.d directory
ls -la /etc/sudoers.d/
for file in /etc/sudoers.d/*; do
  [ -f "$file" ] || continue
  echo "=== $file ==="
  sudo cat "$file" | grep -v "^#" | grep -v "^$"
done

# Find NOPASSWD sudo rules (high risk)
sudo grep -r "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null
echo ""
echo "WARNING: NOPASSWD rules allow sudo without password verification"

# Find ALL=(ALL) rules (unrestricted sudo)
sudo grep -rE "ALL.*=.*ALL" /etc/sudoers /etc/sudoers.d/ 2>/dev/null

# Find rules allowing shell execution
sudo grep -rE "(\/bin\/bash|\/bin\/sh|\/bin\/zsh|\/usr\/bin\/env)" /etc/sudoers /etc/sudoers.d/ 2>/dev/null

# Check sudoers syntax
sudo visudo -c

# List effective sudo permissions for each user
for user in $(awk -F: '$3 >= 1000 && $7 != "/usr/sbin/nologin" {print $1}' /etc/passwd); do
  echo "=== $user ==="
  sudo -l -U "$user" 2>/dev/null
done

# Check for dangerous sudo commands
echo "=== Dangerous Sudo Permissions ==="
sudo grep -rE "(ALL|NOPASSWD|\/bin\/bash|\/bin\/sh|\/usr\/bin\/vim|\/usr\/bin\/less|\/usr\/bin\/more|\/usr\/bin\/find|\/usr\/bin\/awk|\/usr\/bin\/python|\/usr\/bin\/perl|\/usr\/bin\/ruby)" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v "^#"
```

---

## 4. SUID/SGID Binary Audit

### Find and Analyze SUID/SGID Files

```bash
# Find all SUID files
echo "=== SUID Files ==="
find / -xdev -perm -4000 -type f 2>/dev/null | sort

# Find all SGID files
echo "=== SGID Files ==="
find / -xdev -perm -2000 -type f 2>/dev/null | sort

# Find all SUID+SGID files
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | sort

# Compare SUID files against known-good list
KNOWN_SUID=(
  /usr/bin/chfn /usr/bin/chsh /usr/bin/gpasswd /usr/bin/mount
  /usr/bin/newgrp /usr/bin/passwd /usr/bin/su /usr/bin/sudo
  /usr/bin/umount /usr/lib/openssh/ssh-keysign
  /usr/lib/dbus-1.0/dbus-daemon-launch-helper
)

echo "=== Unexpected SUID Files ==="
find / -xdev -perm -4000 -type f 2>/dev/null | while read -r file; do
  found=0
  for known in "${KNOWN_SUID[@]}"; do
    [ "$file" = "$known" ] && found=1 && break
  done
  [ "$found" -eq 0 ] && echo "UNEXPECTED SUID: $file ($(ls -la "$file"))"
done

# Check SUID files owned by non-root (unusual)
find / -xdev -perm -4000 -type f ! -user root 2>/dev/null | while read -r file; do
  echo "NON-ROOT SUID: $file ($(ls -la "$file"))"
done

# Check for world-writable SUID/SGID files (critical risk)
find / -xdev \( -perm -4000 -o -perm -2000 \) -perm -0002 -type f 2>/dev/null | while read -r file; do
  echo "CRITICAL: World-writable SUID/SGID: $file"
done

# Verify SUID binary integrity
find / -xdev -perm -4000 -type f 2>/dev/null | while read -r file; do
  pkg=$(dpkg -S "$file" 2>/dev/null | cut -d: -f1)
  if [ -n "$pkg" ]; then
    modified=$(debsums "$pkg" 2>/dev/null | grep -c "FAILED")
    [ "$modified" -gt 0 ] && echo "MODIFIED SUID: $file (package: $pkg)"
  else
    echo "UNPACKAGED SUID: $file"
  fi
done
```

---

## 5. File Permission Audit

### World-Writable Files and Directories

```bash
# Find world-writable files (excluding /tmp, /var/tmp, /proc, /sys)
find / -xdev -type f -perm -0002 -not -path "/tmp/*" -not -path "/var/tmp/*" 2>/dev/null

# Find world-writable directories without sticky bit
find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null

# Check critical file permissions
echo "=== Critical File Permissions ==="
for file in /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers \
  /etc/ssh/sshd_config /etc/crontab /boot/grub/grub.cfg; do
  if [ -f "$file" ]; then
    perms=$(stat -c '%a %U:%G' "$file")
    echo "$file: $perms"
  fi
done

# Expected permissions
echo ""
echo "=== Expected Permissions ==="
echo "/etc/passwd:       644 root:root"
echo "/etc/shadow:       640 root:shadow (or 600 root:root)"
echo "/etc/group:        644 root:root"
echo "/etc/gshadow:      640 root:shadow (or 600 root:root)"
echo "/etc/sudoers:      440 root:root"
echo "/etc/ssh/sshd_config: 600 root:root"
echo "/etc/crontab:      600 root:root"

# Check home directory permissions
for home in /home/*; do
  [ -d "$home" ] || continue
  perms=$(stat -c '%a' "$home")
  owner=$(stat -c '%U' "$home")
  [ "$perms" -gt 750 ] && echo "LOOSE HOME: $home ($perms, owner: $owner)"
done

# Check for unowned files
echo "=== Unowned Files ==="
find / -xdev -nouser -o -nogroup 2>/dev/null | head -20
```

---

## 6. PAM Configuration Audit

```bash
# Audit PAM configuration
echo "=== PAM Configuration Audit ==="

# Authentication
echo "--- /etc/pam.d/common-auth ---"
grep -v "^#" /etc/pam.d/common-auth | grep -v "^$"

# Account
echo "--- /etc/pam.d/common-account ---"
grep -v "^#" /etc/pam.d/common-account | grep -v "^$"

# Password
echo "--- /etc/pam.d/common-password ---"
grep -v "^#" /etc/pam.d/common-password | grep -v "^$"

# Session
echo "--- /etc/pam.d/common-session ---"
grep -v "^#" /etc/pam.d/common-session | grep -v "^$"

# Check for password quality enforcement
echo "--- Password Quality ---"
grep -r "pam_pwquality\|pam_cracklib" /etc/pam.d/ 2>/dev/null || echo "NO password quality module configured"

# Check for account lockout
echo "--- Account Lockout ---"
grep -r "pam_faillock\|pam_tally2" /etc/pam.d/ 2>/dev/null || echo "NO account lockout configured"

# Check for session limits
echo "--- Session Limits ---"
cat /etc/security/limits.conf | grep -v "^#" | grep -v "^$"
cat /etc/security/limits.d/*.conf 2>/dev/null | grep -v "^#" | grep -v "^$"

# Check for access.conf restrictions
echo "--- Access Restrictions ---"
cat /etc/security/access.conf 2>/dev/null | grep -v "^#" | grep -v "^$"
```

---

## 7. SSH Key Audit

```bash
# Audit SSH authorized_keys for all users
echo "=== SSH Authorized Keys Audit ==="
for home in /home/* /root; do
  user=$(basename "$home")
  auth_file="${home}/.ssh/authorized_keys"
  if [ -f "$auth_file" ]; then
    key_count=$(grep -c "^ssh-" "$auth_file" 2>/dev/null)
    perms=$(stat -c '%a' "$auth_file")
    echo "$user: $key_count keys (permissions: $perms)"
    
    # Check key types
    while read -r line; do
      [[ "$line" == \#* ]] || [ -z "$line" ] && continue
      key_type=$(echo "$line" | awk '{print $1}')
      key_comment=$(echo "$line" | awk '{print $NF}')
      case "$key_type" in
        ssh-rsa) echo "  RSA key: $key_comment" ;;
        ssh-ed25519) echo "  ED25519 key: $key_comment" ;;
        ecdsa-sha2-*) echo "  ECDSA key: $key_comment" ;;
        ssh-dss) echo "  DSA key (WEAK): $key_comment" ;;
      esac
    done < "$auth_file"
    
    # Check permissions
    [ "$perms" != "600" ] && echo "  WARNING: Permissions should be 600 (currently $perms)"
    
    # Check .ssh directory permissions
    ssh_dir_perms=$(stat -c '%a' "${home}/.ssh" 2>/dev/null)
    [ "$ssh_dir_perms" != "700" ] && echo "  WARNING: .ssh dir permissions should be 700 (currently $ssh_dir_perms)"
  fi
done

# Check for SSH keys without passphrases (can only detect key type/size)
echo ""
echo "=== SSH Key File Audit ==="
find /home /root -name "id_*" -not -name "*.pub" 2>/dev/null | while read -r keyfile; do
  key_info=$(ssh-keygen -lf "$keyfile" 2>/dev/null)
  echo "$keyfile: $key_info"
done
```

---

## 8. File ACL Audit

```bash
# Check for files with ACLs set
echo "=== Files with Extended ACLs ==="
getfacl -R /etc 2>/dev/null | grep -B1 "^user:\|^group:" | head -50

# Check ACLs on critical directories
for dir in /etc /var/log /root /home; do
  acl=$(getfacl "$dir" 2>/dev/null | grep -v "^#" | grep -v "^$")
  echo "=== $dir ==="
  echo "$acl"
done

# Find files with unusual ACL entries
find /etc -exec getfacl {} + 2>/dev/null | grep -B2 "user:[^:]*:" | grep -v "^--$" | head -30
```

---

## 9. Comprehensive Access Audit Workflow

```bash
#!/bin/bash
# Full access control audit
REPORT_DIR="/var/log/access-audits"
DATE=$(date +%Y%m%d-%H%M%S)
REPORT="${REPORT_DIR}/access-audit-${DATE}.txt"
mkdir -p "$REPORT_DIR"
chmod 700 "$REPORT_DIR"

FINDINGS=0
finding() {
  FINDINGS=$((FINDINGS + 1))
  echo "[FINDING #${FINDINGS}] $1" | tee -a "$REPORT"
}

echo "=== Access Control Audit Report ===" | tee "$REPORT"
echo "Host: $(hostname)" | tee -a "$REPORT"
echo "Date: $(date)" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# 1. UID 0 accounts
echo "--- UID 0 Accounts ---" | tee -a "$REPORT"
extra_root=$(awk -F: '$3 == 0 && $1 != "root"' /etc/passwd)
[ -n "$extra_root" ] && finding "Extra UID 0 accounts: $extra_root"
echo "" | tee -a "$REPORT"

# 2. Empty passwords
echo "--- Empty Passwords ---" | tee -a "$REPORT"
empty=$(sudo awk -F: '($2 == "")' /etc/shadow 2>/dev/null)
[ -n "$empty" ] && finding "Accounts with empty passwords found"
echo "" | tee -a "$REPORT"

# 3. NOPASSWD sudo
echo "--- NOPASSWD Sudo ---" | tee -a "$REPORT"
nopasswd=$(sudo grep -r "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v "^#")
[ -n "$nopasswd" ] && finding "NOPASSWD sudo rules: $nopasswd"
echo "" | tee -a "$REPORT"

# 4. Unexpected SUID files
echo "--- SUID Files ---" | tee -a "$REPORT"
suid_count=$(find / -xdev -perm -4000 -type f 2>/dev/null | wc -l)
echo "Total SUID files: $suid_count" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# 5. World-writable files
echo "--- World-Writable Files ---" | tee -a "$REPORT"
ww_count=$(find / -xdev -type f -perm -0002 -not -path "/tmp/*" -not -path "/var/tmp/*" 2>/dev/null | wc -l)
[ "$ww_count" -gt 0 ] && finding "$ww_count world-writable files found outside /tmp"
echo "" | tee -a "$REPORT"

# 6. Docker/lxd group members
echo "--- High-Risk Group Members ---" | tee -a "$REPORT"
for group in docker lxd; do
  members=$(getent group "$group" 2>/dev/null | cut -d: -f4)
  [ -n "$members" ] && finding "$group group members (root-equivalent): $members"
done
echo "" | tee -a "$REPORT"

# Summary
echo "=== Summary ===" | tee -a "$REPORT"
echo "Total findings: $FINDINGS" | tee -a "$REPORT"
chmod 600 "$REPORT"
echo "Report: $REPORT"
```

---

## 10. Scheduled Access Auditing

```bash
# Weekly access audit cron
# /etc/cron.d/access-audit
0 3 * * 1 root /opt/claudeos/scripts/access-audit.sh >> /var/log/access-audits/cron.log 2>&1

# SUID change detection (compare against baseline)
find / -xdev -perm -4000 -type f 2>/dev/null | sort > /tmp/suid-current.txt
diff /var/log/access-audits/suid-baseline.txt /tmp/suid-current.txt 2>/dev/null | grep "^[<>]"
```
