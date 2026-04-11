# Config Hardener Agent

Auto-harden SSH, kernel, services, and filesystem to security benchmarks. Applies CIS-aligned hardening configurations with rollback capability.

## Safety Rules

- ALWAYS create backups before modifying any configuration
- NEVER apply changes without showing the user what will change
- NEVER lock out the current SSH session (test SSH before closing)
- NEVER disable critical services without confirmation
- Always provide rollback commands for every change
- Test configurations before applying (sshd -t, sysctl --system, etc.)
- Keep a hardening log of all changes made
- Changes should be idempotent (safe to run multiple times)

---

## 1. SSH Hardening

### Backup and Harden SSH Configuration

```bash
# Backup current SSH config
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d)

# Generate hardened SSH config
sudo tee /etc/ssh/sshd_config.d/hardening.conf > /dev/null <<'EOF'
# ClaudeOS SSH Hardening Configuration

# Protocol and authentication
Protocol 2
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey

# Limit authentication attempts
MaxAuthTries 3
MaxSessions 5
LoginGraceTime 30

# Disable forwarding and tunneling
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no
GatewayPorts no

# Session management
ClientAliveInterval 300
ClientAliveCountMax 2

# Logging
LogLevel VERBOSE
SyslogFacility AUTH

# Security
StrictModes yes
IgnoreRhosts yes
HostbasedAuthentication no
PermitUserEnvironment no
UsePAM yes

# Ciphers and MACs (strong only)
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256

# Banner
Banner /etc/issue.net

# Restrict users (uncomment and customize)
# AllowUsers deployer admin
# AllowGroups ssh-users
EOF

# Set SSH banner
sudo tee /etc/issue.net > /dev/null <<'EOF'
***************************************************************************
                    AUTHORIZED ACCESS ONLY
This system is for authorized users only. All activity is monitored
and logged. Unauthorized access will be prosecuted to the fullest
extent of the law.
***************************************************************************
EOF

# Validate SSH configuration
sudo sshd -t && echo "SSH config valid" || echo "SSH config has errors — do NOT restart"

# Set correct permissions
sudo chmod 600 /etc/ssh/sshd_config
sudo chmod 600 /etc/ssh/sshd_config.d/*.conf
sudo chmod 644 /etc/issue.net

# Restart SSH (ONLY after validation passes)
# IMPORTANT: Keep current session open and test with a new connection first
sudo systemctl restart sshd

# Rollback command
# sudo cp /etc/ssh/sshd_config.backup.YYYYMMDD /etc/ssh/sshd_config
# sudo rm /etc/ssh/sshd_config.d/hardening.conf
# sudo systemctl restart sshd
```

### SSH Key Hardening

```bash
# Remove small/weak SSH host keys
sudo find /etc/ssh -name "ssh_host_*_key" -exec sh -c '
  bits=$(ssh-keygen -lf "$1" | awk "{print \$1}")
  type=$(ssh-keygen -lf "$1" | grep -oP "\(.*\)")
  if [ "$bits" -lt 2048 ] 2>/dev/null; then
    echo "WEAK KEY: $1 ($bits bits $type)"
  fi
' _ {} \;

# Regenerate host keys with strong algorithms
sudo rm /etc/ssh/ssh_host_*
sudo ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""
sudo ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""
```

---

## 2. Kernel Hardening (sysctl)

### Apply Kernel Hardening Parameters

```bash
# Backup current sysctl settings
sudo sysctl -a > /tmp/sysctl-backup-$(date +%Y%m%d).conf 2>/dev/null

# Apply hardening parameters
sudo tee /etc/sysctl.d/99-hardening.conf > /dev/null <<'EOF'
# ClaudeOS Kernel Hardening

# Network Security
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_timestamps = 0

# IPv6 hardening (if not using IPv6, disable)
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# Kernel hardening
kernel.sysrq = 0
kernel.core_uses_pid = 1
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.perf_event_paranoid = 3
kernel.yama.ptrace_scope = 2

# Filesystem hardening
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
EOF

# Apply settings
sudo sysctl --system

# Verify settings
echo "=== Verifying Hardening ==="
while IFS='=' read -r key value; do
  key=$(echo "$key" | tr -d ' ')
  value=$(echo "$value" | tr -d ' ')
  [[ "$key" == \#* ]] || [ -z "$key" ] && continue
  actual=$(sysctl -n "$key" 2>/dev/null)
  if [ "$actual" = "$value" ]; then
    echo "[OK] $key = $actual"
  else
    echo "[FAIL] $key = $actual (expected $value)"
  fi
done < /etc/sysctl.d/99-hardening.conf

# Rollback
# sudo rm /etc/sysctl.d/99-hardening.conf
# sudo sysctl --system
```

---

## 3. Filesystem Hardening

### Secure Mount Options

```bash
# Backup fstab
sudo cp /etc/fstab /etc/fstab.backup.$(date +%Y%m%d)

# Recommended mount options for /tmp
# /tmp should have: nodev, nosuid, noexec
# Add to /etc/fstab:
# tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0

# Secure /dev/shm
# /dev/shm should have: nodev, nosuid, noexec
# tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0

# Verify current mount options
mount | grep -E "(\/tmp|\/dev\/shm|\/var|\/home)" | while read -r line; do
  echo "$line"
  echo "$line" | grep -q "nosuid" || echo "  MISSING: nosuid"
  echo "$line" | grep -q "nodev" || echo "  MISSING: nodev"
done

# Remount /tmp with secure options (temporary, until next reboot)
sudo mount -o remount,nosuid,nodev,noexec /tmp 2>/dev/null
sudo mount -o remount,nosuid,nodev,noexec /dev/shm 2>/dev/null
```

### File Permission Hardening

```bash
# Secure critical files
sudo chmod 644 /etc/passwd
sudo chmod 644 /etc/group
sudo chmod 600 /etc/shadow
sudo chmod 600 /etc/gshadow
sudo chmod 600 /etc/ssh/sshd_config
sudo chmod 700 /root
sudo chmod 600 /boot/grub/grub.cfg 2>/dev/null

# Set ownership
sudo chown root:root /etc/passwd /etc/shadow /etc/group /etc/gshadow
sudo chown root:root /etc/ssh/sshd_config

# Restrict cron access
sudo chmod 600 /etc/crontab
sudo chmod 700 /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly 2>/dev/null

# Find and report world-writable files (except /tmp, /var/tmp)
find / -xdev -type f -perm -0002 -not -path "/tmp/*" -not -path "/var/tmp/*" 2>/dev/null

# Find SUID/SGID binaries
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | sort

# Remove unnecessary SUID bits (review carefully first)
# sudo chmod u-s /usr/bin/unnecessary-suid-binary
```

---

## 4. Service Hardening

### Disable Unnecessary Services

```bash
# List all enabled services
systemctl list-unit-files --type=service --state=enabled

# Services commonly recommended to disable
UNNECESSARY_SERVICES=(
  avahi-daemon
  cups
  cups-browsed
  bluetooth
  rpcbind
  nfs-server
  nfs-common
  vsftpd
  telnet
  xinetd
  ypserv
  tftp
  snmpd
)

for svc in "${UNNECESSARY_SERVICES[@]}"; do
  if systemctl is-active "$svc" &>/dev/null; then
    echo "ACTIVE: $svc — consider disabling"
    # To disable:
    # sudo systemctl stop "$svc"
    # sudo systemctl disable "$svc"
    # sudo systemctl mask "$svc"
  fi
done

# Check for listening services on external interfaces
sudo ss -tlnp | grep -v "127.0.0.1\|::1"
```

### Harden systemd Services

```bash
# Create service hardening override
# Example for a web service
sudo mkdir -p /etc/systemd/system/nginx.service.d/
sudo tee /etc/systemd/system/nginx.service.d/hardening.conf > /dev/null <<'EOF'
[Service]
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
MemoryDenyWriteExecute=true
RestrictRealtime=true
EOF

sudo systemctl daemon-reload
```

---

## 5. Firewall Hardening

### UFW Configuration

```bash
# Install and enable UFW
sudo apt-get install -y ufw

# Default policies
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow SSH (CRITICAL: do this before enabling)
sudo ufw allow ssh

# Allow specific services
sudo ufw allow 80/tcp comment "HTTP"
sudo ufw allow 443/tcp comment "HTTPS"

# Rate limit SSH
sudo ufw limit ssh comment "Rate limit SSH"

# Allow from specific IPs only
# sudo ufw allow from 10.0.0.0/8 to any port 22 comment "SSH from internal"

# Enable firewall
sudo ufw enable

# Check status
sudo ufw status verbose

# Log firewall events
sudo ufw logging on

# Rollback
# sudo ufw reset
```

### iptables Hardening

```bash
# Save current rules
sudo iptables-save > /tmp/iptables-backup-$(date +%Y%m%d).rules

# Basic hardening rules
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT ACCEPT

# Allow established connections
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow loopback
sudo iptables -A INPUT -i lo -j ACCEPT

# Allow SSH
sudo iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m limit --limit 3/min --limit-burst 3 -j ACCEPT

# Allow HTTP/HTTPS
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Log dropped packets
sudo iptables -A INPUT -j LOG --log-prefix "IPTables-Drop: " --log-level 4

# Save rules
sudo iptables-save | sudo tee /etc/iptables/rules.v4

# Rollback
# sudo iptables-restore < /tmp/iptables-backup-YYYYMMDD.rules
```

---

## 6. Kernel Module Blacklisting

```bash
# Blacklist unnecessary/dangerous kernel modules
sudo tee /etc/modprobe.d/hardening-blacklist.conf > /dev/null <<'EOF'
# Filesystem modules (rarely needed)
install cramfs /bin/false
install freevxfs /bin/false
install jffs2 /bin/false
install hfs /bin/false
install hfsplus /bin/false
install squashfs /bin/false
install udf /bin/false
install vfat /bin/false

# Network protocols (rarely needed)
install dccp /bin/false
install sctp /bin/false
install rds /bin/false
install tipc /bin/false

# USB storage (if not needed)
# install usb-storage /bin/false

# Firewire
install firewire-core /bin/false
install firewire-ohci /bin/false
install firewire-sbp2 /bin/false

# Bluetooth (if not needed)
install bluetooth /bin/false
install btusb /bin/false
EOF

# Verify blacklisting
for mod in cramfs freevxfs jffs2 hfs hfsplus dccp sctp rds tipc; do
  modprobe -n -v "$mod" 2>&1 | grep -q "install /bin/false" && echo "[OK] $mod blacklisted" || echo "[FAIL] $mod not blacklisted"
done
```

---

## 7. Account Hardening

```bash
# Set password aging defaults
sudo sed -i.bak 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs
sudo sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/' /etc/login.defs
sudo sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 14/' /etc/login.defs
sudo sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN 14/' /etc/login.defs

# Set default umask
sudo sed -i 's/^UMASK.*/UMASK 027/' /etc/login.defs

# Lock system accounts
for user in $(awk -F: '($3 < 1000 && $3 != 0 && $7 != "/usr/sbin/nologin" && $7 != "/bin/false") {print $1}' /etc/passwd); do
  echo "Locking shell for system account: $user"
  # sudo usermod -s /usr/sbin/nologin "$user"
done

# Set account lockout policy
sudo tee /etc/security/faillock.conf > /dev/null <<'EOF'
deny = 5
unlock_time = 900
fail_interval = 900
audit
even_deny_root
root_unlock_time = 60
EOF

# Configure password quality
sudo apt-get install -y libpam-pwquality
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

# Restrict su to wheel/sudo group
sudo dpkg-statoverride --update --add root sudo 4750 /bin/su 2>/dev/null
```

---

## 8. Audit Configuration

```bash
# Install and configure auditd
sudo apt-get install -y auditd audispd-plugins

# Configure audit rules
sudo tee /etc/audit/rules.d/hardening.rules > /dev/null <<'EOF'
# Delete all existing rules
-D

# Buffer size
-b 8192

# Failure mode (1=printk, 2=panic)
-f 1

# Monitor authentication files
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# Monitor SSH config
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /etc/ssh/sshd_config.d/ -p wa -k sshd_config

# Monitor login files
-w /var/log/auth.log -p wa -k auth_log
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins

# Monitor cron
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron

# Privileged command execution
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=4294967295 -k privileged_cmd

# System calls for privilege escalation
-a always,exit -F arch=b64 -S setuid -S setgid -S setreuid -S setregid -k privilege_escalation

# Make rules immutable (requires reboot to change)
# -e 2
EOF

sudo systemctl enable auditd
sudo systemctl restart auditd
```

---

## 9. Comprehensive Hardening Workflow

```bash
#!/bin/bash
# Full system hardening script
LOG="/var/log/hardening-$(date +%Y%m%d-%H%M%S).log"

echo "=== ClaudeOS System Hardening ===" | tee "$LOG"
echo "Date: $(date)" | tee -a "$LOG"
echo "IMPORTANT: Review all changes before applying" | tee -a "$LOG"
echo "" | tee -a "$LOG"

# Pre-flight backup
echo "--- Creating Backups ---" | tee -a "$LOG"
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.pre-hardening
sudo sysctl -a > /tmp/sysctl-pre-hardening.conf 2>/dev/null
sudo iptables-save > /tmp/iptables-pre-hardening.rules 2>/dev/null
sudo cp /etc/login.defs /etc/login.defs.pre-hardening
echo "Backups created" | tee -a "$LOG"

# List all changes that would be made
echo "" | tee -a "$LOG"
echo "--- Planned Changes ---" | tee -a "$LOG"
echo "1. SSH: Disable root login, password auth, enforce key-only" | tee -a "$LOG"
echo "2. Kernel: Network hardening, address space randomization" | tee -a "$LOG"
echo "3. Firewall: Default deny, allow SSH/HTTP/HTTPS only" | tee -a "$LOG"
echo "4. Filesystem: Secure permissions on critical files" | tee -a "$LOG"
echo "5. Accounts: Password policy, lockout policy" | tee -a "$LOG"
echo "6. Services: Disable unnecessary services" | tee -a "$LOG"
echo "7. Modules: Blacklist unnecessary kernel modules" | tee -a "$LOG"
echo "8. Audit: Enable comprehensive auditing" | tee -a "$LOG"

echo "" | tee -a "$LOG"
echo "Review the planned changes above." | tee -a "$LOG"
echo "Apply with: /opt/claudeos/scripts/apply-hardening.sh" | tee -a "$LOG"
echo "Rollback with: /opt/claudeos/scripts/rollback-hardening.sh" | tee -a "$LOG"
```

---

## 10. Hardening Verification

```bash
# Verify all hardening measures
echo "=== Hardening Verification ==="

# SSH
echo "--- SSH ---"
sshd -T 2>/dev/null | grep -E "permitrootlogin|passwordauthentication|x11forwarding|maxauthtries"

# Kernel
echo "--- Kernel ---"
for param in net.ipv4.ip_forward net.ipv4.conf.all.accept_redirects kernel.randomize_va_space kernel.kptr_restrict; do
  echo "$param = $(sysctl -n $param 2>/dev/null)"
done

# Firewall
echo "--- Firewall ---"
sudo ufw status 2>/dev/null || sudo iptables -L -n 2>/dev/null | head -20

# File permissions
echo "--- Critical File Permissions ---"
ls -la /etc/passwd /etc/shadow /etc/group /etc/ssh/sshd_config 2>/dev/null

# Services
echo "--- Listening Services ---"
sudo ss -tlnp | grep -v "127.0.0.1\|::1"
```
