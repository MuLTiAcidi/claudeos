#!/bin/bash
# ClaudeOS ISO Builder
# Run inside a Debian/Ubuntu container with live-build installed
# Usage: bash build-iso.sh

set -e

echo "=================================="
echo "  ClaudeOS ISO Builder"
echo "=================================="

BUILD_DIR="/build/claudeos-live"

# Clean previous build
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# Initialize live-build config
lb config \
    --distribution jammy \
    --archive-areas "main restricted universe multiverse" \
    --architectures amd64 \
    --binary-images iso-hybrid \
    --iso-application "ClaudeOS" \
    --iso-publisher "ClaudeOS" \
    --iso-volume "ClaudeOS" \
    --debian-installer live \
    --debian-installer-gui false \
    --memtest none \
    --bootappend-live "boot=live components hostname=claudeos username=claude" \
    --apt-recommends false

# Package lists
mkdir -p config/package-lists
cat > config/package-lists/claudeos.list.chroot << 'EOF'
# Core system
linux-generic
grub-pc
grub-efi-amd64

# Essential tools
curl
wget
git
htop
nano
vim
unzip
rsync
net-tools
lsof
iotop
iftop
mtr-tiny
dnsutils
software-properties-common
apt-transport-https
ca-certificates
gnupg

# Security
ufw
fail2ban
unattended-upgrades
apt-listchanges
logrotate

# Networking
openssh-server
openssl

# Monitoring
sysstat
procps

# Web server (optional, commonly needed)
nginx

# Database (optional, commonly needed)
mariadb-server

# PHP (commonly needed for web hosting)
php-fpm
php-mysql
php-mbstring
php-xml
php-curl
php-zip
php-gd

# Docker
docker.io
docker-compose

# Node.js will be installed via script

# Utilities
jq
bc
gzip
bzip2
xz-utils
pigz
pv
screen
tmux

# Filesystem
lvm2
btrfs-progs

# Mail (basic)
msmtp
msmtp-mta
EOF

# Hooks - scripts that run during build
mkdir -p config/hooks/live

# Install Node.js and Claude Code
cat > config/hooks/live/01-install-nodejs.hook.chroot << 'HOOKEOF'
#!/bin/bash
set -e
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt-get install -y nodejs
npm install -g @anthropic-ai/claude-code
HOOKEOF
chmod +x config/hooks/live/01-install-nodejs.hook.chroot

# Install ClaudeOS
cat > config/hooks/live/02-install-claudeos.hook.chroot << 'HOOKEOF'
#!/bin/bash
set -e
# ClaudeOS files are copied via overlay
chmod +x /opt/claudeos/scripts/*.sh

# Create claudeos command alias
echo 'alias claudeos="cd /opt/claudeos && claude"' >> /etc/skel/.bashrc
echo 'export PATH="/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH"' >> /etc/skel/.bashrc
HOOKEOF
chmod +x config/hooks/live/02-install-claudeos.hook.chroot

# Security hardening
cat > config/hooks/live/03-security.hook.chroot << 'HOOKEOF'
#!/bin/bash
set -e

# SSH hardening
sed -i 's/#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/#MaxAuthTries.*/MaxAuthTries 5/' /etc/ssh/sshd_config
sed -i 's/#ClientAliveInterval.*/ClientAliveInterval 300/' /etc/ssh/sshd_config
sed -i 's/#ClientAliveCountMax.*/ClientAliveCountMax 2/' /etc/ssh/sshd_config

# UFW defaults
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh

# Fail2ban config
cat > /etc/fail2ban/jail.local << 'F2BEOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true
port = ssh
maxretry = 5
F2BEOF

# Sysctl hardening
cat > /etc/sysctl.d/99-claudeos.conf << 'SYSEOF'
# ClaudeOS Security Hardening
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
kernel.randomize_va_space = 2
fs.suid_dumpable = 0
SYSEOF

# Enable unattended upgrades
echo 'Unattended-Upgrade::Automatic-Reboot "false";' >> /etc/apt/apt.conf.d/50unattended-upgrades
HOOKEOF
chmod +x config/hooks/live/03-security.hook.chroot

# First boot setup script
cat > config/hooks/live/04-firstboot.hook.chroot << 'HOOKEOF'
#!/bin/bash
set -e

# Create first-boot script
cat > /opt/claudeos/scripts/first-boot.sh << 'FBEOF'
#!/bin/bash
# ClaudeOS First Boot Setup
# Runs once on first boot

MARKER="/opt/claudeos/.first-boot-done"
if [ -f "$MARKER" ]; then
    exit 0
fi

clear
echo ""
echo "  ██████╗██╗      █████╗ ██╗   ██╗██████╗ ███████╗ ██████╗ ███████╗"
echo " ██╔════╝██║     ██╔══██╗██║   ██║██╔══██╗██╔════╝██╔═══██╗██╔════╝"
echo " ██║     ██║     ███████║██║   ██║██║  ██║█████╗  ██║   ██║███████╗"
echo " ██║     ██║     ██╔══██║██║   ██║██║  ██║██╔══╝  ██║   ██║╚════██║"
echo " ╚██████╗███████╗██║  ██║╚██████╔╝██████╔╝███████╗╚██████╔╝███████║"
echo "  ╚═════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝ ╚═════╝╚══════╝"
echo ""
echo "  Welcome to ClaudeOS — AI-Powered Server Management"
echo "  =================================================="
echo ""

# Set timezone
echo "Step 1/4: Timezone"
read -p "  Enter timezone (e.g., Europe/Berlin): " TZ
timedatectl set-timezone "$TZ" 2>/dev/null || echo "  Warning: Could not set timezone"

# Create admin user
echo ""
echo "Step 2/4: Admin User"
read -p "  Username: " ADMIN_USER
adduser --gecos "" "$ADMIN_USER"
usermod -aG sudo "$ADMIN_USER"
mkdir -p /home/$ADMIN_USER/.ssh
chmod 700 /home/$ADMIN_USER/.ssh
chown -R $ADMIN_USER:$ADMIN_USER /home/$ADMIN_USER/.ssh
echo "  User $ADMIN_USER created with sudo access"

# Set hostname
echo ""
echo "Step 3/4: Hostname"
read -p "  Hostname: " NEW_HOST
hostnamectl set-hostname "$NEW_HOST" 2>/dev/null
echo "  Hostname set to $NEW_HOST"

# Enable services
echo ""
echo "Step 4/4: Enabling services..."
systemctl enable ssh
systemctl enable ufw
systemctl enable fail2ban
systemctl enable docker
ufw --force enable

# Install auto-pilot cron jobs
bash /opt/claudeos/scripts/install-autopilot.sh

# Create logs directory
mkdir -p /opt/claudeos/logs
mkdir -p /backups

# Mark first boot done
touch "$MARKER"

echo ""
echo "=================================="
echo "  ClaudeOS Setup Complete!"
echo "=================================="
echo ""
echo "  To start managing your server:"
echo "    claudeos"
echo ""
echo "  Or:"
echo "    cd /opt/claudeos && claude"
echo ""
echo "  Your server is secured with:"
echo "    ✓ UFW firewall (SSH allowed)"
echo "    ✓ fail2ban (SSH protection)"
echo "    ✓ Auto-pilot monitoring"
echo "    ✓ Daily backups"
echo "    ✓ Security hardening"
echo ""
FBEOF
chmod +x /opt/claudeos/scripts/first-boot.sh

# Add to rc.local for first boot
cat > /etc/rc.local << 'RCEOF'
#!/bin/bash
/opt/claudeos/scripts/first-boot.sh
exit 0
RCEOF
chmod +x /etc/rc.local

# Create systemd service for first boot
cat > /etc/systemd/system/claudeos-firstboot.service << 'SVCEOF'
[Unit]
Description=ClaudeOS First Boot Setup
After=network.target
ConditionPathExists=!/opt/claudeos/.first-boot-done

[Service]
Type=oneshot
ExecStart=/opt/claudeos/scripts/first-boot.sh
StandardInput=tty
StandardOutput=tty
TTYPath=/dev/tty1

[Install]
WantedBy=multi-user.target
SVCEOF
systemctl enable claudeos-firstboot.service
HOOKEOF
chmod +x config/hooks/live/04-firstboot.hook.chroot

# Copy ClaudeOS overlay files
cp -r /claudeos-source/* config/includes.chroot/opt/claudeos/ 2>/dev/null || true

# Custom MOTD
mkdir -p config/includes.chroot/etc/update-motd.d
cat > config/includes.chroot/etc/update-motd.d/00-claudeos << 'MOTDEOF'
#!/bin/bash
echo ""
echo "  ╔═══════════════════════════════════════╗"
echo "  ║         ClaudeOS Server               ║"
echo "  ║   AI-Powered System Management        ║"
echo "  ╚═══════════════════════════════════════╝"
echo ""
echo "  Type 'claudeos' to start managing"
echo ""
echo "  System: $(uname -r) | $(free -h | awk '/Mem:/{print $3"/"$2}') RAM | $(df -h / | awk 'NR==2{print $5}') disk"
echo ""
MOTDEOF
chmod +x config/includes.chroot/etc/update-motd.d/00-claudeos

# Remove default MOTD scripts
mkdir -p config/includes.chroot/etc/update-motd.d
for f in 10-help-text 50-motd-news 80-livepatch 91-release-upgrade; do
    touch "config/includes.chroot/etc/update-motd.d/$f"
done

echo ""
echo "Building ISO... (this takes 10-30 minutes)"
echo ""

lb build 2>&1 | tail -20

# Find the ISO
ISO=$(find . -name "*.iso" -type f | head -1)
if [ -n "$ISO" ]; then
    cp "$ISO" /output/claudeos.iso
    SIZE=$(du -sh /output/claudeos.iso | awk '{print $1}')
    echo ""
    echo "=================================="
    echo "  ISO built successfully!"
    echo "  Size: $SIZE"
    echo "  Output: /output/claudeos.iso"
    echo "=================================="
else
    echo "ERROR: ISO not found!"
    ls -la
fi
