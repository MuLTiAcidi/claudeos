#!/bin/bash
# ClaudeOS — Initial System Setup
# Run on a fresh Debian/Ubuntu system
# Usage: sudo bash setup.sh

set -e

echo "================================"
echo "  ClaudeOS — System Setup"
echo "================================"
echo ""

# Check if root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Please run as root (sudo bash setup.sh)"
    exit 1
fi

# Check OS
if ! grep -qiE "debian|ubuntu" /etc/os-release; then
    echo "WARNING: This script is designed for Debian/Ubuntu. Your OS may not be fully supported."
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then exit 1; fi
fi

echo "[1/6] Updating system..."
apt update && apt upgrade -y

echo "[2/6] Installing essential packages..."
apt install -y curl wget git htop ufw fail2ban unzip rsync nano net-tools \
    lsof iotop iftop mtr-tiny dnsutils software-properties-common \
    logrotate unattended-upgrades apt-listchanges

echo "[3/6] Configuring firewall (UFW)..."
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
echo "y" | ufw enable
echo "  → UFW enabled (SSH allowed, all other incoming denied)"

echo "[4/6] Configuring fail2ban..."
cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
backend = systemd

[sshd]
enabled = true
port = ssh
filter = sshd
maxretry = 5
EOF
systemctl enable fail2ban
systemctl restart fail2ban
echo "  → fail2ban configured for SSH (5 retries, 1hr ban)"

echo "[5/6] Setting up unattended upgrades..."
dpkg-reconfigure -f noninteractive unattended-upgrades
echo "  → Automatic security updates enabled"

echo "[6/6] Creating ClaudeOS directories..."
mkdir -p /backups /backups/configs
echo "  → Backup directories created"

# Gather system info
echo ""
echo "================================"
echo "  System Info"
echo "================================"
echo "OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '"')"
echo "Hostname: $(hostname)"
echo "IP: $(hostname -I | awk '{print $1}')"
echo "CPU: $(nproc) cores"
echo "RAM: $(free -h | awk '/Mem:/{print $2}')"
echo "Disk: $(df -h / | awk 'NR==2{print $2 " total, " $4 " free"}')"
echo "Uptime: $(uptime -p)"
echo ""
echo "================================"
echo "  ClaudeOS Setup Complete!"
echo "================================"
echo ""
echo "Your system is ready. To start using ClaudeOS:"
echo "  cd /path/to/claudeos && claude"
echo ""
echo "Security status:"
echo "  ✓ System updated"
echo "  ✓ UFW firewall enabled"
echo "  ✓ fail2ban protecting SSH"
echo "  ✓ Unattended security upgrades"
echo "  ✓ Essential tools installed"
echo ""
echo "Next steps:"
echo "  - Set up SSH key authentication"
echo "  - Configure additional firewall rules"
echo "  - Set up backups"
echo "  - Add Claude Code (npm install -g @anthropic-ai/claude-code)"
