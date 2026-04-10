#!/bin/bash
# ClaudeOS Universal Installer
# Usage: curl -fsSL https://raw.githubusercontent.com/MuLTiAcidi/claudeos/main/install.sh | sudo bash
# Options:
#   --server       Server Edition (default)
#   --dashboard    Web Dashboard Edition
#   --desktop      Desktop Edition
#   --kiosk        Kiosk Edition
#   --multi-node   Multi-Node Edition
#   --pi           Raspberry Pi Edition

set -e

EDITION="server"
CLAUDEOS_DIR="/opt/claudeos"
REPO="https://github.com/MuLTiAcidi/claudeos.git"

# Parse args
for arg in "$@"; do
    case $arg in
        --server) EDITION="server" ;;
        --dashboard) EDITION="web-dashboard" ;;
        --desktop) EDITION="desktop" ;;
        --kiosk) EDITION="kiosk" ;;
        --multi-node) EDITION="multi-node" ;;
        --pi) EDITION="raspberry-pi" ;;
    esac
done

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'
BOLD='\033[1m'

echo ""
echo -e "${BLUE}  ██████╗██╗      █████╗ ██╗   ██╗██████╗ ███████╗ ██████╗ ███████╗${NC}"
echo -e "${BLUE} ██╔════╝██║     ██╔══██╗██║   ██║██╔══██╗██╔════╝██╔═══██╗██╔════╝${NC}"
echo -e "${BLUE} ██║     ██║     ███████║██║   ██║██║  ██║█████╗  ██║   ██║███████╗${NC}"
echo -e "${BLUE} ██║     ██║     ██╔══██║██║   ██║██║  ██║██╔══╝  ██║   ██║╚════██║${NC}"
echo -e "${BLUE} ╚██████╗███████╗██║  ██║╚██████╔╝██████╔╝███████╗╚██████╔╝███████║${NC}"
echo -e "${BLUE}  ╚═════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝ ╚═════╝╚══════╝${NC}"
echo ""
echo -e "${WHITE}${BOLD}  AI-Powered Server Management — ${EDITION} Edition${NC}"
echo ""

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root: sudo bash install.sh${NC}"
    exit 1
fi

# Check OS
if ! grep -qiE "debian|ubuntu|raspbian" /etc/os-release 2>/dev/null; then
    echo -e "${YELLOW}Warning: ClaudeOS is designed for Debian/Ubuntu.${NC}"
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    [[ ! $REPLY =~ ^[Yy]$ ]] && exit 1
fi

echo -e "${CYAN}[1/6]${NC} Updating system..."
apt-get update -qq

echo -e "${CYAN}[2/6]${NC} Installing essential packages..."
apt-get install -y -qq curl wget git htop ufw fail2ban unzip rsync nano \
    net-tools lsof software-properties-common ca-certificates gnupg \
    logrotate unattended-upgrades jq bc screen tmux 2>/dev/null

echo -e "${CYAN}[3/6]${NC} Installing Node.js..."
if ! command -v node &>/dev/null; then
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash - 2>/dev/null
    apt-get install -y -qq nodejs 2>/dev/null
fi
echo "  Node.js $(node --version)"

echo -e "${CYAN}[4/6]${NC} Installing Claude Code CLI..."
if ! command -v claude &>/dev/null; then
    npm install -g @anthropic-ai/claude-code 2>/dev/null
fi

echo -e "${CYAN}[5/6]${NC} Installing ClaudeOS..."
if [ -d "$CLAUDEOS_DIR/.git" ]; then
    cd "$CLAUDEOS_DIR" && git pull -q
else
    rm -rf "$CLAUDEOS_DIR"
    git clone -q "$REPO" "$CLAUDEOS_DIR" 2>/dev/null || {
        # If git clone fails (repo doesn't exist yet), use local copy
        mkdir -p "$CLAUDEOS_DIR"
        echo "  Using local installation"
    }
fi

# Make scripts executable
chmod +x "$CLAUDEOS_DIR/scripts/"*.sh 2>/dev/null

# Create directories
mkdir -p "$CLAUDEOS_DIR/logs" /backups

# Initial security setup
echo -e "${CYAN}[6/6]${NC} Configuring security..."
ufw default deny incoming 2>/dev/null
ufw default allow outgoing 2>/dev/null
ufw allow ssh 2>/dev/null
echo "y" | ufw enable 2>/dev/null

# Configure fail2ban
cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
[sshd]
enabled = true
port = ssh
maxretry = 5
EOF
systemctl enable fail2ban 2>/dev/null
systemctl restart fail2ban 2>/dev/null

# Install auto-pilot
bash "$CLAUDEOS_DIR/scripts/install-autopilot.sh"

# Install edition-specific features
if [ "$EDITION" != "server" ] && [ -f "$CLAUDEOS_DIR/editions/$EDITION/install.sh" ]; then
    echo ""
    echo -e "${CYAN}Installing ${EDITION} features...${NC}"
    bash "$CLAUDEOS_DIR/editions/$EDITION/install.sh"
fi

# Get server IP
SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "localhost")

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║${WHITE}${BOLD}  ClaudeOS installed successfully!                 ${NC}${GREEN}║${NC}"
echo -e "${GREEN}║${NC}  Edition: ${CYAN}${EDITION}${NC}                                    ${GREEN}║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${WHITE}Quick Start:${NC}"
echo -e "    ${GREEN}claudeos${NC}           Open AI assistant"
echo -e "    ${GREEN}claudeos status${NC}    System overview"
echo -e "    ${GREEN}claudeos help${NC}      All commands"
if [ "$EDITION" != "server" ] && [ "$EDITION" != "raspberry-pi" ]; then
    echo -e "    ${GREEN}http://${SERVER_IP}:8080${NC}   Web Dashboard"
fi
echo ""
echo -e "  ${WHITE}Auto-Pilot Active:${NC}"
echo -e "    ${GREEN}✓${NC} Health monitoring    (every 5 min)"
echo -e "    ${GREEN}✓${NC} Security scanning    (every 15 min)"
echo -e "    ${GREEN}✓${NC} Automated backups    (daily)"
echo -e "    ${GREEN}✓${NC} Daily reports        (7 AM)"
echo -e "    ${GREEN}✓${NC} Auto-optimization    (weekly)"
echo ""
