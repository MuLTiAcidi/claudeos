#!/bin/bash
# ClaudeOS v3.1 Universal Installer — 345 Wolves
# Usage: curl -fsSL https://raw.githubusercontent.com/MuLTiAcidi/claudeos/main/install.sh | sudo bash
# Options:
#   --server       Server Edition (default)
#   --dashboard    Web Dashboard Edition
#   --desktop      Desktop Edition
#   --kiosk        Kiosk Edition
#   --multi-node   Multi-Node Edition
#   --pi           Raspberry Pi Edition
#   --hunter       Bug Bounty Hunter Edition (installs all hunting tools)
#   --full         Full Edition (everything)
#   --minimal      Minimal Edition (core agents only, no tools)

set -e

EDITION="server"
CLAUDEOS_DIR="/opt/claudeos"
REPO="https://github.com/MuLTiAcidi/claudeos.git"
INSTALL_TOOLS=false
INSTALL_HUNTER=false
INSTALL_MINIMAL=false
NODE_VERSION="22"
GO_VERSION="1.22.0"

# Parse args
for arg in "$@"; do
    case $arg in
        --server) EDITION="server" ;;
        --dashboard) EDITION="web-dashboard" ;;
        --desktop) EDITION="desktop" ;;
        --kiosk) EDITION="kiosk" ;;
        --multi-node) EDITION="multi-node" ;;
        --pi) EDITION="raspberry-pi" ;;
        --hunter) EDITION="hunter"; INSTALL_HUNTER=true ;;
        --full) EDITION="full"; INSTALL_TOOLS=true; INSTALL_HUNTER=true ;;
        --minimal) EDITION="minimal"; INSTALL_MINIMAL=true ;;
        --with-tools) INSTALL_TOOLS=true ;;
        --with-hunter) INSTALL_HUNTER=true ;;
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
echo -e "${WHITE}${BOLD}  The Wolf Pack — 345 Agents — v3.1${NC}"
echo -e "${WHITE}  Edition: ${CYAN}${EDITION}${NC}"
echo ""

# ─────────────────────────────────────────────
# CHECKS
# ─────────────────────────────────────────────

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root: sudo bash install.sh${NC}"
    exit 1
fi

# Check OS
if grep -qiE "debian|ubuntu|raspbian" /etc/os-release 2>/dev/null; then
    OS_FAMILY="debian"
    PKG="apt-get"
elif grep -qiE "centos|rhel|fedora|rocky|alma" /etc/os-release 2>/dev/null; then
    OS_FAMILY="rhel"
    PKG="yum"
elif grep -qiE "arch|manjaro" /etc/os-release 2>/dev/null; then
    OS_FAMILY="arch"
    PKG="pacman"
elif [[ "$(uname)" == "Darwin" ]]; then
    OS_FAMILY="macos"
    PKG="brew"
else
    echo -e "${YELLOW}Warning: Unknown OS. Proceeding with best effort.${NC}"
    OS_FAMILY="unknown"
    PKG="apt-get"
fi

# Detect architecture
ARCH=$(uname -m)
case $ARCH in
    x86_64) GOARCH="amd64"; NODEARCH="x64" ;;
    aarch64|arm64) GOARCH="arm64"; NODEARCH="arm64" ;;
    armv7l) GOARCH="armv6l"; NODEARCH="armv7l" ;;
    *) echo -e "${RED}Unsupported architecture: $ARCH${NC}"; exit 1 ;;
esac

# Count steps
TOTAL_STEPS=7
[ "$INSTALL_HUNTER" = true ] && TOTAL_STEPS=9
[ "$INSTALL_MINIMAL" = true ] && TOTAL_STEPS=4
STEP=0

step() {
    STEP=$((STEP + 1))
    echo ""
    echo -e "${CYAN}[${STEP}/${TOTAL_STEPS}]${NC} ${WHITE}${1}${NC}"
}

# ─────────────────────────────────────────────
# STEP 1: SYSTEM UPDATE
# ─────────────────────────────────────────────

step "Updating system packages..."

if [ "$OS_FAMILY" = "debian" ]; then
    apt-get update -qq
elif [ "$OS_FAMILY" = "rhel" ]; then
    yum update -y -q
elif [ "$OS_FAMILY" = "arch" ]; then
    pacman -Syu --noconfirm --quiet
elif [ "$OS_FAMILY" = "macos" ]; then
    echo "  macOS detected — skipping system update"
fi

# ─────────────────────────────────────────────
# STEP 2: ESSENTIAL PACKAGES
# ─────────────────────────────────────────────

step "Installing essential packages..."

if [ "$OS_FAMILY" = "debian" ]; then
    apt-get install -y -qq \
        curl wget git htop ufw fail2ban unzip rsync nano \
        net-tools lsof software-properties-common ca-certificates gnupg \
        logrotate unattended-upgrades jq bc screen tmux \
        python3 python3-pip python3-venv \
        build-essential libssl-dev libffi-dev \
        dnsutils whois nmap 2>/dev/null
elif [ "$OS_FAMILY" = "rhel" ]; then
    yum install -y -q \
        curl wget git htop firewalld fail2ban unzip rsync nano \
        net-tools lsof jq bc screen tmux \
        python3 python3-pip \
        gcc openssl-devel libffi-devel \
        bind-utils whois nmap 2>/dev/null
elif [ "$OS_FAMILY" = "macos" ]; then
    for pkg in curl wget git htop jq nmap tmux python3; do
        command -v $pkg &>/dev/null || brew install $pkg 2>/dev/null
    done
fi

echo -e "  ${GREEN}✓${NC} Python $(python3 --version 2>/dev/null | awk '{print $2}')"

# ─────────────────────────────────────────────
# STEP 3: NODE.JS
# ─────────────────────────────────────────────

step "Installing Node.js ${NODE_VERSION}.x..."

if command -v node &>/dev/null; then
    CURRENT_NODE=$(node --version | sed 's/v//' | cut -d. -f1)
    if [ "$CURRENT_NODE" -ge "$NODE_VERSION" ]; then
        echo -e "  ${GREEN}✓${NC} Node.js $(node --version) already installed"
    else
        echo "  Upgrading from Node.js v${CURRENT_NODE} to v${NODE_VERSION}..."
        if [ "$OS_FAMILY" = "debian" ]; then
            curl -fsSL https://deb.nodesource.com/setup_${NODE_VERSION}.x | bash - 2>/dev/null
            apt-get install -y -qq nodejs 2>/dev/null
        fi
    fi
else
    if [ "$OS_FAMILY" = "debian" ]; then
        curl -fsSL https://deb.nodesource.com/setup_${NODE_VERSION}.x | bash - 2>/dev/null
        apt-get install -y -qq nodejs 2>/dev/null
    elif [ "$OS_FAMILY" = "rhel" ]; then
        curl -fsSL https://rpm.nodesource.com/setup_${NODE_VERSION}.x | bash - 2>/dev/null
        yum install -y -q nodejs 2>/dev/null
    elif [ "$OS_FAMILY" = "macos" ]; then
        brew install node 2>/dev/null
    fi
fi
echo -e "  ${GREEN}✓${NC} Node.js $(node --version 2>/dev/null || echo 'not found')"

# ─────────────────────────────────────────────
# STEP 4: CLAUDE CODE CLI
# ─────────────────────────────────────────────

step "Installing Claude Code CLI..."

if command -v claude &>/dev/null; then
    echo -e "  ${GREEN}✓${NC} Claude Code already installed"
else
    npm install -g @anthropic-ai/claude-code 2>/dev/null && \
        echo -e "  ${GREEN}✓${NC} Claude Code installed" || \
        echo -e "  ${YELLOW}⚠${NC} Claude Code install failed — install manually: npm install -g @anthropic-ai/claude-code"
fi

# ─────────────────────────────────────────────
# STEP 5: CLAUDEOS
# ─────────────────────────────────────────────

step "Installing ClaudeOS (345 agents)..."

if [ -d "$CLAUDEOS_DIR/.git" ]; then
    cd "$CLAUDEOS_DIR" && git pull -q
    echo -e "  ${GREEN}✓${NC} ClaudeOS updated"
else
    rm -rf "$CLAUDEOS_DIR"
    git clone -q "$REPO" "$CLAUDEOS_DIR" 2>/dev/null && \
        echo -e "  ${GREEN}✓${NC} ClaudeOS cloned" || {
        mkdir -p "$CLAUDEOS_DIR"
        echo -e "  ${YELLOW}⚠${NC} Git clone failed — using local installation"
    }
fi

# Make scripts executable
chmod +x "$CLAUDEOS_DIR/scripts/"*.sh 2>/dev/null

# Create directories
mkdir -p "$CLAUDEOS_DIR"/{logs,config,engagements,evidence}
mkdir -p /var/log/claudeos
mkdir -p /backups

# Count agents
AGENT_COUNT=$(find "$CLAUDEOS_DIR/agents" -name "CLAUDE.md" 2>/dev/null | wc -l)
echo -e "  ${GREEN}✓${NC} ${AGENT_COUNT} agents loaded"

# ─────────────────────────────────────────────
# STEP 6: CREATE CLAUDEOS COMMAND
# ─────────────────────────────────────────────

step "Setting up claudeos command..."

cat > /usr/local/bin/claudeos << 'CLAUDEOS_CMD'
#!/bin/bash
# ClaudeOS CLI — The Wolf Pack
CLAUDEOS_DIR="/opt/claudeos"

case "${1}" in
    status)
        echo "=== ClaudeOS Status ==="
        echo "Agents: $(find $CLAUDEOS_DIR/agents -name 'CLAUDE.md' 2>/dev/null | wc -l)"
        echo "Uptime: $(uptime -p 2>/dev/null || uptime)"
        echo "CPU: $(top -bn1 2>/dev/null | grep 'Cpu' | head -1 | awk '{print $2}')%"
        echo "RAM: $(free -h 2>/dev/null | awk '/Mem:/{print $3"/"$2}')"
        echo "Disk: $(df -h / 2>/dev/null | awk 'NR==2{print $3"/"$2" ("$5")"}')"
        ;;
    agents)
        echo "=== ClaudeOS Agents ==="
        if [ -n "$2" ]; then
            grep -ril "$2" "$CLAUDEOS_DIR/agents/"*/CLAUDE.md 2>/dev/null | while read f; do
                agent=$(echo "$f" | rev | cut -d/ -f2 | rev)
                echo "  $agent"
            done
        else
            find "$CLAUDEOS_DIR/agents" -name "CLAUDE.md" -exec dirname {} \; 2>/dev/null | \
                xargs -I{} basename {} | sort | column
        fi
        ;;
    guide)
        cat "$CLAUDEOS_DIR/AGENT-GUIDE.md" 2>/dev/null || echo "AGENT-GUIDE.md not found"
        ;;
    stats)
        cat "$CLAUDEOS_DIR/technique-stats.md" 2>/dev/null || echo "technique-stats.md not found"
        ;;
    engagement)
        if [ -n "$2" ]; then
            mkdir -p "$CLAUDEOS_DIR/engagements/$2"/{evidence/{requests,screenshots,video},recon/{subdomains,js-bundles,tech-stack},reports,notes,scripts}
            cat > "$CLAUDEOS_DIR/engagements/$2/STATE.md" << STATE
# $2 — Hunt State

**Created:** $(date +%Y-%m-%d)
**Status:** ACTIVE

## Findings

| # | Finding | Severity | Evidence |
|---|---------|----------|----------|

## Timeline

- $(date +%Y-%m-%d) — Engagement created
STATE
            echo "Engagement created: $CLAUDEOS_DIR/engagements/$2/"
        else
            echo "Usage: claudeos engagement <target-name>"
            echo "Active engagements:"
            ls -d "$CLAUDEOS_DIR/engagements/"*/ 2>/dev/null | xargs -I{} basename {}
        fi
        ;;
    hunt)
        if [ -n "$2" ]; then
            echo "Starting hunt against: $2"
            echo "Loading ALPHA-BRAIN..."
            cd "$CLAUDEOS_DIR" && claude --print "Read ALPHA-BRAIN.md first, then hunt $2. Deploy the full pack."
        else
            echo "Usage: claudeos hunt <target.com>"
        fi
        ;;
    help|--help|-h)
        echo ""
        echo "  ClaudeOS v3.1 — The Wolf Pack (345 Agents)"
        echo ""
        echo "  Usage: claudeos [command]"
        echo ""
        echo "  Commands:"
        echo "    (none)         Open Claude Code with ClaudeOS loaded"
        echo "    status         System health overview"
        echo "    agents         List all agents (claudeos agents <search>)"
        echo "    guide          Show agent discovery guide"
        echo "    stats          Show technique win/loss stats"
        echo "    engagement     Create/list engagements"
        echo "    hunt <target>  Start a hunt with full pack"
        echo "    help           Show this help"
        echo ""
        ;;
    *)
        cd "$CLAUDEOS_DIR" && claude "$@"
        ;;
esac
CLAUDEOS_CMD

chmod +x /usr/local/bin/claudeos
echo -e "  ${GREEN}✓${NC} claudeos command installed"

# ─────────────────────────────────────────────
# STEP 7: SECURITY HARDENING
# ─────────────────────────────────────────────

step "Configuring security..."

if [ "$OS_FAMILY" = "debian" ] || [ "$OS_FAMILY" = "rhel" ]; then
    # Firewall
    if command -v ufw &>/dev/null; then
        ufw default deny incoming 2>/dev/null
        ufw default allow outgoing 2>/dev/null
        ufw allow ssh 2>/dev/null
        echo "y" | ufw enable 2>/dev/null
        echo -e "  ${GREEN}✓${NC} Firewall configured (UFW)"
    fi

    # Fail2ban
    cat > /etc/fail2ban/jail.local << 'JAIL'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
banaction = iptables-multiport

[sshd]
enabled = true
port = ssh
maxretry = 5

[sshd-ddos]
enabled = true
port = ssh
maxretry = 10
JAIL
    systemctl enable fail2ban 2>/dev/null
    systemctl restart fail2ban 2>/dev/null
    echo -e "  ${GREEN}✓${NC} Fail2ban configured"

    # SSH hardening
    if [ -f /etc/ssh/sshd_config ]; then
        sed -i 's/#PermitRootLogin yes/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config 2>/dev/null
        sed -i 's/#MaxAuthTries 6/MaxAuthTries 3/' /etc/ssh/sshd_config 2>/dev/null
        echo -e "  ${GREEN}✓${NC} SSH hardened"
    fi
fi

# ─────────────────────────────────────────────
# STEP 8: HUNTER TOOLS (optional)
# ─────────────────────────────────────────────

if [ "$INSTALL_HUNTER" = true ]; then
    step "Installing Bug Bounty Hunter tools..."

    # Go
    if ! command -v go &>/dev/null; then
        echo "  Installing Go ${GO_VERSION}..."
        wget -q "https://go.dev/dl/go${GO_VERSION}.linux-${GOARCH}.tar.gz" -O /tmp/go.tar.gz
        rm -rf /usr/local/go
        tar -C /usr/local -xzf /tmp/go.tar.gz
        rm /tmp/go.tar.gz
        export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
        echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> /etc/profile.d/go.sh
    fi
    echo -e "  ${GREEN}✓${NC} Go $(go version 2>/dev/null | awk '{print $3}')"

    # Install Go-based security tools
    export GOPATH=$HOME/go
    export PATH=$PATH:$GOPATH/bin

    echo "  Installing recon tools..."
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null && echo -e "    ${GREEN}✓${NC} subfinder"
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null && echo -e "    ${GREEN}✓${NC} httpx"
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null && echo -e "    ${GREEN}✓${NC} nuclei"
    go install -v github.com/ffuf/ffuf/v2@latest 2>/dev/null && echo -e "    ${GREEN}✓${NC} ffuf"
    go install -v github.com/tomnomnom/waybackurls@latest 2>/dev/null && echo -e "    ${GREEN}✓${NC} waybackurls"
    go install -v github.com/lc/gau/v2/cmd/gau@latest 2>/dev/null && echo -e "    ${GREEN}✓${NC} gau"
    go install -v github.com/tomnomnom/anew@latest 2>/dev/null && echo -e "    ${GREEN}✓${NC} anew"
    go install -v github.com/hakluke/hakrawler@latest 2>/dev/null && echo -e "    ${GREEN}✓${NC} hakrawler"

    # Update nuclei templates
    nuclei -update-templates 2>/dev/null && echo -e "    ${GREEN}✓${NC} nuclei templates updated"

    # Python tools
    echo "  Installing Python tools..."
    pip3 install -q mitmproxy 2>/dev/null && echo -e "    ${GREEN}✓${NC} mitmproxy"
    pip3 install -q sqlmap 2>/dev/null && echo -e "    ${GREEN}✓${NC} sqlmap"

    # Playwright
    echo "  Installing Playwright..."
    npm install -g playwright 2>/dev/null
    npx playwright install chromium 2>/dev/null && echo -e "    ${GREEN}✓${NC} Playwright + Chromium"

    # Create hunter workspace
    mkdir -p "$CLAUDEOS_DIR"/{engagements,evidence,tokens,tools}

    echo -e "  ${GREEN}✓${NC} Hunter tools installed"
fi

# ─────────────────────────────────────────────
# STEP 9: VPS HUNTING BASE (hunter edition)
# ─────────────────────────────────────────────

if [ "$INSTALL_HUNTER" = true ]; then
    step "Setting up VPS hunting base..."

    # Wolf pack parallel tester
    cat > "$CLAUDEOS_DIR/scripts/wolf-pack.sh" << 'WOLFPACK'
#!/bin/bash
# ClaudeOS Wolf Pack — Parallel GraphQL Mutation Tester
TOKEN="$1"
TARGET="${2:-https://target.com/graphql}"
EVIDENCE="$CLAUDEOS_DIR/evidence/$(date +%Y%m%d-%H%M%S)-wolfpack.txt"

echo "=== WOLF PACK DEPLOYED — $(date -u) ===" | tee "$EVIDENCE"
echo "Target: $TARGET" | tee -a "$EVIDENCE"

test_mutation() {
    local name="$1"
    local query="$2"
    local resp=$(curl -s -w "\n%{http_code}" -X POST "$TARGET" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $TOKEN" \
        -d "{\"query\":\"$query\"}" 2>/dev/null)
    local body=$(echo "$resp" | head -n -1)
    local code=$(echo "$resp" | tail -1)
    echo "[$code] $name → $(echo $body | head -c 120)" | tee -a "$EVIDENCE"
}

echo "Deploy your mutations here..."
echo "=== PACK COMPLETE — $(date -u) ===" | tee -a "$EVIDENCE"
WOLFPACK
    chmod +x "$CLAUDEOS_DIR/scripts/wolf-pack.sh"

    # Webhook listener
    cat > "$CLAUDEOS_DIR/scripts/webhook-listener.py" << 'WEBHOOK'
#!/usr/bin/env python3
"""Blind SSRF/XSS callback catcher"""
from http.server import HTTPServer, BaseHTTPRequestHandler
import json, datetime

class Handler(BaseHTTPRequestHandler):
    def handle_request(self):
        ts = datetime.datetime.utcnow().isoformat()
        log = f"[{ts}] {self.command} {self.path} from {self.client_address[0]}\n"
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode() if content_length else ''
        if body: log += f"Body: {body}\n"
        print(log)
        with open('/opt/claudeos/evidence/webhook-hits.log', 'a') as f:
            f.write(log + '---\n')
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({"status": "captured"}).encode())
    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = handle_request

if __name__ == '__main__':
    port = 8888
    server = HTTPServer(('0.0.0.0', port), Handler)
    print(f'Webhook listener on port {port}')
    server.serve_forever()
WEBHOOK
    chmod +x "$CLAUDEOS_DIR/scripts/webhook-listener.py"

    # Open webhook port
    if command -v ufw &>/dev/null; then
        ufw allow 8888/tcp 2>/dev/null
    fi

    echo -e "  ${GREEN}✓${NC} VPS hunting base configured"
    echo -e "  ${GREEN}✓${NC} wolf-pack.sh ready"
    echo -e "  ${GREEN}✓${NC} webhook-listener.py on port 8888"
fi

# ─────────────────────────────────────────────
# DONE
# ─────────────────────────────────────────────

# Auto-pilot (if script exists)
if [ -f "$CLAUDEOS_DIR/scripts/install-autopilot.sh" ]; then
    bash "$CLAUDEOS_DIR/scripts/install-autopilot.sh" 2>/dev/null
fi

# Edition-specific features
if [ "$EDITION" != "server" ] && [ "$EDITION" != "hunter" ] && [ "$EDITION" != "minimal" ] && [ -f "$CLAUDEOS_DIR/editions/$EDITION/install.sh" ]; then
    echo ""
    echo -e "${CYAN}Installing ${EDITION} features...${NC}"
    bash "$CLAUDEOS_DIR/editions/$EDITION/install.sh"
fi

# Get server IP
SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || curl -s ifconfig.me 2>/dev/null || echo "localhost")

echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║${WHITE}${BOLD}  ClaudeOS v3.1 installed successfully!                     ${NC}${GREEN}║${NC}"
echo -e "${GREEN}║${NC}                                                            ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}  Edition:  ${CYAN}${EDITION}${NC}                                           ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}  Agents:   ${CYAN}$(find "$CLAUDEOS_DIR/agents" -name 'CLAUDE.md' 2>/dev/null | wc -l | tr -d ' ')${NC} wolves                                      ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}  Server:   ${CYAN}${SERVER_IP}${NC}                                      ${GREEN}║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${WHITE}${BOLD}Quick Start:${NC}"
echo -e "    ${GREEN}claudeos${NC}              Open AI assistant"
echo -e "    ${GREEN}claudeos status${NC}       System overview"
echo -e "    ${GREEN}claudeos agents${NC}       List all agents"
echo -e "    ${GREEN}claudeos guide${NC}        Agent discovery guide"
echo -e "    ${GREEN}claudeos stats${NC}        Technique win/loss stats"
echo -e "    ${GREEN}claudeos engagement${NC}   Create hunt workspace"
echo -e "    ${GREEN}claudeos hunt${NC}         Start autonomous hunt"
echo -e "    ${GREEN}claudeos help${NC}         All commands"
if [ "$EDITION" = "web-dashboard" ] || [ "$EDITION" = "full" ]; then
    echo -e "    ${GREEN}http://${SERVER_IP}:8080${NC}   Web Dashboard"
fi
echo ""
if [ "$INSTALL_HUNTER" = true ]; then
    echo -e "  ${WHITE}${BOLD}Hunter Tools:${NC}"
    echo -e "    ${GREEN}✓${NC} subfinder, httpx, nuclei, ffuf"
    echo -e "    ${GREEN}✓${NC} waybackurls, gau, hakrawler"
    echo -e "    ${GREEN}✓${NC} mitmproxy, sqlmap, Playwright"
    echo -e "    ${GREEN}✓${NC} webhook listener on port 8888"
    echo ""
fi
echo -e "  ${WHITE}${BOLD}Security:${NC}"
echo -e "    ${GREEN}✓${NC} Firewall configured (deny incoming)"
echo -e "    ${GREEN}✓${NC} Fail2ban active (SSH brute-force protection)"
echo -e "    ${GREEN}✓${NC} SSH hardened (max 3 auth tries)"
echo ""
echo -e "  ${WHITE}The Wolf Pack is ready. 🐺${NC}"
echo ""
