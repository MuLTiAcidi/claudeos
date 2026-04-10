# ClaudeOS Server Edition

Lightweight CLI-only server management. No GUI, minimal resources.

## Requirements
- Ubuntu 22.04+ or Debian 12+
- 512MB RAM minimum
- Node.js 20+
- Internet connection (for Claude Code CLI)

## Quick Install
```bash
curl -fsSL https://raw.githubusercontent.com/herolind/claudeos/main/install.sh | sudo bash
```

## Manual Install
```bash
git clone https://github.com/herolind/claudeos.git /opt/claudeos
cd /opt/claudeos
sudo bash scripts/setup.sh
sudo bash scripts/install-autopilot.sh
```

## Usage
```bash
claudeos              # Open AI assistant
claudeos status       # System dashboard
claudeos help         # All commands
claudeos backup       # Run backup
claudeos security     # Security audit
```

## What's Included
- 32 specialist AI agents
- Auto-pilot: health checks, security scans, backups, reports
- Self-optimizing: auto-tunes MySQL, Nginx, PHP based on your hardware
- Self-updating: weekly security patches
