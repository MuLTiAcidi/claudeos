# ClaudeOS Multi-Node Edition

Manage multiple servers from one central dashboard.

## Requirements
- One "controller" server with ClaudeOS installed
- SSH access to all managed servers
- 2GB RAM minimum on controller

## Install
```bash
curl -fsSL https://raw.githubusercontent.com/MuLTiAcidi/claudeos/main/install.sh | sudo bash
sudo bash /opt/claudeos/editions/multi-node/install.sh
```

## Add Servers
Edit `/opt/claudeos/config/servers.json` to add your servers:
```json
{
  "servers": [
    { "name": "web-01", "host": "192.168.1.10", "user": "root", "key": "~/.ssh/id_rsa" }
  ]
}
```

## Features
- Central dashboard showing all servers
- Run commands across all servers simultaneously
- Fleet-wide health monitoring
- Deploy to multiple servers at once
- Compare server configurations
- Single pane of glass for your entire infrastructure
