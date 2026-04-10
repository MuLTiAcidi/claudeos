# ClaudeOS Web Dashboard Edition

Browser-based dashboard for managing your server from any device.

## Requirements
- Everything from Server Edition
- 1GB RAM minimum
- Port 8080 available

## Install
```bash
# Install Server Edition first
curl -fsSL https://raw.githubusercontent.com/MuLTiAcidi/claudeos/main/install.sh | sudo bash

# Then enable the dashboard
cd /opt/claudeos/web
npm install
sudo bash /opt/claudeos/editions/web-dashboard/install.sh
```

## Access
Open `http://your-server-ip:8080` from any browser.

## Features
- Real-time CPU/RAM/Disk monitoring with live charts
- Service management (start/stop/restart)
- Security overview with firewall and fail2ban status
- Quick action buttons (backup, update, optimize)
- Alert feed with color-coded warnings
- Responsive — works on phone, tablet, desktop
- Dark mode
- WebSocket for real-time updates (no page refresh)
