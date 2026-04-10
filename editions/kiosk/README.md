# ClaudeOS Kiosk Edition

Full-screen monitoring dashboard that auto-starts on boot. Perfect for office monitoring screens.

## Requirements
- Ubuntu 22.04+ (minimal install OK)
- 1GB RAM minimum
- Display/monitor connected
- No keyboard needed after setup

## Install
```bash
curl -fsSL https://raw.githubusercontent.com/herolind/claudeos/main/install.sh | sudo bash
sudo bash /opt/claudeos/editions/kiosk/install.sh
```

## Features
- Auto-boots into full-screen dashboard
- No login required
- Auto-refreshes every 30 seconds
- Shows all servers (multi-node compatible)
- Large fonts and indicators (readable from across the room)
- Auto-recovers from crashes
