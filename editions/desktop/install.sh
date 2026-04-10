#!/bin/bash
# Install ClaudeOS Desktop Edition

set -e

if [ "$EUID" -ne 0 ]; then
    echo "Run as root: sudo bash install.sh"
    exit 1
fi

CLAUDEOS_DIR="/opt/claudeos"

# Install Web Dashboard first
bash "$CLAUDEOS_DIR/editions/web-dashboard/install.sh"

# Create desktop application entry
cat > /usr/share/applications/claudeos.desktop << 'EOF'
[Desktop Entry]
Name=ClaudeOS
Comment=AI-Powered Server Management
Exec=xdg-open http://localhost:8080
Icon=utilities-system-monitor
Terminal=false
Type=Application
Categories=System;Monitor;
EOF

# Create terminal shortcut
cat > /usr/share/applications/claudeos-terminal.desktop << 'EOF'
[Desktop Entry]
Name=ClaudeOS Terminal
Comment=ClaudeOS AI Assistant
Exec=gnome-terminal -- bash -c "cd /opt/claudeos && claude; bash"
Icon=utilities-terminal
Terminal=false
Type=Application
Categories=System;
EOF

# Auto-start dashboard on login
mkdir -p /etc/xdg/autostart
cat > /etc/xdg/autostart/claudeos-notify.desktop << 'EOF'
[Desktop Entry]
Type=Application
Name=ClaudeOS Notifications
Exec=bash -c "sleep 10 && notify-send 'ClaudeOS' 'Dashboard ready at http://localhost:8080' --icon=dialog-information"
X-GNOME-Autostart-enabled=true
EOF

echo ""
echo "ClaudeOS Desktop Edition installed!"
echo "  - Find 'ClaudeOS' in your application menu"
echo "  - Dashboard auto-opens at http://localhost:8080"
echo "  - Desktop notifications enabled"
