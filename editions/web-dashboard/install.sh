#!/bin/bash
# Install ClaudeOS Web Dashboard as a systemd service

set -e

if [ "$EUID" -ne 0 ]; then
    echo "Run as root: sudo bash install.sh"
    exit 1
fi

CLAUDEOS_DIR="/opt/claudeos"

# Install Node.js dependencies
cd "$CLAUDEOS_DIR/web"
npm install --production

# Create systemd service
cat > /etc/systemd/system/claudeos-dashboard.service << EOF
[Unit]
Description=ClaudeOS Web Dashboard
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$CLAUDEOS_DIR/web
ExecStart=/usr/bin/node server.js
Restart=always
RestartSec=5
Environment=CLAUDEOS_DIR=$CLAUDEOS_DIR
Environment=CLAUDEOS_PORT=8080

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable claudeos-dashboard
systemctl start claudeos-dashboard

# Open firewall port
ufw allow 8080/tcp 2>/dev/null

echo ""
echo "ClaudeOS Web Dashboard installed!"
echo "Access at: http://$(hostname -I | awk '{print $1}'):8080"
