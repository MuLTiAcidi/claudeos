#!/bin/bash
# Install ClaudeOS Multi-Node Edition

set -e

if [ "$EUID" -ne 0 ]; then
    echo "Run as root: sudo bash install.sh"
    exit 1
fi

CLAUDEOS_DIR="/opt/claudeos"

# Install Web Dashboard
bash "$CLAUDEOS_DIR/editions/web-dashboard/install.sh"

# Generate SSH key for server communication (if not exists)
if [ ! -f /root/.ssh/id_rsa ]; then
    ssh-keygen -t rsa -b 4096 -f /root/.ssh/id_rsa -N "" -q
    echo "SSH key generated at /root/.ssh/id_rsa"
    echo "Copy to managed servers with: ssh-copy-id user@server-ip"
fi

echo ""
echo "ClaudeOS Multi-Node Edition installed!"
echo ""
echo "Next steps:"
echo "  1. Edit /opt/claudeos/config/servers.json to add your servers"
echo "  2. Copy SSH key to each server: ssh-copy-id user@server-ip"
echo "  3. Access dashboard at: http://$(hostname -I | awk '{print $1}'):8080"
