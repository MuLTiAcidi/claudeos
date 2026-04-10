#!/bin/bash
# Install ClaudeOS CLI command globally
# Usage: sudo bash install-cli.sh

set -e

if [ "$EUID" -ne 0 ]; then
    echo "Run as root: sudo bash install-cli.sh"
    exit 1
fi

CLAUDEOS_DIR="/opt/claudeos"

# Create symlink for claudeos command
ln -sf "$CLAUDEOS_DIR/scripts/claudeos-cli.sh" /usr/local/bin/claudeos
chmod +x "$CLAUDEOS_DIR/scripts/claudeos-cli.sh"

echo "ClaudeOS CLI installed!"
echo "  Type 'claudeos' to start"
echo "  Type 'claudeos help' for commands"
echo "  Type 'claudeos status' for quick overview"
