#!/bin/bash
# ClaudeOS Self-Update
# Checks for and applies updates to ClaudeOS agents and scripts

CLAUDEOS_DIR="/opt/claudeos"
LOG="$CLAUDEOS_DIR/logs/actions.log"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

echo "[$TIMESTAMP] [INFO] [update] Checking for ClaudeOS updates..." >> "$LOG"

# Update Claude Code CLI
echo "Checking Claude Code CLI..."
CURRENT_VERSION=$(claude --version 2>/dev/null || echo "not installed")
npm update -g @anthropic-ai/claude-code 2>/dev/null
NEW_VERSION=$(claude --version 2>/dev/null || echo "not installed")

if [ "$CURRENT_VERSION" != "$NEW_VERSION" ]; then
    echo "[$TIMESTAMP] [INFO] [update] Claude Code updated: $CURRENT_VERSION -> $NEW_VERSION" >> "$LOG"
    echo "Claude Code updated to $NEW_VERSION"
else
    echo "Claude Code is up to date ($CURRENT_VERSION)"
fi

# Update system packages (security only)
echo "Checking system security updates..."
apt update -qq 2>/dev/null
SECURITY_UPDATES=$(apt list --upgradable 2>/dev/null | grep -i security | wc -l)
if [ "$SECURITY_UPDATES" -gt 0 ]; then
    echo "$SECURITY_UPDATES security updates available"
    unattended-upgrade -d 2>/dev/null
    echo "[$TIMESTAMP] [INFO] [update] Applied $SECURITY_UPDATES security updates" >> "$LOG"
else
    echo "No security updates needed"
fi

echo ""
echo "ClaudeOS update check complete"
