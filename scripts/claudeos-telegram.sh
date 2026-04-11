#!/bin/bash
# ClaudeOS — Telegram Bot Bridge
# Send notifications and receive commands via Telegram
# Usage: claudeos telegram [send|listen|test] [args]

CONFIG_FILE="$HOME/.claudeos/config.toml"

GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

load_config() {
    if [ ! -f "$CONFIG_FILE" ]; then
        echo -e "${RED}No config file. Run: claudeos wizard${NC}"
        return 1
    fi
    BOT_TOKEN=$(grep "bot_token" "$CONFIG_FILE" | head -1 | sed 's/.*"\([^"]*\)".*/\1/')
    CHAT_ID=$(grep "chat_id" "$CONFIG_FILE" | head -1 | sed 's/.*"\([^"]*\)".*/\1/')

    if [ -z "$BOT_TOKEN" ] || [ -z "$CHAT_ID" ]; then
        echo -e "${RED}Telegram not configured. Run: claudeos wizard${NC}"
        return 1
    fi
}

send_message() {
    load_config || return 1
    local message="$1"
    [ -z "$message" ] && message=$(cat)

    curl -s -X POST "https://api.telegram.org/bot${BOT_TOKEN}/sendMessage" \
        -d chat_id="$CHAT_ID" \
        -d parse_mode="Markdown" \
        -d text="$message" > /dev/null
    echo -e "${GREEN}✓${NC} Sent"
}

send_alert() {
    load_config || return 1
    local severity="$1"
    local message="$2"
    local emoji="ℹ️"
    case "$severity" in
        critical) emoji="🚨" ;;
        high) emoji="⚠️" ;;
        warning) emoji="⚠️" ;;
        success) emoji="✅" ;;
        info) emoji="ℹ️" ;;
    esac
    send_message "$emoji *ClaudeOS Alert*

$message

\`$(hostname)\` • $(date '+%H:%M')"
}

send_finding() {
    load_config || return 1
    local title="$1"
    local severity="$2"
    local target="$3"
    local emoji="🔴"
    [ "$severity" = "high" ] && emoji="🟠"
    [ "$severity" = "medium" ] && emoji="🟡"
    [ "$severity" = "low" ] && emoji="🔵"
    [ "$severity" = "info" ] && emoji="ℹ️"

    send_message "$emoji *New Finding*

*Title:* $title
*Severity:* $severity
*Target:* \`$target\`

Run: \`claudeos findings show last\`"
}

send_file() {
    load_config || return 1
    local file="$1"
    [ ! -f "$file" ] && echo -e "${RED}File not found: $file${NC}" && return 1

    curl -s -X POST "https://api.telegram.org/bot${BOT_TOKEN}/sendDocument" \
        -F chat_id="$CHAT_ID" \
        -F document="@$file" > /dev/null
    echo -e "${GREEN}✓${NC} File sent: $file"
}

test_bot() {
    load_config || return 1
    echo -e "${CYAN}Testing bot...${NC}"
    local response=$(curl -s "https://api.telegram.org/bot${BOT_TOKEN}/getMe")
    local username=$(echo "$response" | grep -o '"username":"[^"]*"' | cut -d'"' -f4)
    if [ -n "$username" ]; then
        echo -e "${GREEN}✓${NC} Bot active: @$username"
        send_message "🤖 ClaudeOS test message from \`$(hostname)\`"
    else
        echo -e "${RED}✗${NC} Bot test failed"
        echo "$response"
    fi
}

# Listen mode: poll for commands
listen() {
    load_config || return 1
    echo -e "${CYAN}Listening for Telegram commands... (Ctrl+C to stop)${NC}"
    local offset=0
    while true; do
        local updates=$(curl -s "https://api.telegram.org/bot${BOT_TOKEN}/getUpdates?offset=$offset&timeout=30")
        local update_id=$(echo "$updates" | grep -o '"update_id":[0-9]*' | tail -1 | cut -d: -f2)
        local text=$(echo "$updates" | grep -o '"text":"[^"]*"' | tail -1 | cut -d'"' -f4)

        if [ -n "$update_id" ] && [ -n "$text" ]; then
            offset=$((update_id + 1))
            echo -e "${CYAN}Command:${NC} $text"

            case "$text" in
                /status)
                    local status=$(uptime; free -h | head -2; df -h / | tail -1)
                    send_message "*Status*
\`\`\`
$status
\`\`\`"
                    ;;
                /findings)
                    local f=$(claudeos findings stats 2>/dev/null | head -20)
                    send_message "*Findings*
\`\`\`
$f
\`\`\`"
                    ;;
                /help)
                    send_message "*Available commands:*
/status — system status
/findings — findings summary
/help — this message"
                    ;;
                *)
                    send_message "Unknown command: \`$text\`
Try /help"
                    ;;
            esac
        fi
        sleep 1
    done
}

show_help() {
    cat <<EOF

${BOLD}ClaudeOS Telegram Bridge${NC}

${BOLD}Usage:${NC}
  claudeos telegram test                       Test bot connection
  claudeos telegram send "message"             Send a message
  claudeos telegram alert SEVERITY "message"   Send styled alert
  claudeos telegram finding TITLE SEV TARGET   Send finding notification
  claudeos telegram file PATH                  Send a file/document
  claudeos telegram listen                     Listen for commands

${BOLD}Setup:${NC}
  Run ${CYAN}claudeos wizard${NC} to configure bot token and chat ID

${BOLD}Examples:${NC}
  claudeos telegram alert critical "Disk full on \$(hostname)"
  claudeos telegram finding "XSS in login" high tesla.com
  claudeos telegram file ~/scan-results.txt
  echo "Long message" | claudeos telegram send

EOF
}

case "${1:-help}" in
    test)
        test_bot
        ;;
    send)
        send_message "$2"
        ;;
    alert)
        send_alert "$2" "$3"
        ;;
    finding)
        send_finding "$2" "$3" "$4"
        ;;
    file|document)
        send_file "$2"
        ;;
    listen|listener|bot)
        listen
        ;;
    help|--help|-h|"")
        show_help
        ;;
    *)
        show_help
        ;;
esac
