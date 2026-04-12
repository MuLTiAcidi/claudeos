#!/bin/bash
# ClaudeOS — Friendly CLI Entry Point
# Usage: claudeos [command]

CLAUDEOS_DIR="/opt/claudeos"
VERSION="2.0.0"
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Icons (using Unicode)
OK="✓"
WARN="⚠"
FAIL="✗"
INFO="ℹ"
ARROW="→"

header() {
    echo ""
    echo -e "${BLUE}╔═══════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${WHITE}${BOLD}         ClaudeOS v${VERSION}                  ${NC}${BLUE}║${NC}"
    echo -e "${BLUE}║${CYAN}   AI-Powered Server Management            ${NC}${BLUE}║${NC}"
    echo -e "${BLUE}╚═══════════════════════════════════════════╝${NC}"
    echo ""
}

show_help() {
    header
    echo -e "${WHITE}${BOLD}Available Commands:${NC}"
    echo ""
    echo -e "  ${GREEN}claudeos${NC}                  ${ARROW} Open AI assistant (Claude)"
    echo -e "  ${GREEN}claudeos status${NC}           ${ARROW} System health dashboard"
    echo -e "  ${GREEN}claudeos dashboard${NC}        ${ARROW} Full system overview"
    echo -e "  ${GREEN}claudeos health${NC}           ${ARROW} Run health check now"
    echo -e "  ${GREEN}claudeos security${NC}         ${ARROW} Security status & audit"
    echo -e "  ${GREEN}claudeos backup${NC}           ${ARROW} Run backup now"
    echo -e "  ${GREEN}claudeos backup list${NC}      ${ARROW} Show available backups"
    echo -e "  ${GREEN}claudeos update${NC}           ${ARROW} Update system packages"
    echo -e "  ${GREEN}claudeos report${NC}           ${ARROW} Show today's report"
    echo -e "  ${GREEN}claudeos logs${NC}             ${ARROW} View recent log events"
    echo -e "  ${GREEN}claudeos services${NC}         ${ARROW} List running services"
    echo -e "  ${GREEN}claudeos firewall${NC}         ${ARROW} Firewall status & rules"
    echo -e "  ${GREEN}claudeos users${NC}            ${ARROW} List system users"
    echo -e "  ${GREEN}claudeos disk${NC}             ${ARROW} Disk usage details"
    echo -e "  ${GREEN}claudeos alerts${NC}           ${ARROW} Recent warnings & alerts"
    echo -e "  ${GREEN}claudeos setup${NC}            ${ARROW} Run setup wizard again"
    echo -e "  ${GREEN}claudeos ai${NC}               ${ARROW} Open Claude AI assistant"
    echo ""
    echo -e "${WHITE}${BOLD}Pro Features (v2.0):${NC}"
    echo ""
    echo -e "  ${GREEN}claudeos wizard${NC}           ${ARROW} First-run setup wizard"
    echo -e "  ${GREEN}claudeos agents${NC}           ${ARROW} Browse 200+ specialist agents"
    echo -e "  ${GREEN}claudeos workflow${NC}         ${ARROW} Run pre-built multi-agent workflows"
    echo -e "  ${GREEN}claudeos engagement${NC}       ${ARROW} Manage bug bounty / pentest workspaces"
    echo -e "  ${GREEN}claudeos findings${NC}         ${ARROW} Track findings, CVSS, payouts"
    echo -e "  ${GREEN}claudeos undo${NC}             ${ARROW} Roll back agent changes"
    echo -e "  ${GREEN}claudeos diff${NC}             ${ARROW} Compare scan results"
    echo -e "  ${GREEN}claudeos screenshot${NC}       ${ARROW} Auto-screenshot URLs for PoCs"
    echo -e "  ${GREEN}claudeos cheatsheet${NC}       ${ARROW} Generate agent cheat sheets"
    echo -e "  ${GREEN}claudeos telegram${NC}         ${ARROW} Telegram bot bridge"
    echo ""
    echo -e "  ${GREEN}claudeos help${NC}             ${ARROW} Show this help"
    echo -e "  ${GREEN}claudeos version${NC}          ${ARROW} Show version info"
    echo ""
    echo -e "${CYAN}${INFO} Tip: You can also just type 'claudeos' to talk to the AI assistant${NC}"
    echo -e "${CYAN}  and ask it anything in plain English!${NC}"
    echo ""
}

show_status() {
    header

    # CPU
    LOAD=$(cat /proc/loadavg 2>/dev/null | awk '{print $1}')
    CORES=$(nproc 2>/dev/null || echo 1)
    CPU_PCT=$(echo "$LOAD $CORES" | awk '{printf "%.0f", ($1/$2)*100}')
    if [ "$CPU_PCT" -gt 90 ]; then
        CPU_COLOR=$RED; CPU_ICON=$FAIL
    elif [ "$CPU_PCT" -gt 70 ]; then
        CPU_COLOR=$YELLOW; CPU_ICON=$WARN
    else
        CPU_COLOR=$GREEN; CPU_ICON=$OK
    fi

    # RAM
    RAM_TOTAL=$(free -m 2>/dev/null | awk '/Mem:/{print $2}')
    RAM_USED=$(free -m 2>/dev/null | awk '/Mem:/{print $3}')
    RAM_PCT=$((RAM_USED * 100 / RAM_TOTAL))
    if [ "$RAM_PCT" -gt 90 ]; then
        RAM_COLOR=$RED; RAM_ICON=$FAIL
    elif [ "$RAM_PCT" -gt 70 ]; then
        RAM_COLOR=$YELLOW; RAM_ICON=$WARN
    else
        RAM_COLOR=$GREEN; RAM_ICON=$OK
    fi

    # Disk
    DISK_PCT=$(df / 2>/dev/null | awk 'NR==2{print $5}' | tr -d '%')
    DISK_FREE=$(df -h / 2>/dev/null | awk 'NR==2{print $4}')
    if [ "$DISK_PCT" -gt 90 ]; then
        DISK_COLOR=$RED; DISK_ICON=$FAIL
    elif [ "$DISK_PCT" -gt 70 ]; then
        DISK_COLOR=$YELLOW; DISK_ICON=$WARN
    else
        DISK_COLOR=$GREEN; DISK_ICON=$OK
    fi

    # Uptime
    UPTIME=$(uptime -p 2>/dev/null || echo "unknown")

    echo -e "${WHITE}${BOLD}  System Health${NC}"
    echo -e "  ─────────────────────────────────────"
    echo -e "  ${CPU_COLOR}${CPU_ICON}${NC} CPU:    ${CPU_COLOR}${CPU_PCT}%${NC} (load: $LOAD, $CORES cores)"
    echo -e "  ${RAM_COLOR}${RAM_ICON}${NC} Memory: ${RAM_COLOR}${RAM_PCT}%${NC} (${RAM_USED}MB / ${RAM_TOTAL}MB)"
    echo -e "  ${DISK_COLOR}${DISK_ICON}${NC} Disk:   ${DISK_COLOR}${DISK_PCT}%${NC} used (${DISK_FREE} free)"
    echo -e "  ${GREEN}${OK}${NC} Uptime: ${UPTIME}"
    echo ""

    # Services
    echo -e "${WHITE}${BOLD}  Key Services${NC}"
    echo -e "  ─────────────────────────────────────"
    for SVC in ssh nginx apache2 mysql mariadb postgresql php*-fpm docker fail2ban ufw; do
        if systemctl is-active --quiet "$SVC" 2>/dev/null; then
            echo -e "  ${GREEN}${OK}${NC} $SVC: ${GREEN}running${NC}"
        elif systemctl list-unit-files 2>/dev/null | grep -q "^${SVC}"; then
            echo -e "  ${RED}${FAIL}${NC} $SVC: ${RED}stopped${NC}"
        fi
    done
    echo ""

    # Security
    echo -e "${WHITE}${BOLD}  Security${NC}"
    echo -e "  ─────────────────────────────────────"
    if ufw status 2>/dev/null | grep -q "active"; then
        echo -e "  ${GREEN}${OK}${NC} Firewall: ${GREEN}active${NC}"
    else
        echo -e "  ${RED}${FAIL}${NC} Firewall: ${RED}inactive${NC}"
    fi
    if systemctl is-active --quiet fail2ban 2>/dev/null; then
        BANNED=$(fail2ban-client status sshd 2>/dev/null | grep "Currently banned" | awk '{print $NF}')
        echo -e "  ${GREEN}${OK}${NC} Fail2ban: ${GREEN}active${NC} (${BANNED:-0} IPs banned)"
    fi
    FAILED_SSH=$(grep "Failed password" /var/log/auth.log 2>/dev/null | grep "$(date +%Y-%m-%d)" | wc -l)
    echo -e "  ${INFO} Failed SSH today: $FAILED_SSH"
    echo ""

    # Auto-pilot
    echo -e "${WHITE}${BOLD}  Auto-Pilot${NC}"
    echo -e "  ─────────────────────────────────────"
    if [ -f /etc/cron.d/claudeos ]; then
        echo -e "  ${GREEN}${OK}${NC} Auto-pilot: ${GREEN}enabled${NC}"
        echo -e "  ${GREEN}${OK}${NC} Health checks: every 5 min"
        echo -e "  ${GREEN}${OK}${NC} Security scans: every 15 min"
        echo -e "  ${GREEN}${OK}${NC} Daily backups: 2:00 AM"
        echo -e "  ${GREEN}${OK}${NC} Daily reports: 7:00 AM"
    else
        echo -e "  ${YELLOW}${WARN}${NC} Auto-pilot: ${YELLOW}not installed${NC}"
        echo -e "      Run: ${CYAN}sudo claudeos setup${NC}"
    fi
    echo ""

    # Recent alerts
    ALERTS=$(grep -E "\[WARNING\]|\[CRITICAL\]|\[ALERT\]" "$CLAUDEOS_DIR/logs/"*.log 2>/dev/null | tail -3)
    if [ -n "$ALERTS" ]; then
        echo -e "${WHITE}${BOLD}  Recent Alerts${NC}"
        echo -e "  ─────────────────────────────────────"
        echo "$ALERTS" | while read line; do
            if echo "$line" | grep -q "CRITICAL"; then
                echo -e "  ${RED}${FAIL} $line${NC}"
            elif echo "$line" | grep -q "ALERT"; then
                echo -e "  ${RED}${WARN} $line${NC}"
            else
                echo -e "  ${YELLOW}${WARN} $line${NC}"
            fi
        done
        echo ""
    fi
}

show_dashboard() {
    clear
    show_status
}

show_disk() {
    header
    echo -e "${WHITE}${BOLD}  Disk Usage${NC}"
    echo -e "  ─────────────────────────────────────"
    df -h | awk 'NR==1 || /^\/dev/' | while read line; do
        echo "  $line"
    done
    echo ""
    echo -e "${WHITE}${BOLD}  Largest Directories (top 10)${NC}"
    echo -e "  ─────────────────────────────────────"
    du -sh /var/log /var/www /home /tmp /backups /var/lib/mysql /var/lib/docker 2>/dev/null | sort -rh | head -10 | while read line; do
        echo "  $line"
    done
    echo ""
}

show_services() {
    header
    echo -e "${WHITE}${BOLD}  Running Services${NC}"
    echo -e "  ─────────────────────────────────────"
    systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | awk '{printf "  %-40s %s\n", $1, $4}' | head -25
    echo ""
    FAILED=$(systemctl list-units --type=service --state=failed --no-pager --no-legend 2>/dev/null)
    if [ -n "$FAILED" ]; then
        echo -e "${RED}${BOLD}  Failed Services${NC}"
        echo -e "  ─────────────────────────────────────"
        echo "$FAILED" | awk '{printf "  %-40s %s\n", $1, $4}'
        echo ""
    fi
}

show_logs() {
    header
    echo -e "${WHITE}${BOLD}  Recent ClaudeOS Events${NC}"
    echo -e "  ─────────────────────────────────────"
    cat "$CLAUDEOS_DIR/logs/"*.log 2>/dev/null | sort | tail -20 | while read line; do
        if echo "$line" | grep -q "CRITICAL"; then
            echo -e "  ${RED}$line${NC}"
        elif echo "$line" | grep -q "WARNING\|ALERT"; then
            echo -e "  ${YELLOW}$line${NC}"
        else
            echo -e "  ${NC}$line"
        fi
    done
    echo ""
}

show_report() {
    REPORT="$CLAUDEOS_DIR/logs/daily-report-$(date +%Y-%m-%d).md"
    if [ -f "$REPORT" ]; then
        cat "$REPORT"
    else
        echo -e "${YELLOW}No report for today yet. Generate one?${NC}"
        read -p "  (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            bash "$CLAUDEOS_DIR/scripts/daily-report.sh"
            cat "$REPORT"
        fi
    fi
}

show_alerts() {
    header
    echo -e "${WHITE}${BOLD}  Warnings & Alerts (last 24h)${NC}"
    echo -e "  ─────────────────────────────────────"
    grep -E "\[WARNING\]|\[CRITICAL\]|\[ALERT\]" "$CLAUDEOS_DIR/logs/"*.log 2>/dev/null | sort | tail -30 | while read line; do
        if echo "$line" | grep -q "CRITICAL"; then
            echo -e "  ${RED}$line${NC}"
        elif echo "$line" | grep -q "ALERT"; then
            echo -e "  ${RED}$line${NC}"
        else
            echo -e "  ${YELLOW}$line${NC}"
        fi
    done
    echo ""
    COUNT=$(grep -cE "\[WARNING\]|\[CRITICAL\]|\[ALERT\]" "$CLAUDEOS_DIR/logs/"*.log 2>/dev/null | awk -F: '{sum += $NF} END {print sum}')
    echo -e "  Total: ${COUNT:-0} alerts"
    echo ""
}

show_users() {
    header
    echo -e "${WHITE}${BOLD}  System Users${NC}"
    echo -e "  ─────────────────────────────────────"
    echo -e "  ${BOLD}Username         UID   Home              Shell${NC}"
    grep -E "/bin/(bash|sh|zsh)" /etc/passwd | awk -F: '{printf "  %-16s %-5s %-17s %s\n", $1, $3, $6, $7}'
    echo ""
    echo -e "${WHITE}${BOLD}  Sudo Users${NC}"
    echo -e "  ─────────────────────────────────────"
    getent group sudo 2>/dev/null | awk -F: '{print "  " $4}'
    echo ""
}

show_firewall() {
    header
    echo -e "${WHITE}${BOLD}  Firewall Status${NC}"
    echo -e "  ─────────────────────────────────────"
    ufw status verbose 2>/dev/null || echo "  UFW not installed"
    echo ""
}

run_backup() {
    header
    echo -e "${CYAN}Running backup...${NC}"
    bash "$CLAUDEOS_DIR/scripts/auto-backup.sh"
    echo -e "${GREEN}${OK} Backup complete!${NC}"
    echo ""
    tail -5 "$CLAUDEOS_DIR/logs/backup.log"
    echo ""
}

list_backups() {
    header
    echo -e "${WHITE}${BOLD}  Available Backups${NC}"
    echo -e "  ─────────────────────────────────────"
    ls -lh /backups/ 2>/dev/null | awk 'NR>1{printf "  %-45s %s %s %s\n", $9, $5, $6, $7}'
    echo ""
    TOTAL=$(du -sh /backups/ 2>/dev/null | awk '{print $1}')
    echo -e "  Total size: ${TOTAL:-0}"
    echo ""
}

run_update() {
    header
    echo -e "${CYAN}Checking for updates...${NC}"
    apt update -qq 2>/dev/null
    UPGRADES=$(apt list --upgradable 2>/dev/null | grep -c "upgradable")
    if [ "$UPGRADES" -gt 0 ]; then
        echo -e "${YELLOW}$UPGRADES packages can be updated${NC}"
        apt list --upgradable 2>/dev/null | head -15
        echo ""
        read -p "  Install updates? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            apt upgrade -y 2>&1 | tail -5
            echo -e "${GREEN}${OK} Updates installed!${NC}"
        fi
    else
        echo -e "${GREEN}${OK} System is up to date!${NC}"
    fi
    echo ""
}

run_security() {
    header
    echo -e "${CYAN}Running security check...${NC}"
    bash "$CLAUDEOS_DIR/scripts/auto-security.sh"
    echo ""
    show_firewall
}

open_ai() {
    cd "$CLAUDEOS_DIR" && claude
}

# Main command router
case "${1:-}" in
    "")
        # No args — open AI assistant
        open_ai
        ;;
    status)
        show_status
        ;;
    dashboard)
        show_dashboard
        ;;
    health)
        header
        echo -e "${CYAN}Running health check...${NC}"
        bash "$CLAUDEOS_DIR/scripts/auto-health.sh"
        echo -e "${GREEN}${OK} Health check complete!${NC}"
        tail -5 "$CLAUDEOS_DIR/logs/health.log"
        echo ""
        ;;
    security)
        run_security
        ;;
    backup)
        if [ "${2:-}" = "list" ]; then
            list_backups
        else
            run_backup
        fi
        ;;
    update)
        run_update
        ;;
    report)
        show_report
        ;;
    logs)
        show_logs
        ;;
    services)
        show_services
        ;;
    firewall)
        show_firewall
        ;;
    users)
        show_users
        ;;
    disk)
        show_disk
        ;;
    alerts)
        show_alerts
        ;;
    setup)
        bash "$CLAUDEOS_DIR/scripts/first-boot.sh"
        ;;
    wizard|onboard)
        bash "$SCRIPT_DIR/claudeos-wizard.sh"
        ;;
    agents|agent)
        shift
        bash "$SCRIPT_DIR/claudeos-agents.sh" "$@"
        ;;
    workflow|wf)
        shift
        bash "$SCRIPT_DIR/claudeos-workflow.sh" "$@"
        ;;
    engagement|engage|eng)
        shift
        bash "$SCRIPT_DIR/claudeos-engagement.sh" "$@"
        ;;
    findings|finding|find)
        shift
        bash "$SCRIPT_DIR/claudeos-findings.sh" "$@"
        ;;
    undo|rollback)
        shift
        bash "$SCRIPT_DIR/claudeos-undo.sh" "$@"
        ;;
    diff|compare)
        shift
        bash "$SCRIPT_DIR/claudeos-diff.sh" "$@"
        ;;
    screenshot|screen|shot)
        shift
        bash "$SCRIPT_DIR/claudeos-screenshot.sh" "$@"
        ;;
    cheatsheet|cheat)
        shift
        bash "$SCRIPT_DIR/claudeos-cheatsheet.sh" "$@"
        ;;
    telegram|tg)
        shift
        bash "$SCRIPT_DIR/claudeos-telegram.sh" "$@"
        ;;
    improve|self-improve)
        shift
        python3 "$SCRIPT_DIR/claudeos-improve.py" "$@"
        ;;
    quickscan|scan|qs)
        shift
        python3 "$SCRIPT_DIR/claudeos-quickscan.py" "$@"
        ;;
    ai)
        open_ai
        ;;
    help|--help|-h)
        show_help
        ;;
    version|--version|-v)
        echo "ClaudeOS v${VERSION}"
        ;;
    *)
        echo -e "${YELLOW}Unknown command: $1${NC}"
        echo -e "Run ${GREEN}claudeos help${NC} to see available commands"
        echo -e "Or just type ${GREEN}claudeos${NC} to talk to the AI assistant"
        ;;
esac
