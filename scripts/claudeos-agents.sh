#!/bin/bash
# ClaudeOS — Agent Discovery & Browser
# Browse, search, and read all 200+ specialist agents
# Usage: claudeos agents [list|search|show|category] [args]

CLAUDEOS_DIR="${CLAUDEOS_DIR:-/opt/claudeos}"
AGENTS_DIR="$CLAUDEOS_DIR/agents"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
WHITE='\033[1;37m'
NC='\033[0m'
BOLD='\033[1m'

# Agent category map (manually curated for clean output)
declare -A CATEGORIES
CATEGORIES["core-system"]="package-manager service-manager security network monitoring backup cron-tasks user-manager auto-pilot"
CATEGORIES["infrastructure"]="docker-manager database web-server dns-manager mail-server"
CATEGORIES["intelligence"]="incident-responder performance-tuner cost-optimizer migration"
CATEGORIES["devops"]="git-deploy environment-manager multi-server"
CATEGORIES["monitoring"]="notifications log-aggregator ssl-watchdog snapshot-manager compliance"
CATEGORIES["advanced-ops"]="firewall-visualizer crontab-auditor process-forensics capacity-planner api-gateway container-orchestrator"
CATEGORIES["white-hat"]="vulnerability-scanner security-auditor password-auditor web-app-scanner ssl-tester network-mapper patch-validator log-forensics config-hardener access-auditor encryption-enforcer compliance-checker incident-logger"
CATEGORIES["grey-hat"]="zero-day-hunter reverse-engineer traffic-analyzer exploit-researcher bug-bounty-hunter credential-tester wifi-breaker dns-poisoner session-hijacker api-fuzzer osint-gatherer"
CATEGORIES["black-hat"]="attack-chain malware-analyst data-exfiltrator ransomware-tester apt-operator social-engineer backdoor-hunter keylogger-deployer rootkit-builder c2-operator cryptojacker supply-chain-attacker"
CATEGORIES["red-team"]="red-commander attack-planner defense-breaker tool-forge recon-master persistence-agent lateral-mover exfil-operator evasion-engine implant-builder vuln-weaponizer phishing-operator report-writer blue-team-tester arsenal-manager"
CATEGORIES["bug-bounty"]="subdomain-takeover js-analyzer xss-hunter sqli-hunter ssrf-hunter idor-hunter graphql-hunter jwt-hunter cors-tester request-smuggler race-hunter cache-poisoner param-finder github-recon cloud-recon collaborator nuclei-master screenshot-hunter payload-crafter xxe-hunter ssti-hunter lfi-hunter deserialization-hunter oauth-tester saml-tester prototype-pollution-hunter csrf-hunter"
CATEGORIES["cms-frameworks"]="wordpress-hunter drupal-hunter magento-hunter laravel-hunter django-hunter"
CATEGORIES["active-directory"]="ad-attacker smb-tester kerberos-attacker ldap-tester"
CATEGORIES["cloud-native"]="aws-tester kubernetes-tester container-escape"
CATEGORIES["mobile-iot"]="android-tester ios-tester firmware-extractor bluetooth-tester"
CATEGORIES["bb-workflow"]="vuln-tracker program-monitor dupe-checker recon-orchestrator"
CATEGORIES["ai-ml-security"]="prompt-injection-tester model-extractor ai-jailbreaker"
CATEGORIES["coder"]="code-generator debugger refactorer api-designer database-designer test-writer dependency-manager doc-generator"
CATEGORIES["fixer"]="auto-healer config-fixer dependency-resolver log-doctor network-healer boot-fixer database-repair"
CATEGORIES["always-up"]="uptime-guardian failover-manager load-balancer chaos-tester ddos-shield auto-restarter redundancy-manager heartbeat-monitor"
CATEGORIES["gamer"]="game-server-manager minecraft-server steam-server game-performance player-manager mod-manager game-backup discord-bot-manager"
CATEGORIES["automation"]="script-builder cron-master webhook-listener task-automator file-watcher event-reactor api-automator email-automator report-generator cleanup-automator deploy-automator notification-router retry-engine trigger-builder batch-processor"
CATEGORIES["network-infra"]="vpn-manager proxy-manager bandwidth-monitor cluster-manager cloud-deployer firewall-architect file-manager system-profiler update-manager"
CATEGORIES["stealth"]="trace-cleaner tunnel-builder identity-rotator"

# Get one-line description from agent CLAUDE.md
get_description() {
    local agent="$1"
    local file="$AGENTS_DIR/$agent/CLAUDE.md"
    [ ! -f "$file" ] && echo "(missing)" && return
    # Get the first non-header line
    awk '/^You are/{print; exit}' "$file" | sed 's/You are the .* Agent for ClaudeOS\. //' | sed 's/You are .* for ClaudeOS\. //' | head -c 80
}

list_all() {
    echo ""
    echo -e "${BOLD}${BLUE}ClaudeOS Specialist Agents${NC}"
    echo -e "${CYAN}────────────────────────────────────────────────────────${NC}"
    local total=$(ls -1 "$AGENTS_DIR" 2>/dev/null | wc -l)
    echo -e "Total: ${BOLD}$total agents${NC} across ${BOLD}${#CATEGORIES[@]} categories${NC}"
    echo ""

    for cat in core-system infrastructure intelligence devops monitoring advanced-ops white-hat grey-hat black-hat red-team bug-bounty cms-frameworks active-directory cloud-native mobile-iot bb-workflow ai-ml-security coder fixer always-up gamer automation network-infra stealth; do
        local agents="${CATEGORIES[$cat]}"
        local count=$(echo "$agents" | wc -w)
        echo -e "${BOLD}${YELLOW}$cat${NC} (${count})"
        for a in $agents; do
            if [ -d "$AGENTS_DIR/$a" ]; then
                echo -e "  ${GREEN}•${NC} $a"
            fi
        done
        echo ""
    done
}

list_category() {
    local cat="$1"
    local agents="${CATEGORIES[$cat]}"
    if [ -z "$agents" ]; then
        echo -e "${RED}Unknown category: $cat${NC}"
        echo ""
        echo -e "${BOLD}Available categories:${NC}"
        for c in "${!CATEGORIES[@]}"; do
            echo "  • $c"
        done | sort
        return 1
    fi

    echo ""
    echo -e "${BOLD}${BLUE}Category: $cat${NC}"
    echo -e "${CYAN}────────────────────────────────────────────────────────${NC}"
    for a in $agents; do
        if [ -d "$AGENTS_DIR/$a" ]; then
            local desc=$(get_description "$a")
            printf "  ${GREEN}%-25s${NC} %s\n" "$a" "$desc"
        fi
    done
    echo ""
}

search_agents() {
    local query="$1"
    if [ -z "$query" ]; then
        echo -e "${RED}Usage: claudeos agents search <query>${NC}"
        return 1
    fi

    echo ""
    echo -e "${BOLD}${BLUE}Searching for: '$query'${NC}"
    echo -e "${CYAN}────────────────────────────────────────────────────────${NC}"

    local found=0
    # Search by name
    for d in "$AGENTS_DIR"/*/; do
        local agent=$(basename "$d")
        if echo "$agent" | grep -qi "$query"; then
            local desc=$(get_description "$agent")
            printf "  ${GREEN}%-25s${NC} %s\n" "$agent" "$desc"
            found=$((found+1))
        fi
    done

    # Search inside CLAUDE.md content (top of file only for speed)
    echo ""
    echo -e "${CYAN}Content matches:${NC}"
    for d in "$AGENTS_DIR"/*/; do
        local agent=$(basename "$d")
        local file="$d/CLAUDE.md"
        if [ -f "$file" ] && head -50 "$file" | grep -qi "$query"; then
            if ! echo "$agent" | grep -qi "$query"; then
                local desc=$(get_description "$agent")
                printf "  ${YELLOW}%-25s${NC} %s\n" "$agent" "$desc"
                found=$((found+1))
            fi
        fi
    done

    echo ""
    echo -e "Found ${BOLD}$found${NC} match(es)"
    echo ""
}

show_agent() {
    local agent="$1"
    local file="$AGENTS_DIR/$agent/CLAUDE.md"

    if [ ! -f "$file" ]; then
        echo -e "${RED}Agent not found: $agent${NC}"
        echo -e "Try: ${CYAN}claudeos agents search $agent${NC}"
        return 1
    fi

    if command -v less >/dev/null 2>&1; then
        less -R "$file"
    else
        cat "$file"
    fi
}

show_help() {
    cat <<EOF

${BOLD}${BLUE}ClaudeOS Agent Browser${NC}

${BOLD}Usage:${NC}
  claudeos agents              ${CYAN}# List all agents by category${NC}
  claudeos agents list         ${CYAN}# Same as above${NC}
  claudeos agents search QUERY ${CYAN}# Search agents by name or content${NC}
  claudeos agents show NAME    ${CYAN}# Show full agent playbook${NC}
  claudeos agents category CAT ${CYAN}# List agents in a category${NC}
  claudeos agents categories   ${CYAN}# List all categories${NC}
  claudeos agents stats        ${CYAN}# Show statistics${NC}

${BOLD}Examples:${NC}
  claudeos agents search xss
  claudeos agents show jwt-hunter
  claudeos agents category bug-bounty
  claudeos agents category red-team

EOF
}

show_categories() {
    echo ""
    echo -e "${BOLD}${BLUE}ClaudeOS Agent Categories${NC}"
    echo -e "${CYAN}────────────────────────────────────────────────────────${NC}"
    for c in core-system infrastructure intelligence devops monitoring advanced-ops white-hat grey-hat black-hat red-team bug-bounty cms-frameworks active-directory cloud-native mobile-iot bb-workflow ai-ml-security coder fixer always-up gamer automation network-infra stealth; do
        local agents="${CATEGORIES[$c]}"
        local count=$(echo "$agents" | wc -w)
        printf "  ${GREEN}%-20s${NC} %d agents\n" "$c" "$count"
    done
    echo ""
}

show_stats() {
    local total=$(ls -1 "$AGENTS_DIR" 2>/dev/null | wc -l)
    local with_content=$(find "$AGENTS_DIR" -name CLAUDE.md | wc -l)
    local total_lines=$(find "$AGENTS_DIR" -name CLAUDE.md -exec cat {} \; 2>/dev/null | wc -l)
    local total_size=$(du -sh "$AGENTS_DIR" 2>/dev/null | awk '{print $1}')

    echo ""
    echo -e "${BOLD}${BLUE}ClaudeOS Agent Statistics${NC}"
    echo -e "${CYAN}────────────────────────────────────────────────────────${NC}"
    echo -e "  Total agents:        ${BOLD}$total${NC}"
    echo -e "  With playbooks:      ${BOLD}$with_content${NC}"
    echo -e "  Total lines:         ${BOLD}$total_lines${NC}"
    echo -e "  Total size:          ${BOLD}$total_size${NC}"
    echo -e "  Categories:          ${BOLD}${#CATEGORIES[@]}${NC}"
    echo ""
}

# Main router
case "${1:-list}" in
    list|"")
        list_all
        ;;
    search)
        search_agents "$2"
        ;;
    show|view|cat)
        show_agent "$2"
        ;;
    category|cat)
        list_category "$2"
        ;;
    categories)
        show_categories
        ;;
    stats|info)
        show_stats
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        # If first arg is an agent name, show it
        if [ -d "$AGENTS_DIR/$1" ]; then
            show_agent "$1"
        else
            show_help
        fi
        ;;
esac
