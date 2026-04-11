#!/bin/bash
# ClaudeOS — Scan Diff Mode
# Compare two scan results to find what changed
# Usage: claudeos diff <old> <new>

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

diff_files() {
    local old="$1"
    local new="$2"

    if [ ! -f "$old" ] || [ ! -f "$new" ]; then
        echo -e "${RED}Both files must exist${NC}"
        return 1
    fi

    echo ""
    echo -e "${BOLD}Diff: ${CYAN}$old${NC} vs ${CYAN}$new${NC}"
    echo -e "${CYAN}─────────────────────────────────────────────${NC}"

    # New lines (in new but not in old)
    local added=$(comm -13 <(sort "$old") <(sort "$new"))
    # Removed lines (in old but not in new)
    local removed=$(comm -23 <(sort "$old") <(sort "$new"))

    local added_count=$(echo "$added" | grep -c .)
    local removed_count=$(echo "$removed" | grep -c .)

    echo ""
    echo -e "${BOLD}${GREEN}+ Added ($added_count):${NC}"
    if [ -n "$added" ]; then
        echo "$added" | sed "s/^/  ${GREEN}+${NC} /"
    else
        echo "  (none)"
    fi
    echo ""
    echo -e "${BOLD}${RED}- Removed ($removed_count):${NC}"
    if [ -n "$removed" ]; then
        echo "$removed" | sed "s/^/  ${RED}-${NC} /"
    else
        echo "  (none)"
    fi
    echo ""
}

diff_scans() {
    local engagement="$1"
    local engagement_dir="$HOME/.claudeos/engagements/$engagement"

    if [ ! -d "$engagement_dir" ]; then
        echo -e "${RED}Engagement not found: $engagement${NC}"
        return 1
    fi

    # Find subdomain files sorted by date
    local files=($(ls -t "$engagement_dir/recon/subdomains"*.txt 2>/dev/null))
    if [ ${#files[@]} -lt 2 ]; then
        echo -e "${YELLOW}Need at least 2 scan files in $engagement_dir/recon/${NC}"
        return 1
    fi

    diff_files "${files[1]}" "${files[0]}"
}

show_help() {
    cat <<EOF

${BOLD}ClaudeOS Diff Mode${NC}

Compare scan results to find what changed (new subdomains, new ports, etc.)

${BOLD}Usage:${NC}
  claudeos diff FILE_OLD FILE_NEW       Compare two files
  claudeos diff engagement NAME         Compare last 2 scans in an engagement

${BOLD}Examples:${NC}
  claudeos diff scan-yesterday.txt scan-today.txt
  claudeos diff engagement tesla-corp

EOF
}

case "${1:-help}" in
    engagement)
        diff_scans "$2"
        ;;
    help|--help|-h|"")
        show_help
        ;;
    *)
        if [ -f "$1" ] && [ -f "$2" ]; then
            diff_files "$1" "$2"
        else
            show_help
        fi
        ;;
esac
