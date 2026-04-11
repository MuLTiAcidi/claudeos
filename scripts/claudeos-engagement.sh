#!/bin/bash
# ClaudeOS — Engagement Manager
# Create and manage bug bounty / pentest engagement workspaces
# Usage: claudeos engagement [start|switch|list|end|info] [name]

ENGAGEMENTS_DIR="${ENGAGEMENTS_DIR:-$HOME/.claudeos/engagements}"
ACTIVE_FILE="$HOME/.claudeos/active-engagement"

mkdir -p "$ENGAGEMENTS_DIR"
mkdir -p "$HOME/.claudeos"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

active_name() {
    [ -f "$ACTIVE_FILE" ] && cat "$ACTIVE_FILE"
}

start_engagement() {
    local name="$1"
    if [ -z "$name" ]; then
        echo -e "${RED}Usage: claudeos engagement start <name>${NC}"
        return 1
    fi

    local dir="$ENGAGEMENTS_DIR/$name"
    if [ -d "$dir" ]; then
        echo -e "${YELLOW}Engagement '$name' already exists. Switching to it.${NC}"
        echo "$name" > "$ACTIVE_FILE"
        return 0
    fi

    echo -e "${CYAN}Creating engagement: ${BOLD}$name${NC}"
    mkdir -p "$dir"/{recon,scans,findings,evidence,reports,screenshots,loot,notes}

    # Initialize files
    cat > "$dir/info.json" <<EOF
{
  "name": "$name",
  "type": "bug-bounty",
  "started": "$(date -Iseconds)",
  "status": "active",
  "target": "",
  "platform": "",
  "scope_url": ""
}
EOF

    touch "$dir/scope.txt" "$dir/out-of-scope.txt"

    cat > "$dir/notes/README.md" <<EOF
# $name

**Started:** $(date -Iseconds)

## Targets
- Add in-scope assets to \`scope.txt\`
- Add out-of-scope assets to \`out-of-scope.txt\`

## Workflow
- recon/   — subdomain enum, port scans, JS files
- scans/   — nuclei, nikto, sqlmap output
- findings/ — confirmed vulnerabilities
- evidence/ — screenshots, request/response captures
- reports/ — final markdown/PDF reports
- loot/    — credentials, tokens, secrets found
- notes/   — your scratch notes
EOF

    echo "$name" > "$ACTIVE_FILE"
    echo -e "${GREEN}✓${NC} Engagement created at: $dir"
    echo -e "${GREEN}✓${NC} Now active. All findings will be saved here."
    echo ""
    echo -e "${CYAN}Next:${NC}"
    echo -e "  • Add scope: ${BOLD}echo 'example.com' >> $dir/scope.txt${NC}"
    echo -e "  • Open dir:  ${BOLD}cd $dir${NC}"
}

switch_engagement() {
    local name="$1"
    local dir="$ENGAGEMENTS_DIR/$name"
    if [ ! -d "$dir" ]; then
        echo -e "${RED}Engagement not found: $name${NC}"
        list_engagements
        return 1
    fi
    echo "$name" > "$ACTIVE_FILE"
    echo -e "${GREEN}✓${NC} Switched to engagement: ${BOLD}$name${NC}"
}

list_engagements() {
    echo ""
    echo -e "${BOLD}Engagements${NC}"
    echo -e "${CYAN}────────────────────────────────────────${NC}"
    local active=$(active_name)
    local found=0
    for d in "$ENGAGEMENTS_DIR"/*/; do
        [ -d "$d" ] || continue
        local name=$(basename "$d")
        local status="active"
        [ -f "$d/info.json" ] && status=$(grep '"status"' "$d/info.json" | sed 's/.*: "\([^"]*\)".*/\1/')
        local marker="  "
        if [ "$name" = "$active" ]; then
            marker="${GREEN}* ${NC}"
        fi
        printf "${marker}%-30s [%s]\n" "$name" "$status"
        found=$((found+1))
    done
    if [ $found -eq 0 ]; then
        echo -e "${YELLOW}No engagements yet.${NC}"
        echo -e "Create one: ${CYAN}claudeos engagement start <name>${NC}"
    fi
    echo ""
}

end_engagement() {
    local name="${1:-$(active_name)}"
    if [ -z "$name" ]; then
        echo -e "${RED}No active engagement.${NC}"
        return 1
    fi
    local dir="$ENGAGEMENTS_DIR/$name"
    if [ ! -d "$dir" ]; then
        echo -e "${RED}Engagement not found: $name${NC}"
        return 1
    fi

    if [ -f "$dir/info.json" ]; then
        sed -i 's/"status": "active"/"status": "ended"/' "$dir/info.json"
        echo -e "${GREEN}✓${NC} Engagement '${BOLD}$name${NC}' marked as ended."
        echo -e "${CYAN}Files preserved at: $dir${NC}"
    fi

    if [ "$(active_name)" = "$name" ]; then
        rm -f "$ACTIVE_FILE"
    fi
}

info_engagement() {
    local name="${1:-$(active_name)}"
    if [ -z "$name" ]; then
        echo -e "${RED}No active engagement.${NC}"
        return 1
    fi
    local dir="$ENGAGEMENTS_DIR/$name"
    if [ ! -d "$dir" ]; then
        echo -e "${RED}Engagement not found: $name${NC}"
        return 1
    fi

    echo ""
    echo -e "${BOLD}Engagement: $name${NC}"
    echo -e "${CYAN}────────────────────────────────────────${NC}"
    [ -f "$dir/info.json" ] && cat "$dir/info.json" | (command -v jq >/dev/null && jq . || cat)
    echo ""
    echo -e "${BOLD}Path:${NC} $dir"
    echo -e "${BOLD}Scope:${NC}"
    if [ -s "$dir/scope.txt" ]; then
        sed 's/^/  • /' "$dir/scope.txt"
    else
        echo "  (empty — add targets to $dir/scope.txt)"
    fi
    echo ""
    echo -e "${BOLD}Files:${NC}"
    for sub in recon scans findings evidence reports screenshots; do
        local count=$(find "$dir/$sub" -type f 2>/dev/null | wc -l)
        printf "  %-15s %d files\n" "$sub/" "$count"
    done
    echo ""
}

show_help() {
    cat <<EOF

${BOLD}ClaudeOS Engagement Manager${NC}

${BOLD}Usage:${NC}
  claudeos engagement start NAME    Create and activate a new engagement
  claudeos engagement switch NAME   Switch to an existing engagement
  claudeos engagement list          List all engagements
  claudeos engagement info [NAME]   Show details (default: active)
  claudeos engagement end [NAME]    Mark as ended (preserves files)
  claudeos engagement active        Show currently active engagement

${BOLD}Examples:${NC}
  claudeos engagement start acme-corp
  claudeos engagement start hackerone-tesla
  claudeos engagement info
  claudeos engagement list

EOF
}

case "${1:-list}" in
    start|new|create)
        start_engagement "$2"
        ;;
    switch|use)
        switch_engagement "$2"
        ;;
    list|ls)
        list_engagements
        ;;
    end|stop|finish)
        end_engagement "$2"
        ;;
    info|show)
        info_engagement "$2"
        ;;
    active|current)
        active_name && echo "Active: $(active_name)" || echo "(no active engagement)"
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        show_help
        ;;
esac
