#!/bin/bash
# ClaudeOS — Screenshot Helper
# Auto-screenshot URLs for PoCs and visual recon
# Usage: claudeos screenshot [url|file] [output-dir]

GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

ENGAGEMENT_DIR="$HOME/.claudeos/engagements"
ACTIVE_FILE="$HOME/.claudeos/active-engagement"

get_outdir() {
    if [ -f "$ACTIVE_FILE" ]; then
        local engagement=$(cat "$ACTIVE_FILE")
        local dir="$ENGAGEMENT_DIR/$engagement/screenshots"
        mkdir -p "$dir"
        echo "$dir"
    else
        echo "./screenshots"
    fi
}

check_tool() {
    if command -v gowitness >/dev/null 2>&1; then
        echo "gowitness"
    elif command -v aquatone >/dev/null 2>&1; then
        echo "aquatone"
    elif command -v chromium >/dev/null 2>&1; then
        echo "chromium"
    elif command -v google-chrome >/dev/null 2>&1; then
        echo "google-chrome"
    else
        echo ""
    fi
}

screenshot_one() {
    local url="$1"
    local outdir="${2:-$(get_outdir)}"
    mkdir -p "$outdir"

    local tool=$(check_tool)
    if [ -z "$tool" ]; then
        echo -e "${RED}No screenshot tool found. Install one:${NC}"
        echo -e "  ${CYAN}go install github.com/sensepost/gowitness@latest${NC}"
        echo -e "  ${CYAN}sudo apt install chromium${NC}"
        return 1
    fi

    local fname=$(echo "$url" | sed 's|https\?://||' | tr '/' '_' | tr ':' '_')
    local outfile="$outdir/${fname}.png"

    case "$tool" in
        gowitness)
            gowitness single --url "$url" -P "$outdir" 2>/dev/null
            ;;
        chromium|google-chrome)
            "$tool" --headless --disable-gpu --no-sandbox --screenshot="$outfile" --window-size=1920,1080 "$url" 2>/dev/null
            ;;
    esac

    if [ -f "$outfile" ] || ls "$outdir"/*.png 2>/dev/null | head -1 >/dev/null; then
        echo -e "${GREEN}✓${NC} Screenshot saved to $outdir"
    else
        echo -e "${RED}✗${NC} Screenshot failed"
        return 1
    fi
}

screenshot_list() {
    local file="$1"
    local outdir="${2:-$(get_outdir)}"
    [ ! -f "$file" ] && echo -e "${RED}File not found: $file${NC}" && return 1

    local tool=$(check_tool)
    case "$tool" in
        gowitness)
            gowitness file -f "$file" -P "$outdir"
            ;;
        *)
            local count=0
            local total=$(wc -l < "$file")
            while read url; do
                count=$((count+1))
                printf "\r${CYAN}[$count/$total]${NC} $url           "
                screenshot_one "$url" "$outdir" 2>/dev/null
            done < "$file"
            echo ""
            ;;
    esac
    echo -e "${GREEN}✓${NC} Done. Screenshots in: $outdir"
}

show_help() {
    cat <<EOF

${BOLD}ClaudeOS Screenshot Helper${NC}

${BOLD}Usage:${NC}
  claudeos screenshot URL [outdir]      Screenshot one URL
  claudeos screenshot file URLS [outdir]  Screenshot from file (one URL per line)

${BOLD}Examples:${NC}
  claudeos screenshot https://example.com
  claudeos screenshot file urls.txt

${BOLD}Tools used (auto-detected):${NC}
  • gowitness (preferred)
  • aquatone
  • chromium / google-chrome (headless fallback)

${BOLD}Tip:${NC} Screenshots auto-save to active engagement folder.

EOF
}

case "${1:-help}" in
    file)
        screenshot_list "$2" "$3"
        ;;
    help|--help|-h|"")
        show_help
        ;;
    *)
        if [[ "$1" =~ ^https?:// ]]; then
            screenshot_one "$1" "$2"
        else
            show_help
        fi
        ;;
esac
