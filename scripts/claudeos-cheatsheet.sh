#!/bin/bash
# ClaudeOS — Cheat Sheet Generator
# Generate one-page reference cards for any agent
# Usage: claudeos cheatsheet <agent-name> [output-file]

CLAUDEOS_DIR="${CLAUDEOS_DIR:-/opt/claudeos}"
AGENTS_DIR="$CLAUDEOS_DIR/agents"

GREEN='\033[0;32m'
CYAN='\033[0;36m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

generate() {
    local agent="$1"
    local output="${2:-/tmp/${agent}-cheatsheet.md}"
    local file="$AGENTS_DIR/$agent/CLAUDE.md"

    if [ ! -f "$file" ]; then
        echo -e "${RED}Agent not found: $agent${NC}"
        return 1
    fi

    # Extract title
    local title=$(head -1 "$file" | sed 's/^# //')
    # Extract description (You are line)
    local description=$(grep "^You are" "$file" | head -1)
    # Extract Quick Reference table if present
    local quickref=$(awk '/## Quick Reference/,/^## /' "$file" | head -50)
    # Extract code blocks (first 10)
    local examples=$(awk '/^```bash$/,/^```$/' "$file" | head -100)

    cat > "$output" <<EOF
# ${title} — Cheat Sheet

${description}

---

## Quick Commands

\`\`\`bash
$(awk '/^```bash$/{flag=1;next} /^```$/{flag=0;print "";next} flag' "$file" | head -50)
\`\`\`

---

${quickref}

---

*Generated from: $file*
*Date: $(date -Iseconds)*
EOF

    echo -e "${GREEN}✓${NC} Cheat sheet: $output"

    # Try to convert to PDF if pandoc is installed
    if command -v pandoc >/dev/null 2>&1; then
        local pdf="${output%.md}.pdf"
        pandoc "$output" -o "$pdf" 2>/dev/null && echo -e "${GREEN}✓${NC} PDF: $pdf"
    fi
}

generate_all() {
    local outdir="${1:-/tmp/claudeos-cheatsheets}"
    mkdir -p "$outdir"
    echo -e "${CYAN}Generating cheat sheets for all agents...${NC}"
    local count=0
    for d in "$AGENTS_DIR"/*/; do
        local agent=$(basename "$d")
        if [ -f "$d/CLAUDE.md" ]; then
            generate "$agent" "$outdir/${agent}.md" >/dev/null 2>&1
            count=$((count+1))
        fi
    done
    echo -e "${GREEN}✓${NC} Generated $count cheat sheets in $outdir"
}

show_help() {
    cat <<EOF

${BOLD}ClaudeOS Cheat Sheet Generator${NC}

${BOLD}Usage:${NC}
  claudeos cheatsheet AGENT [output]   Generate one cheat sheet
  claudeos cheatsheet all [outdir]     Generate for all agents

${BOLD}Examples:${NC}
  claudeos cheatsheet jwt-hunter
  claudeos cheatsheet jwt-hunter ~/jwt.md
  claudeos cheatsheet all ~/cheatsheets/

EOF
}

case "${1:-help}" in
    all)
        generate_all "$2"
        ;;
    help|--help|-h|"")
        show_help
        ;;
    *)
        generate "$1" "$2"
        ;;
esac
