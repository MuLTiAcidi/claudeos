#!/bin/bash
# ClaudeOS — Undo/Rollback System
# Track and reverse changes made by ClaudeOS agents
# Usage: claudeos undo [list|show|run] [id]

UNDO_DIR="${UNDO_DIR:-$HOME/.claudeos/undo}"
mkdir -p "$UNDO_DIR"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

# Public API: agents call this to record an undoable action
# Usage: claudeos-undo-record "description" "rollback-command"
record() {
    local description="$1"
    local rollback_cmd="$2"
    local id=$(date +%s%N)
    cat > "$UNDO_DIR/$id.json" <<EOF
{
  "id": "$id",
  "timestamp": "$(date -Iseconds)",
  "description": "$description",
  "rollback": "$rollback_cmd",
  "applied": false
}
EOF
    echo "$id"
}

# Snapshot a file before modifying it
snapshot_file() {
    local file="$1"
    local description="${2:-modified $file}"
    if [ ! -f "$file" ]; then
        return 1
    fi
    local id=$(date +%s%N)
    local backup="$UNDO_DIR/$id.bak"
    cp -p "$file" "$backup"
    cat > "$UNDO_DIR/$id.json" <<EOF
{
  "id": "$id",
  "timestamp": "$(date -Iseconds)",
  "description": "$description",
  "type": "file",
  "file": "$file",
  "backup": "$backup",
  "applied": false
}
EOF
    echo "$id"
}

list_undos() {
    echo ""
    echo -e "${BOLD}Undoable Actions${NC}"
    echo -e "${CYAN}──────────────────────────────────────────────────────${NC}"
    local found=0
    for f in $(ls -t "$UNDO_DIR"/*.json 2>/dev/null); do
        local id=$(basename "$f" .json)
        local timestamp=$(grep '"timestamp"' "$f" | sed 's/.*"timestamp": "\([^"]*\)".*/\1/')
        local desc=$(grep '"description"' "$f" | sed 's/.*"description": "\([^"]*\)".*/\1/')
        local applied=$(grep '"applied"' "$f" | sed 's/.*"applied": \([^,]*\).*/\1/')
        local marker="${GREEN}●${NC}"
        [ "$applied" = "true" ] && marker="${YELLOW}○${NC}"
        printf "  ${marker} ${BOLD}%-15s${NC} %s\n" "${id:0:13}" "$desc"
        printf "    ${CYAN}%s${NC}\n" "$timestamp"
        found=$((found+1))
    done
    if [ $found -eq 0 ]; then
        echo -e "${YELLOW}No undoable actions yet.${NC}"
    fi
    echo ""
    echo -e "  ${GREEN}●${NC} Reversible   ${YELLOW}○${NC} Already rolled back"
    echo ""
}

show_undo() {
    local id="$1"
    [ -z "$id" ] && echo -e "${RED}Usage: claudeos undo show <id>${NC}" && return 1

    # Find matching ID
    local file=$(ls "$UNDO_DIR"/${id}*.json 2>/dev/null | head -1)
    if [ -z "$file" ]; then
        echo -e "${RED}Undo ID not found: $id${NC}"
        return 1
    fi

    cat "$file" | (command -v jq >/dev/null && jq . || cat)
}

run_undo() {
    local id="$1"
    [ -z "$id" ] && echo -e "${RED}Usage: claudeos undo run <id>${NC}" && return 1

    local file=$(ls "$UNDO_DIR"/${id}*.json 2>/dev/null | head -1)
    if [ -z "$file" ]; then
        echo -e "${RED}Undo ID not found: $id${NC}"
        return 1
    fi

    local applied=$(grep '"applied"' "$file" | sed 's/.*"applied": \([^,}]*\).*/\1/' | tr -d ' ')
    if [ "$applied" = "true" ]; then
        echo -e "${YELLOW}Already rolled back.${NC}"
        return 0
    fi

    local desc=$(grep '"description"' "$file" | sed 's/.*"description": "\([^"]*\)".*/\1/')
    local type=$(grep '"type"' "$file" | sed 's/.*"type": "\([^"]*\)".*/\1/')

    echo -e "${BOLD}About to undo:${NC} $desc"
    read -p "Continue? (y/N) " -n 1 -r
    echo
    [[ ! $REPLY =~ ^[Yy]$ ]] && return 0

    if [ "$type" = "file" ]; then
        local target_file=$(grep '"file"' "$file" | sed 's/.*"file": "\([^"]*\)".*/\1/')
        local backup=$(grep '"backup"' "$file" | sed 's/.*"backup": "\([^"]*\)".*/\1/')
        if [ -f "$backup" ]; then
            cp -p "$backup" "$target_file"
            echo -e "${GREEN}✓${NC} Restored $target_file"
        else
            echo -e "${RED}Backup file missing: $backup${NC}"
            return 1
        fi
    else
        local rollback=$(grep '"rollback"' "$file" | sed 's/.*"rollback": "\([^"]*\)".*/\1/')
        echo -e "${CYAN}Running:${NC} $rollback"
        eval "$rollback"
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✓${NC} Rolled back"
        else
            echo -e "${RED}✗${NC} Rollback failed"
            return 1
        fi
    fi

    sed -i 's/"applied": false/"applied": true/' "$file"
}

run_last() {
    local last=$(ls -t "$UNDO_DIR"/*.json 2>/dev/null | head -1)
    [ -z "$last" ] && echo -e "${YELLOW}No undoable actions.${NC}" && return 1
    local id=$(basename "$last" .json)
    run_undo "$id"
}

clean_old() {
    local days="${1:-30}"
    find "$UNDO_DIR" -mtime +$days -delete 2>/dev/null
    echo -e "${GREEN}✓${NC} Cleaned undo records older than $days days"
}

show_help() {
    cat <<EOF

${BOLD}ClaudeOS Undo/Rollback System${NC}

${BOLD}Usage:${NC}
  claudeos undo               List all undoable actions
  claudeos undo list          Same as above
  claudeos undo last          Undo the most recent action
  claudeos undo run ID        Undo a specific action
  claudeos undo show ID       Show details of an undo record
  claudeos undo clean [days]  Remove records older than N days (default: 30)

${BOLD}For agent developers:${NC}
  claudeos undo record "desc" "rollback-cmd"   Record an undoable action
  claudeos undo snapshot FILE                  Snapshot a file before edit

${BOLD}Examples:${NC}
  claudeos undo
  claudeos undo last
  claudeos undo run 17012345
  claudeos undo clean 7

EOF
}

case "${1:-list}" in
    list|ls|"")
        list_undos
        ;;
    show)
        show_undo "$2"
        ;;
    run|do)
        run_undo "$2"
        ;;
    last|previous)
        run_last
        ;;
    clean)
        clean_old "$2"
        ;;
    record)
        record "$2" "$3"
        ;;
    snapshot)
        snapshot_file "$2" "$3"
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        show_help
        ;;
esac
