#!/bin/bash
# ClaudeOS — Findings Tracker
# SQLite-backed tracker for bug bounty findings across programs
# Usage: claudeos findings [add|list|update|export|stats] [args]

DB_DIR="${DB_DIR:-$HOME/.claudeos}"
DB="$DB_DIR/findings.db"

mkdir -p "$DB_DIR"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

# Check sqlite3
if ! command -v sqlite3 >/dev/null 2>&1; then
    echo -e "${RED}sqlite3 is required. Install: sudo apt install -y sqlite3${NC}"
    exit 1
fi

init_db() {
    sqlite3 "$DB" <<'SQL'
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    program TEXT,
    target TEXT,
    severity TEXT CHECK(severity IN ('critical','high','medium','low','info')),
    cvss REAL,
    type TEXT,
    status TEXT DEFAULT 'new' CHECK(status IN ('new','triaged','reported','duplicate','wontfix','fixed','paid','closed')),
    discovered TEXT DEFAULT (datetime('now')),
    reported TEXT,
    resolved TEXT,
    payout REAL DEFAULT 0,
    currency TEXT DEFAULT 'USD',
    url TEXT,
    description TEXT,
    poc TEXT,
    notes TEXT,
    report_url TEXT,
    cve TEXT
);

CREATE INDEX IF NOT EXISTS idx_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_program ON findings(program);
CREATE INDEX IF NOT EXISTS idx_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_discovered ON findings(discovered);
SQL
}

add_finding() {
    init_db
    echo -e "${BOLD}${BLUE}Add New Finding${NC}"
    echo -e "${CYAN}────────────────────────────────────────${NC}"

    read -p "Title: " title
    read -p "Program (e.g. tesla, acme): " program
    read -p "Target URL/host: " target
    read -p "Type (xss/sqli/idor/ssrf/...): " type
    echo "Severity:"
    echo "  1) critical  2) high  3) medium  4) low  5) info"
    read -p "Choice [1-5]: " sev_choice
    case "$sev_choice" in
        1) severity="critical" ;;
        2) severity="high" ;;
        3) severity="medium" ;;
        4) severity="low" ;;
        5) severity="info" ;;
        *) severity="medium" ;;
    esac
    read -p "CVSS score (0-10, optional): " cvss
    read -p "URL of vulnerable endpoint: " url
    read -p "Description (one line): " description

    cvss=${cvss:-0}

    sqlite3 "$DB" <<SQL
INSERT INTO findings (title, program, target, type, severity, cvss, url, description)
VALUES ('$(echo "$title" | sed "s/'/''/g")',
        '$(echo "$program" | sed "s/'/''/g")',
        '$(echo "$target" | sed "s/'/''/g")',
        '$(echo "$type" | sed "s/'/''/g")',
        '$severity',
        $cvss,
        '$(echo "$url" | sed "s/'/''/g")',
        '$(echo "$description" | sed "s/'/''/g")');
SQL

    local id=$(sqlite3 "$DB" "SELECT last_insert_rowid();")
    echo ""
    echo -e "${GREEN}✓${NC} Finding #$id added"
    echo -e "  ${CYAN}Update later: claudeos findings update $id status reported${NC}"
}

list_findings() {
    init_db
    local filter="$1"
    local query="SELECT id, severity, status, program, title, payout FROM findings"
    case "$filter" in
        new|triaged|reported|duplicate|fixed|paid|wontfix|closed)
            query="$query WHERE status='$filter'"
            ;;
        critical|high|medium|low|info)
            query="$query WHERE severity='$filter'"
            ;;
        unpaid)
            query="$query WHERE status IN ('reported','triaged','fixed') AND (payout IS NULL OR payout=0)"
            ;;
    esac
    query="$query ORDER BY id DESC LIMIT 50;"

    echo ""
    echo -e "${BOLD}${BLUE}Findings${NC} ${filter:+(filtered: $filter)}"
    echo -e "${CYAN}─────────────────────────────────────────────────────────────────${NC}"
    printf "${BOLD}%-4s %-9s %-10s %-15s %-30s %s${NC}\n" "ID" "SEV" "STATUS" "PROGRAM" "TITLE" "PAYOUT"
    echo ""

    sqlite3 -separator '|' "$DB" "$query" | while IFS='|' read id sev status program title payout; do
        local sev_color=""
        case "$sev" in
            critical) sev_color="$RED" ;;
            high) sev_color="$RED" ;;
            medium) sev_color="$YELLOW" ;;
            low) sev_color="$BLUE" ;;
            info) sev_color="$NC" ;;
        esac
        local status_color=""
        case "$status" in
            paid) status_color="$GREEN" ;;
            reported|triaged) status_color="$YELLOW" ;;
            new) status_color="$BLUE" ;;
            duplicate|wontfix|closed) status_color="$NC" ;;
            fixed) status_color="$GREEN" ;;
        esac
        local title_short=$(echo "$title" | cut -c 1-30)
        local payout_display=""
        [ "$payout" != "0" ] && [ -n "$payout" ] && payout_display="\$$payout"
        printf "%-4s ${sev_color}%-9s${NC} ${status_color}%-10s${NC} %-15s %-30s %s\n" \
            "$id" "$sev" "$status" "$program" "$title_short" "$payout_display"
    done
    echo ""
}

show_finding() {
    init_db
    local id="$1"
    if [ -z "$id" ]; then
        echo -e "${RED}Usage: claudeos findings show <id>${NC}"
        return 1
    fi
    echo ""
    sqlite3 -line "$DB" "SELECT * FROM findings WHERE id=$id;"
    echo ""
}

update_finding() {
    init_db
    local id="$1"
    local field="$2"
    local value="$3"

    if [ -z "$id" ] || [ -z "$field" ] || [ -z "$value" ]; then
        echo -e "${RED}Usage: claudeos findings update <id> <field> <value>${NC}"
        echo -e "Fields: status, severity, payout, cvss, target, program, notes, report_url"
        return 1
    fi

    case "$field" in
        status)
            sqlite3 "$DB" "UPDATE findings SET status='$value' WHERE id=$id;"
            if [ "$value" = "reported" ]; then
                sqlite3 "$DB" "UPDATE findings SET reported=datetime('now') WHERE id=$id;"
            fi
            if [ "$value" = "fixed" ] || [ "$value" = "paid" ] || [ "$value" = "closed" ]; then
                sqlite3 "$DB" "UPDATE findings SET resolved=datetime('now') WHERE id=$id;"
            fi
            ;;
        payout)
            sqlite3 "$DB" "UPDATE findings SET payout=$value WHERE id=$id;"
            ;;
        cvss)
            sqlite3 "$DB" "UPDATE findings SET cvss=$value WHERE id=$id;"
            ;;
        *)
            sqlite3 "$DB" "UPDATE findings SET $field='$(echo "$value" | sed "s/'/''/g")' WHERE id=$id;"
            ;;
    esac
    echo -e "${GREEN}✓${NC} Updated finding #$id"
}

delete_finding() {
    init_db
    local id="$1"
    [ -z "$id" ] && echo -e "${RED}Usage: claudeos findings delete <id>${NC}" && return 1
    read -p "Delete finding #$id? (y/n) " -n 1 -r
    echo
    [[ $REPLY =~ ^[Yy]$ ]] && sqlite3 "$DB" "DELETE FROM findings WHERE id=$id;" && echo -e "${GREEN}Deleted${NC}"
}

stats() {
    init_db
    echo ""
    echo -e "${BOLD}${BLUE}Findings Statistics${NC}"
    echo -e "${CYAN}────────────────────────────────────────${NC}"

    local total=$(sqlite3 "$DB" "SELECT COUNT(*) FROM findings;")
    echo -e "${BOLD}Total findings:${NC} $total"
    echo ""

    echo -e "${BOLD}By Status:${NC}"
    sqlite3 "$DB" "SELECT status, COUNT(*) FROM findings GROUP BY status ORDER BY COUNT(*) DESC;" | while IFS='|' read status count; do
        printf "  %-12s %d\n" "$status" "$count"
    done
    echo ""

    echo -e "${BOLD}By Severity:${NC}"
    sqlite3 "$DB" "SELECT severity, COUNT(*) FROM findings GROUP BY severity ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END;" | while IFS='|' read sev count; do
        printf "  %-12s %d\n" "$sev" "$count"
    done
    echo ""

    echo -e "${BOLD}By Program:${NC}"
    sqlite3 "$DB" "SELECT program, COUNT(*) FROM findings GROUP BY program ORDER BY COUNT(*) DESC LIMIT 10;" | while IFS='|' read program count; do
        printf "  %-20s %d\n" "$program" "$count"
    done
    echo ""

    local total_payout=$(sqlite3 "$DB" "SELECT COALESCE(SUM(payout), 0) FROM findings;")
    local paid_count=$(sqlite3 "$DB" "SELECT COUNT(*) FROM findings WHERE payout > 0;")
    echo -e "${BOLD}${GREEN}Earnings:${NC}"
    echo -e "  Total payout: ${BOLD}\$$total_payout${NC}"
    echo -e "  Paid bugs:    ${BOLD}$paid_count${NC}"
    if [ "$paid_count" -gt 0 ]; then
        local avg=$(echo "scale=2; $total_payout / $paid_count" | bc 2>/dev/null || echo "0")
        echo -e "  Average:      ${BOLD}\$$avg${NC}"
    fi
    echo ""
}

export_findings() {
    init_db
    local format="${1:-json}"
    case "$format" in
        json)
            sqlite3 -json "$DB" "SELECT * FROM findings ORDER BY id;"
            ;;
        csv)
            sqlite3 -header -csv "$DB" "SELECT * FROM findings ORDER BY id;"
            ;;
        markdown|md)
            echo "# Findings Report"
            echo ""
            echo "| ID | Severity | Status | Program | Title | Payout |"
            echo "|----|----------|--------|---------|-------|--------|"
            sqlite3 -separator '|' "$DB" "SELECT id, severity, status, program, title, payout FROM findings ORDER BY id;" | while IFS='|' read id sev status program title payout; do
                echo "| $id | $sev | $status | $program | $title | \$$payout |"
            done
            ;;
        *)
            echo -e "${RED}Unknown format: $format${NC}"
            echo "Available: json, csv, markdown"
            return 1
            ;;
    esac
}

show_help() {
    cat <<EOF

${BOLD}ClaudeOS Findings Tracker${NC}

${BOLD}Usage:${NC}
  claudeos findings add                    Add new finding (interactive)
  claudeos findings list [filter]          List findings
  claudeos findings show ID                Show finding details
  claudeos findings update ID FIELD VALUE  Update a field
  claudeos findings delete ID              Delete a finding
  claudeos findings stats                  Show statistics
  claudeos findings export [json|csv|md]   Export findings

${BOLD}List filters:${NC}
  new, triaged, reported, duplicate, fixed, paid, wontfix, closed
  critical, high, medium, low, info
  unpaid (reported but not paid)

${BOLD}Update fields:${NC}
  status, severity, payout, cvss, target, program, notes, report_url

${BOLD}Examples:${NC}
  claudeos findings add
  claudeos findings list unpaid
  claudeos findings list critical
  claudeos findings update 5 status reported
  claudeos findings update 5 payout 1500
  claudeos findings stats
  claudeos findings export markdown > report.md

EOF
}

case "${1:-list}" in
    add|new)
        add_finding
        ;;
    list|ls)
        list_findings "$2"
        ;;
    show|view)
        show_finding "$2"
        ;;
    update|set)
        update_finding "$2" "$3" "$4"
        ;;
    delete|rm)
        delete_finding "$2"
        ;;
    stats|info)
        stats
        ;;
    export)
        export_findings "$2"
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        show_help
        ;;
esac
