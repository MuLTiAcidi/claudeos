#!/usr/bin/env python3
"""
claudeos-improve.py — Self-improvement engine for ClaudeOS agents
Tracks, reports, and manages auto-improvements made by the self-improver agent.

Usage:
    claudeos improve --stats          Show improvement statistics
    claudeos improve --recent         Show recent improvements
    claudeos improve --report         Full improvement report
    claudeos improve --export         Export as JSON
    claudeos improve --init           Initialize the improvements database
    claudeos improve <agent-name>     Show improvements for a specific agent
"""

import sys
import os
import json
import sqlite3
from pathlib import Path
from datetime import datetime

DB_PATH = os.environ.get("CLAUDEOS_IMPROVE_DB", "/var/lib/claudeos/improvements.db")
AGENTS_DIR = os.environ.get("CLAUDEOS_AGENTS", "/opt/claudeos/agents")

# Colors
class C:
    R = "\033[91m"  # red
    G = "\033[92m"  # green
    Y = "\033[93m"  # yellow
    B = "\033[94m"  # blue
    P = "\033[95m"  # purple
    BOLD = "\033[1m"
    END = "\033[0m"

def init_db():
    """Initialize the improvements database."""
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS improvements (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            agent        TEXT NOT NULL,
            failure_type TEXT NOT NULL,
            error_msg    TEXT,
            original_cmd TEXT,
            fixed_cmd    TEXT,
            description  TEXT,
            auto_fixed   BOOLEAN DEFAULT 1,
            confidence   TEXT DEFAULT 'high',
            verified     BOOLEAN DEFAULT 0,
            server_os    TEXT,
            timestamp    TEXT DEFAULT (datetime('now'))
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_agent ON improvements(agent)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_type ON improvements(failure_type)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ts ON improvements(timestamp)")
    conn.commit()
    conn.close()
    print(f"{C.G}✓{C.END} Database initialized at {DB_PATH}")

def get_db():
    """Get database connection."""
    if not Path(DB_PATH).exists():
        init_db()
    return sqlite3.connect(DB_PATH)

def cmd_stats():
    """Show improvement statistics."""
    conn = get_db()
    cur = conn.cursor()

    total = cur.execute("SELECT COUNT(*) FROM improvements").fetchone()[0]
    auto = cur.execute("SELECT COUNT(*) FROM improvements WHERE auto_fixed=1").fetchone()[0]
    manual = total - auto
    verified = cur.execute("SELECT COUNT(*) FROM improvements WHERE verified=1").fetchone()[0]

    print(f"\n{C.BOLD}{C.B}ClaudeOS Self-Improvement Stats{C.END}\n")
    print(f"  Total improvements:  {C.BOLD}{total}{C.END}")
    print(f"  Auto-fixed:          {C.G}{auto}{C.END}")
    print(f"  Manual/suggested:    {C.Y}{manual}{C.END}")
    print(f"  Verified working:    {C.G}{verified}{C.END}")

    if total > 0:
        print(f"\n{C.BOLD}By failure type:{C.END}")
        for row in cur.execute(
            "SELECT failure_type, COUNT(*) as c FROM improvements GROUP BY failure_type ORDER BY c DESC"
        ):
            bar = "█" * min(row[1], 30)
            print(f"  {row[0]:20s} {row[1]:4d} {C.B}{bar}{C.END}")

        print(f"\n{C.BOLD}Top 10 most-improved agents:{C.END}")
        for row in cur.execute(
            "SELECT agent, COUNT(*) as c FROM improvements GROUP BY agent ORDER BY c DESC LIMIT 10"
        ):
            print(f"  {C.G}{row[0]:30s}{C.END} {row[1]} fixes")

        print(f"\n{C.BOLD}By OS:{C.END}")
        for row in cur.execute(
            "SELECT COALESCE(server_os, 'unknown'), COUNT(*) FROM improvements GROUP BY server_os ORDER BY COUNT(*) DESC LIMIT 10"
        ):
            print(f"  {row[0]:25s} {row[1]} fixes")

    conn.close()

def cmd_recent(limit=20):
    """Show recent improvements."""
    conn = get_db()
    cur = conn.cursor()
    rows = cur.execute(
        "SELECT id, agent, failure_type, description, auto_fixed, verified, timestamp "
        "FROM improvements ORDER BY timestamp DESC LIMIT ?", (limit,)
    ).fetchall()

    if not rows:
        print(f"\n{C.Y}No improvements recorded yet.{C.END}")
        print(f"Run agents and let them fail — the self-improver will catch it.\n")
        conn.close()
        return

    print(f"\n{C.BOLD}{C.B}Recent Improvements (last {limit}){C.END}\n")
    for r in rows:
        auto_icon = f"{C.G}AUTO{C.END}" if r[4] else f"{C.Y}MANUAL{C.END}"
        verified_icon = f"{C.G}✓{C.END}" if r[5] else f"{C.R}?{C.END}"
        type_color = {
            "TOOL_MISSING": C.B,
            "SYNTAX_ERROR": C.Y,
            "PARSE_ERROR": C.Y,
            "DEPRECATED_TOOL": C.P,
            "FALSE_POSITIVE": C.R,
            "FALSE_NEGATIVE": C.R,
            "PERMISSION_DENIED": C.Y,
            "OS_MISMATCH": C.P,
        }.get(r[2], "")
        print(f"  #{r[0]:4d} {r[6][:19]}")
        print(f"        Agent: {C.BOLD}{r[1]}{C.END}")
        print(f"        Type:  {type_color}{r[2]}{C.END}  [{auto_icon}] [{verified_icon}]")
        if r[3]:
            print(f"        Fix:   {r[3][:100]}")
        print()

    conn.close()

def cmd_agent(agent_name):
    """Show improvements for a specific agent."""
    conn = get_db()
    cur = conn.cursor()
    rows = cur.execute(
        "SELECT id, failure_type, description, auto_fixed, verified, timestamp "
        "FROM improvements WHERE agent=? ORDER BY timestamp DESC", (agent_name,)
    ).fetchall()

    agent_file = Path(AGENTS_DIR) / agent_name / "CLAUDE.md"
    exists = agent_file.exists()

    print(f"\n{C.BOLD}{C.B}Improvements for: {agent_name}{C.END}")
    print(f"  Agent exists: {'✓' if exists else '✗'}")
    print(f"  Total improvements: {len(rows)}\n")

    for r in rows:
        print(f"  #{r[0]} [{r[1]}] {r[2] or '(no description)'} — {r[5][:19]}")

    conn.close()

def cmd_report():
    """Full improvement report in markdown."""
    conn = get_db()
    cur = conn.cursor()

    total = cur.execute("SELECT COUNT(*) FROM improvements").fetchone()[0]
    auto = cur.execute("SELECT COUNT(*) FROM improvements WHERE auto_fixed=1").fetchone()[0]
    verified = cur.execute("SELECT COUNT(*) FROM improvements WHERE verified=1").fetchone()[0]

    print(f"# ClaudeOS Self-Improvement Report")
    print(f"")
    print(f"**Generated:** {datetime.now().isoformat()}")
    print(f"**Total improvements:** {total}")
    print(f"**Auto-fixed:** {auto}")
    print(f"**Verified:** {verified}")
    print()
    print("## By Failure Type")
    print()
    print("| Type | Count |")
    print("|---|---|")
    for row in cur.execute("SELECT failure_type, COUNT(*) FROM improvements GROUP BY failure_type ORDER BY COUNT(*) DESC"):
        print(f"| {row[0]} | {row[1]} |")

    print()
    print("## Most Improved Agents")
    print()
    print("| Agent | Fixes |")
    print("|---|---|")
    for row in cur.execute("SELECT agent, COUNT(*) FROM improvements GROUP BY agent ORDER BY COUNT(*) DESC LIMIT 20"):
        print(f"| {row[0]} | {row[1]} |")

    print()
    print("## Recent Improvements")
    print()
    for row in cur.execute("SELECT agent, failure_type, description, timestamp FROM improvements ORDER BY timestamp DESC LIMIT 30"):
        print(f"- **{row[0]}** ({row[1]}): {row[2] or '(no description)'} — {row[3][:19]}")

    conn.close()

def cmd_export():
    """Export improvements as JSON."""
    conn = get_db()
    cur = conn.cursor()
    rows = cur.execute("SELECT * FROM improvements ORDER BY timestamp DESC").fetchall()
    cols = [d[0] for d in cur.description]
    result = [dict(zip(cols, row)) for row in rows]
    print(json.dumps(result, indent=2))
    conn.close()

def cmd_help():
    """Show help."""
    print(f"""
{C.BOLD}{C.B}ClaudeOS Self-Improvement Engine{C.END}

{C.BOLD}Usage:{C.END}
  claudeos improve --init           Initialize the improvements database
  claudeos improve --stats          Show improvement statistics
  claudeos improve --recent [N]     Show recent N improvements (default: 20)
  claudeos improve --report         Full improvement report (markdown)
  claudeos improve --export         Export all improvements as JSON
  claudeos improve AGENT_NAME       Show improvements for a specific agent
  claudeos improve --help           This message

{C.BOLD}How it works:{C.END}
  When any ClaudeOS agent fails during execution, the self-improver
  meta-agent detects the failure, classifies it, fixes the agent's
  CLAUDE.md playbook, retries, and commits the improvement.

  Every improvement is logged to {DB_PATH}
  and can be queried with this tool.

{C.BOLD}Examples:{C.END}
  claudeos improve --stats
  claudeos improve vulnerability-scanner
  claudeos improve --export > backup.json
""")

def main():
    args = sys.argv[1:]

    if not args or "--help" in args or "-h" in args:
        cmd_help()
    elif args[0] == "--init":
        init_db()
    elif args[0] == "--stats":
        cmd_stats()
    elif args[0] == "--recent":
        limit = int(args[1]) if len(args) > 1 else 20
        cmd_recent(limit)
    elif args[0] == "--report":
        cmd_report()
    elif args[0] == "--export":
        cmd_export()
    elif args[0].startswith("--"):
        print(f"Unknown option: {args[0]}")
        cmd_help()
    else:
        cmd_agent(args[0])

if __name__ == "__main__":
    main()
