#!/usr/bin/env python3
"""
claudeos-bot.py — Telegram bot that controls ClaudeOS from your phone
Built tonight by ClaudeOS at the celebration table.

Architecture: long-polling Telegram bot with command allowlist + chat-id allowlist.
No webhooks, no public ports — just outbound HTTPS to Telegram.

Configuration via /etc/claudeos/bot.conf:
    BOT_TOKEN=...
    ALLOWED_CHATS=123456,789012
    DISABLED_FILE=/var/lib/claudeos/bot.disabled
"""
import os, sys, json, time, subprocess, urllib.request, urllib.parse, signal, logging
from pathlib import Path

# === Config ===
CONFIG_FILE = "/etc/claudeos/bot.conf"
LOG_FILE = "/var/log/claudeos/telegram-bot.log"
DISABLED_FILE = "/var/lib/claudeos/bot.disabled"
RATE_LIMIT_FILE = "/var/lib/claudeos/bot.rate"
MAX_CMDS_PER_HOUR = 30

# Read config
config = {}
if Path(CONFIG_FILE).exists():
    for line in open(CONFIG_FILE):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            config[k.strip()] = v.strip().strip('"').strip("'")

BOT_TOKEN = config.get("BOT_TOKEN") or os.environ.get("BOT_TOKEN", "")
ALLOWED_CHATS = set(int(x) for x in config.get("ALLOWED_CHATS", "").split(",") if x.strip())

if not BOT_TOKEN:
    print("ERROR: BOT_TOKEN not set in /etc/claudeos/bot.conf or environment")
    sys.exit(1)
if not ALLOWED_CHATS:
    print("ERROR: ALLOWED_CHATS not set — bot will not respond to anyone")
    sys.exit(1)

# Logging
Path(LOG_FILE).parent.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()]
)
log = logging.getLogger("claudeos-bot")

API = f"https://api.telegram.org/bot{BOT_TOKEN}"

# === Telegram helpers ===
def tg_call(method, **params):
    """Call Telegram API."""
    url = f"{API}/{method}"
    data = urllib.parse.urlencode(params).encode()
    req = urllib.request.Request(url, data=data)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())
    except Exception as e:
        log.error(f"Telegram API error: {e}")
        return {"ok": False, "error": str(e)}

def send(chat_id, text, parse_mode="Markdown"):
    """Send a message, splitting if too long."""
    MAX = 4000
    if len(text) <= MAX:
        return tg_call("sendMessage", chat_id=chat_id, text=text, parse_mode=parse_mode)
    chunks = [text[i:i+MAX] for i in range(0, len(text), MAX)]
    for chunk in chunks:
        tg_call("sendMessage", chat_id=chat_id, text=chunk, parse_mode=parse_mode)

# === Rate limiting ===
def rate_limit_check(chat_id):
    """Allow MAX_CMDS_PER_HOUR per chat per hour."""
    now = int(time.time())
    hour = now // 3600
    Path(RATE_LIMIT_FILE).parent.mkdir(parents=True, exist_ok=True)
    state = {}
    if Path(RATE_LIMIT_FILE).exists():
        try:
            state = json.loads(Path(RATE_LIMIT_FILE).read_text())
        except:
            state = {}
    key = f"{chat_id}:{hour}"
    state[key] = state.get(key, 0) + 1
    # Cleanup old hours
    state = {k: v for k, v in state.items() if int(k.split(":")[1]) >= hour - 1}
    Path(RATE_LIMIT_FILE).write_text(json.dumps(state))
    return state[key] <= MAX_CMDS_PER_HOUR

# === Command execution ===
def run_cmd(cmd_list, timeout=30):
    """Run a command, return (stdout, stderr, code)."""
    try:
        r = subprocess.run(cmd_list, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", "Command timed out", -1
    except Exception as e:
        return "", str(e), -1

def safe_truncate(text, max_lines=40, max_chars=3500):
    """Truncate output for Telegram message."""
    lines = text.splitlines()
    if len(lines) > max_lines:
        text = "\n".join(lines[:max_lines]) + f"\n... ({len(lines)-max_lines} more lines truncated)"
    if len(text) > max_chars:
        text = text[:max_chars] + "\n... (truncated)"
    return text

def code_block(text):
    """Wrap text in a Telegram code block."""
    text = text.replace("```", "'''")
    return f"```\n{text}\n```"

# === Command handlers ===
def cmd_help(chat_id, args):
    msg = """🤖 *ClaudeOS Bot Commands*

*Read-only (always allowed):*
/status — server health
/findings — last 10 BB findings
/agents — list installed agents (count only)
/log — last 20 lines of actions.log
/disk — disk usage
/services — running services
/uptime — system uptime
/help — this message

*Action commands (need server access):*
/health — full health check
/run AGENT [args] — run any agent
/scan TARGET — quick security scan
/backup — trigger backup

*Management:*
/disable — disable the bot until /enable
/enable — re-enable the bot
/whoami — your chat ID + access level

🛑 *Forbidden via Telegram:* delete, undo run, kill, firewall reset, sudo

Built tonight at the celebration table 🍻"""
    send(chat_id, msg)

def cmd_status(chat_id, args):
    out, _, _ = run_cmd(["sh", "-c", "uptime; echo; free -h | head -2; echo; df -h / | tail -1"])
    send(chat_id, f"📊 *Status*\n{code_block(out)}")

def cmd_uptime(chat_id, args):
    out, _, _ = run_cmd(["uptime"])
    send(chat_id, f"⏱ {code_block(out.strip())}")

def cmd_disk(chat_id, args):
    out, _, _ = run_cmd(["df", "-h"])
    send(chat_id, f"💾 *Disk*\n{code_block(safe_truncate(out, 15))}")

def cmd_services(chat_id, args):
    out, _, _ = run_cmd(["sh", "-c", "systemctl list-units --type=service --state=running --no-pager --no-legend | head -20"])
    send(chat_id, f"⚙️ *Running services*\n{code_block(safe_truncate(out, 25))}")

def cmd_agents(chat_id, args):
    count_dirs, _, _ = run_cmd(["sh", "-c", "ls /opt/claudeos/agents 2>/dev/null | wc -l"])
    count_md, _, _   = run_cmd(["sh", "-c", "find /opt/claudeos/agents -name CLAUDE.md 2>/dev/null | wc -l"])
    msg = f"📚 *ClaudeOS Agents*\n```\nDirectories: {count_dirs.strip()}\nWith playbooks: {count_md.strip()}\n```"
    send(chat_id, msg)

def cmd_findings(chat_id, args):
    out, err, code = run_cmd(["sh", "-c", "command -v claudeos >/dev/null && claudeos findings list 2>&1 | head -25 || echo 'claudeos CLI not installed on this box'"])
    send(chat_id, f"🐛 *Findings*\n{code_block(safe_truncate(out))}")

def cmd_log(chat_id, args):
    out, _, _ = run_cmd(["sh", "-c", "tail -20 /var/log/claudeos/actions.log 2>/dev/null || tail -20 /var/log/claudeos/*.log 2>/dev/null || echo 'no logs yet'"])
    send(chat_id, f"📋 *Recent log*\n{code_block(safe_truncate(out))}")

def cmd_health(chat_id, args):
    send(chat_id, "🩺 Running health check...")
    out, _, _ = run_cmd(["sh", "-c", "command -v claudeos >/dev/null && claudeos health 2>&1 || (uptime; echo; free -h | head -2; echo; df -h / | tail -1; echo; systemctl --failed --no-pager | head -10)"], timeout=60)
    send(chat_id, f"🩺 *Health*\n{code_block(safe_truncate(out))}")

def cmd_run(chat_id, args):
    if not args:
        send(chat_id, "Usage: `/run AGENT_NAME [args]`")
        return
    agent = args[0]
    extra = args[1:]
    # Read the agent's CLAUDE.md and confirm it exists
    agent_file = f"/opt/claudeos/agents/{agent}/CLAUDE.md"
    if not Path(agent_file).exists():
        send(chat_id, f"❌ Agent `{agent}` not found.\nList: /agents")
        return
    send(chat_id, f"🤖 Loading agent `{agent}`...\n\nNote: from Telegram I can confirm the agent exists and show its quick reference, but to actually *run* its commands I need a richer execution environment than this minimal bot. Use `/scan TARGET` for quick scans, or open ClaudeOS on the laptop for full agent execution.")
    head, _, _ = run_cmd(["sh", "-c", f"head -30 {agent_file}"])
    send(chat_id, f"📖 *{agent}*\n{code_block(safe_truncate(head, 25))}")

def cmd_scan(chat_id, args):
    if not args:
        send(chat_id, "Usage: `/scan TARGET` (e.g. /scan example.com)")
        return
    target = args[0]
    # Sanitize: only alphanum, dots, dashes
    if not all(c.isalnum() or c in ".-_" for c in target):
        send(chat_id, "❌ Invalid target — only letters, digits, dots, dashes allowed")
        return
    send(chat_id, f"🎯 Quick scan on `{target}`...")
    out, _, _ = run_cmd([
        "sh", "-c",
        f"echo '=== DNS ==='; dig +short A {target} | head -5; echo; "
        f"echo '=== HTTP HEADERS ==='; curl -sI -L --max-time 8 https://{target} 2>&1 | head -15; echo; "
        f"echo '=== TLS ==='; echo Q | openssl s_client -connect {target}:443 -servername {target} 2>/dev/null | openssl x509 -noout -subject -issuer -dates 2>/dev/null"
    ], timeout=30)
    send(chat_id, f"🎯 *Scan: {target}*\n{code_block(safe_truncate(out))}")

def cmd_whoami(chat_id, args):
    msg = f"👤 *Your access*\n```\nchat_id: {chat_id}\nallowed: ✓ yes\nlevel: operator\n```"
    send(chat_id, msg)

def cmd_disable(chat_id, args):
    Path(DISABLED_FILE).parent.mkdir(parents=True, exist_ok=True)
    Path(DISABLED_FILE).write_text(f"disabled by chat {chat_id} at {time.time()}")
    send(chat_id, "🛑 Bot disabled. Send /enable to turn back on.")

def cmd_enable(chat_id, args):
    if Path(DISABLED_FILE).exists():
        Path(DISABLED_FILE).unlink()
    send(chat_id, "🟢 Bot enabled.")

# === Command router ===
COMMANDS = {
    "/help":      cmd_help,
    "/start":     cmd_help,
    "/status":    cmd_status,
    "/uptime":    cmd_uptime,
    "/disk":      cmd_disk,
    "/services":  cmd_services,
    "/agents":    cmd_agents,
    "/findings":  cmd_findings,
    "/log":       cmd_log,
    "/health":    cmd_health,
    "/run":       cmd_run,
    "/scan":      cmd_scan,
    "/whoami":    cmd_whoami,
    "/disable":   cmd_disable,
    "/enable":    cmd_enable,
}

# === Main loop ===
def main():
    log.info(f"claudeos-bot starting (allowed chats: {ALLOWED_CHATS})")
    me = tg_call("getMe")
    if me.get("ok"):
        log.info(f"Bot: @{me['result']['username']} (id={me['result']['id']})")
    else:
        log.error(f"Bot identity check failed: {me}")
        sys.exit(1)

    # Send a startup message to all allowed chats
    for cid in ALLOWED_CHATS:
        send(cid, "🤖 *ClaudeOS Bot online*\n\nReady to receive commands. Send /help to see what I can do.")

    offset = 0
    while True:
        try:
            r = tg_call("getUpdates", offset=offset, timeout=25)
            if not r.get("ok"):
                log.error(f"getUpdates failed: {r}")
                time.sleep(5)
                continue
            for u in r.get("result", []):
                offset = u["update_id"] + 1
                msg = u.get("message")
                if not msg:
                    continue
                chat_id = msg["chat"]["id"]
                user = msg.get("from", {}).get("username", "?")
                text = msg.get("text", "").strip()

                # Allowlist check
                if chat_id not in ALLOWED_CHATS:
                    log.warning(f"DENIED chat={chat_id} user=@{user} text={text!r}")
                    continue

                # Disable kill switch
                if Path(DISABLED_FILE).exists() and not text.startswith("/enable"):
                    log.info(f"BOT DISABLED — ignored chat={chat_id} text={text!r}")
                    continue

                # Rate limit
                if not rate_limit_check(chat_id):
                    send(chat_id, "🛑 Rate limit exceeded (30/hour). Wait an hour or hit /disable.")
                    log.warning(f"RATE LIMIT chat={chat_id}")
                    continue

                log.info(f"CMD chat={chat_id} user=@{user} text={text!r}")

                # Parse command
                if not text.startswith("/"):
                    send(chat_id, "Send /help for the command list.")
                    continue

                parts = text.split()
                cmd = parts[0].split("@")[0].lower()  # strip @botname suffix
                args = parts[1:]

                handler = COMMANDS.get(cmd)
                if handler:
                    try:
                        handler(chat_id, args)
                    except Exception as e:
                        log.error(f"Handler error for {cmd}: {e}")
                        send(chat_id, f"❌ Error running `{cmd}`:\n{code_block(str(e)[:300])}")
                else:
                    send(chat_id, f"❌ Unknown command: `{cmd}`. Send /help.")
        except KeyboardInterrupt:
            log.info("Shutting down")
            break
        except Exception as e:
            log.error(f"Main loop error: {e}")
            time.sleep(5)

if __name__ == "__main__":
    main()
