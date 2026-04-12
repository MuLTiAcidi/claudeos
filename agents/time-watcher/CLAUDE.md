# Time Watcher Agent
# Continuous Target Monitoring for Changes
# SQLite-backed state with webhook/Telegram alerts

## Purpose
Monitor bug bounty targets over time for changes that indicate new attack surface:
new subdomains, new endpoints, certificate changes, header changes, DNS record changes.
Alerts you the moment something changes so you can be first to test new features.

## Usage
```
time-watcher add <domain> [--interval 1h] [--webhook URL] [--telegram BOT:CHAT]
time-watcher check <domain>
time-watcher check-all
time-watcher status
time-watcher history <domain> [--last 30]
time-watcher setup-cron [--interval 1h]
```

## Environment Requirements
- Python 3.10+, requests, sqlite3 (built-in)
- Optional: subfinder, httpx, dig
- Optional: Telegram bot token, webhook URL (Slack/Discord)

## Database Schema

```sql
CREATE TABLE IF NOT EXISTS targets (
    domain TEXT PRIMARY KEY,
    added_at TEXT NOT NULL,
    last_checked TEXT,
    check_interval_seconds INTEGER DEFAULT 3600,
    webhook_url TEXT,
    telegram_config TEXT,
    enabled INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS subdomains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    subdomain TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    status TEXT DEFAULT 'active',
    UNIQUE(domain, subdomain)
);

CREATE TABLE IF NOT EXISTS endpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    url TEXT NOT NULL,
    status_code INTEGER,
    content_hash TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    UNIQUE(domain, url)
);

CREATE TABLE IF NOT EXISTS headers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    header_name TEXT NOT NULL,
    header_value TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    UNIQUE(domain, header_name, header_value)
);

CREATE TABLE IF NOT EXISTS dns_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    record_type TEXT NOT NULL,
    record_value TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    UNIQUE(domain, record_type, record_value)
);

CREATE TABLE IF NOT EXISTS certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    subject TEXT,
    issuer TEXT,
    not_before TEXT,
    not_after TEXT,
    serial TEXT,
    fingerprint TEXT,
    first_seen TEXT NOT NULL,
    UNIQUE(domain, fingerprint)
);

CREATE TABLE IF NOT EXISTS changes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    change_type TEXT NOT NULL,
    description TEXT NOT NULL,
    old_value TEXT,
    new_value TEXT,
    detected_at TEXT NOT NULL,
    alerted INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_changes_domain ON changes(domain);
CREATE INDEX IF NOT EXISTS idx_changes_detected ON changes(detected_at);
```

## Full Implementation

```python
#!/usr/bin/env python3
"""
time_watcher.py - Continuous Target Monitor
Usage: python3 time_watcher.py add example.com --interval 1h
       python3 time_watcher.py check-all
"""

import argparse
import hashlib
import json
import os
import re
import sqlite3
import ssl
import socket
import subprocess
import sys
import time
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple
from pathlib import Path

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("[!] pip install requests")
    sys.exit(1)


DB_PATH = os.path.expanduser("~/.time_watcher/state.db")


class Database:
    def __init__(self, db_path=DB_PATH):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self):
        schema = """
        CREATE TABLE IF NOT EXISTS targets (
            domain TEXT PRIMARY KEY, added_at TEXT NOT NULL,
            last_checked TEXT, check_interval_seconds INTEGER DEFAULT 3600,
            webhook_url TEXT, telegram_config TEXT, enabled INTEGER DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS subdomains (
            id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT NOT NULL,
            subdomain TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
            status TEXT DEFAULT 'active', UNIQUE(domain, subdomain)
        );
        CREATE TABLE IF NOT EXISTS endpoints (
            id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT NOT NULL,
            url TEXT NOT NULL, status_code INTEGER, content_hash TEXT,
            first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, UNIQUE(domain, url)
        );
        CREATE TABLE IF NOT EXISTS headers (
            id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT NOT NULL,
            header_name TEXT NOT NULL, header_value TEXT NOT NULL,
            first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
            UNIQUE(domain, header_name, header_value)
        );
        CREATE TABLE IF NOT EXISTS dns_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT NOT NULL,
            record_type TEXT NOT NULL, record_value TEXT NOT NULL,
            first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
            UNIQUE(domain, record_type, record_value)
        );
        CREATE TABLE IF NOT EXISTS certificates (
            id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT NOT NULL,
            subject TEXT, issuer TEXT, not_before TEXT, not_after TEXT,
            serial TEXT, fingerprint TEXT, first_seen TEXT NOT NULL,
            UNIQUE(domain, fingerprint)
        );
        CREATE TABLE IF NOT EXISTS changes (
            id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT NOT NULL,
            change_type TEXT NOT NULL, description TEXT NOT NULL,
            old_value TEXT, new_value TEXT, detected_at TEXT NOT NULL,
            alerted INTEGER DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_changes_domain ON changes(domain);
        CREATE INDEX IF NOT EXISTS idx_changes_detected ON changes(detected_at);
        """
        self.conn.executescript(schema)

    def execute(self, sql, params=()):
        return self.conn.execute(sql, params)

    def commit(self):
        self.conn.commit()

    def fetchall(self, sql, params=()):
        return self.conn.execute(sql, params).fetchall()

    def fetchone(self, sql, params=()):
        return self.conn.execute(sql, params).fetchone()


class AlertManager:
    def __init__(self, webhook_url=None, telegram_config=None):
        self.webhook_url = webhook_url
        self.telegram_config = telegram_config  # "BOT_TOKEN:CHAT_ID"

    def send_alert(self, title: str, message: str, severity: str = "info"):
        """Send alert via all configured channels."""
        prefix = {"critical": "[!!!]", "high": "[!!]", "medium": "[!]", "info": "[*]"}.get(severity, "[*]")
        full_message = f"{prefix} {title}\n{message}"

        print(f"\n  ALERT: {full_message}")

        if self.webhook_url:
            self._send_webhook(title, message, severity)
        if self.telegram_config:
            self._send_telegram(full_message)

    def _send_webhook(self, title: str, message: str, severity: str):
        """Send to Slack/Discord-compatible webhook."""
        color = {"critical": "#FF0000", "high": "#FF6600", "medium": "#FFAA00"}.get(severity, "#00FF00")
        payload = {
            "text": f"*{title}*",
            "attachments": [{
                "color": color,
                "text": message,
                "ts": int(time.time()),
            }],
        }
        # Discord format
        if "discord" in (self.webhook_url or ""):
            payload = {
                "embeds": [{
                    "title": title,
                    "description": message,
                    "color": int(color.replace("#", ""), 16),
                }]
            }
        try:
            requests.post(self.webhook_url, json=payload, timeout=10)
        except Exception as e:
            print(f"  [!] Webhook failed: {e}")

    def _send_telegram(self, message: str):
        """Send via Telegram Bot API."""
        if not self.telegram_config or ":" not in self.telegram_config:
            return
        parts = self.telegram_config.split(":", 1)
        if len(parts) != 2:
            return
        bot_token, chat_id = parts[0], parts[1]
        # Telegram bot tokens contain a colon, so we need the first part before the first colon
        # as the numeric ID and the rest as the hash, then the chat_id after the last colon
        # Format is actually: "BOTTOKEN:CHATID" where BOTTOKEN itself contains a colon
        # Let's use a different delimiter
        # Expecting format: "123456:ABCdef:CHAT_ID" -> bot token is "123456:ABCdef", chat_id is "CHAT_ID"
        parts = self.telegram_config.rsplit(":", 1)
        bot_token, chat_id = parts[0], parts[1]
        try:
            requests.post(
                f"https://api.telegram.org/bot{bot_token}/sendMessage",
                json={"chat_id": chat_id, "text": message, "parse_mode": "Markdown"},
                timeout=10,
            )
        except Exception as e:
            print(f"  [!] Telegram failed: {e}")


class TimeWatcher:
    def __init__(self, db_path=DB_PATH):
        self.db = Database(db_path)
        self.now = datetime.utcnow().isoformat()

    def add_target(self, domain: str, interval: int = 3600,
                   webhook_url: str = None, telegram_config: str = None):
        """Add a domain to monitor."""
        self.db.execute(
            "INSERT OR REPLACE INTO targets (domain, added_at, check_interval_seconds, webhook_url, telegram_config) VALUES (?, ?, ?, ?, ?)",
            (domain, self.now, interval, webhook_url, telegram_config),
        )
        self.db.commit()
        print(f"[+] Added {domain} (check every {interval}s)")

        # Run initial check
        self.check_target(domain)

    def check_target(self, domain: str):
        """Run all checks on a single target."""
        target = self.db.fetchone("SELECT * FROM targets WHERE domain = ?", (domain,))
        if not target:
            print(f"[!] Target {domain} not found. Use 'add' first.")
            return

        alerter = AlertManager(
            webhook_url=target["webhook_url"],
            telegram_config=target["telegram_config"],
        )

        print(f"\n[*] Checking {domain}...")
        changes = []

        # Check subdomains
        changes.extend(self._check_subdomains(domain))

        # Check DNS records
        changes.extend(self._check_dns(domain))

        # Check HTTP headers
        changes.extend(self._check_headers(domain))

        # Check TLS certificate
        changes.extend(self._check_certificate(domain))

        # Check key endpoints
        changes.extend(self._check_endpoints(domain))

        # Record changes and send alerts
        for change_type, description, old_val, new_val, severity in changes:
            self.db.execute(
                "INSERT INTO changes (domain, change_type, description, old_value, new_value, detected_at) VALUES (?, ?, ?, ?, ?, ?)",
                (domain, change_type, description, old_val, new_val, self.now),
            )
            alerter.send_alert(
                f"Change detected on {domain}",
                f"Type: {change_type}\n{description}",
                severity,
            )

        self.db.execute(
            "UPDATE targets SET last_checked = ? WHERE domain = ?",
            (self.now, domain),
        )
        self.db.commit()

        if changes:
            print(f"  [{len(changes)} changes detected]")
        else:
            print(f"  [No changes]")

    def _check_subdomains(self, domain: str) -> List[Tuple]:
        """Check for new subdomains."""
        changes = []
        current_subs = set()

        # Method 1: crt.sh
        try:
            resp = requests.get(
                f"https://crt.sh/?q=%25.{domain}&output=json",
                timeout=30,
            )
            if resp.status_code == 200:
                for entry in resp.json():
                    for name in entry.get("name_value", "").split("\n"):
                        name = name.strip().replace("*.", "")
                        if name and name.endswith(domain):
                            current_subs.add(name)
        except Exception:
            pass

        # Method 2: subfinder (if available)
        try:
            result = subprocess.run(
                ["subfinder", "-d", domain, "-silent"],
                capture_output=True, text=True, timeout=60,
            )
            for line in result.stdout.strip().split("\n"):
                if line.strip():
                    current_subs.add(line.strip())
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Compare with known subdomains
        known = set()
        for row in self.db.fetchall(
            "SELECT subdomain FROM subdomains WHERE domain = ? AND status = 'active'",
            (domain,),
        ):
            known.add(row["subdomain"])

        new_subs = current_subs - known
        for sub in new_subs:
            self.db.execute(
                "INSERT OR IGNORE INTO subdomains (domain, subdomain, first_seen, last_seen) VALUES (?, ?, ?, ?)",
                (domain, sub, self.now, self.now),
            )
            changes.append((
                "new_subdomain",
                f"New subdomain discovered: {sub}",
                None,
                sub,
                "high",
            ))

        # Update last_seen for existing
        for sub in current_subs & known:
            self.db.execute(
                "UPDATE subdomains SET last_seen = ? WHERE domain = ? AND subdomain = ?",
                (self.now, domain, sub),
            )

        return changes

    def _check_dns(self, domain: str) -> List[Tuple]:
        """Check for DNS record changes."""
        changes = []
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]

        for rtype in record_types:
            try:
                result = subprocess.run(
                    ["dig", "+short", rtype, domain, "@8.8.8.8"],
                    capture_output=True, text=True, timeout=10,
                )
                current_values = set(
                    line.strip() for line in result.stdout.strip().split("\n") if line.strip()
                )
            except Exception:
                continue

            known = set()
            for row in self.db.fetchall(
                "SELECT record_value FROM dns_records WHERE domain = ? AND record_type = ?",
                (domain, rtype),
            ):
                known.add(row["record_value"])

            new_records = current_values - known
            removed_records = known - current_values

            for val in new_records:
                self.db.execute(
                    "INSERT OR IGNORE INTO dns_records (domain, record_type, record_value, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)",
                    (domain, rtype, val, self.now, self.now),
                )
                severity = "high" if rtype in ("A", "NS", "CNAME") else "medium"
                changes.append((
                    "new_dns_record",
                    f"New {rtype} record: {val}",
                    None,
                    val,
                    severity,
                ))

            for val in removed_records:
                changes.append((
                    "removed_dns_record",
                    f"Removed {rtype} record: {val}",
                    val,
                    None,
                    "medium",
                ))

            for val in current_values:
                self.db.execute(
                    "UPDATE dns_records SET last_seen = ? WHERE domain = ? AND record_type = ? AND record_value = ?",
                    (self.now, domain, rtype, val),
                )

        return changes

    def _check_headers(self, domain: str) -> List[Tuple]:
        """Check for HTTP header changes."""
        changes = []
        important_headers = [
            "server", "x-powered-by", "content-security-policy",
            "strict-transport-security", "x-frame-options",
            "access-control-allow-origin", "x-content-type-options",
            "set-cookie",
        ]

        try:
            resp = requests.get(
                f"https://{domain}",
                timeout=10,
                verify=False,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0"},
            )
        except Exception:
            return changes

        for header_name in important_headers:
            current_value = resp.headers.get(header_name, "")
            if not current_value:
                continue

            # Normalize cookie values (session IDs change)
            if header_name == "set-cookie":
                current_value = re.sub(r'=[^;]+', '=REDACTED', current_value)

            known = self.db.fetchone(
                "SELECT header_value FROM headers WHERE domain = ? AND header_name = ? ORDER BY last_seen DESC LIMIT 1",
                (domain, header_name),
            )

            if known:
                if known["header_value"] != current_value:
                    changes.append((
                        "header_changed",
                        f"Header '{header_name}' changed",
                        known["header_value"][:200],
                        current_value[:200],
                        "high" if header_name in ("content-security-policy", "server", "x-powered-by") else "medium",
                    ))
            else:
                # New header
                self.db.execute(
                    "INSERT OR IGNORE INTO headers (domain, header_name, header_value, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)",
                    (domain, header_name, current_value[:500], self.now, self.now),
                )

            self.db.execute(
                "INSERT OR REPLACE INTO headers (domain, header_name, header_value, first_seen, last_seen) VALUES (?, ?, ?, COALESCE((SELECT first_seen FROM headers WHERE domain = ? AND header_name = ? AND header_value = ?), ?), ?)",
                (domain, header_name, current_value[:500], domain, header_name, current_value[:500], self.now, self.now),
            )

        return changes

    def _check_certificate(self, domain: str) -> List[Tuple]:
        """Check for TLS certificate changes."""
        changes = []
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.settimeout(10)
                s.connect((domain, 443))
                cert = s.getpeercert()

            subject = str(cert.get("subject", ""))
            issuer = str(cert.get("issuer", ""))
            not_before = cert.get("notBefore", "")
            not_after = cert.get("notAfter", "")
            serial = cert.get("serialNumber", "")
            fingerprint = hashlib.sha256(str(cert).encode()).hexdigest()[:32]

            known = self.db.fetchone(
                "SELECT fingerprint FROM certificates WHERE domain = ? ORDER BY first_seen DESC LIMIT 1",
                (domain,),
            )

            if known and known["fingerprint"] != fingerprint:
                changes.append((
                    "certificate_changed",
                    f"TLS certificate changed (new issuer: {issuer[:100]})",
                    known["fingerprint"],
                    fingerprint,
                    "high",
                ))

            self.db.execute(
                "INSERT OR IGNORE INTO certificates (domain, subject, issuer, not_before, not_after, serial, fingerprint, first_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (domain, subject[:500], issuer[:500], not_before, not_after, serial, fingerprint, self.now),
            )

        except Exception:
            pass

        return changes

    def _check_endpoints(self, domain: str) -> List[Tuple]:
        """Check key endpoints for changes."""
        changes = []
        endpoints = [
            f"https://{domain}/",
            f"https://{domain}/robots.txt",
            f"https://{domain}/sitemap.xml",
            f"https://{domain}/.well-known/security.txt",
        ]

        for url in endpoints:
            try:
                resp = requests.get(url, timeout=10, verify=False, allow_redirects=True)
                content_hash = hashlib.sha256(resp.text.encode()).hexdigest()[:16]

                known = self.db.fetchone(
                    "SELECT content_hash, status_code FROM endpoints WHERE domain = ? AND url = ?",
                    (domain, url),
                )

                if known:
                    if known["content_hash"] != content_hash:
                        changes.append((
                            "endpoint_content_changed",
                            f"Content changed at {url}",
                            known["content_hash"],
                            content_hash,
                            "medium",
                        ))
                    if known["status_code"] != resp.status_code:
                        changes.append((
                            "endpoint_status_changed",
                            f"Status code changed at {url}: {known['status_code']} -> {resp.status_code}",
                            str(known["status_code"]),
                            str(resp.status_code),
                            "high" if resp.status_code == 200 and known["status_code"] in (404, 403) else "medium",
                        ))

                self.db.execute(
                    "INSERT OR REPLACE INTO endpoints (domain, url, status_code, content_hash, first_seen, last_seen) VALUES (?, ?, ?, ?, COALESCE((SELECT first_seen FROM endpoints WHERE domain = ? AND url = ?), ?), ?)",
                    (domain, url, resp.status_code, content_hash, domain, url, self.now, self.now),
                )
            except Exception:
                pass

        return changes

    def check_all(self):
        """Check all enabled targets that are due."""
        targets = self.db.fetchall(
            "SELECT domain, last_checked, check_interval_seconds FROM targets WHERE enabled = 1"
        )
        for target in targets:
            domain = target["domain"]
            last = target["last_checked"]
            interval = target["check_interval_seconds"]

            if last:
                last_dt = datetime.fromisoformat(last)
                next_check = last_dt + timedelta(seconds=interval)
                if datetime.utcnow() < next_check:
                    remaining = (next_check - datetime.utcnow()).total_seconds()
                    print(f"  [~] {domain}: next check in {int(remaining)}s")
                    continue

            self.check_target(domain)

    def show_status(self):
        """Show status of all monitored targets."""
        targets = self.db.fetchall("SELECT * FROM targets ORDER BY last_checked DESC")
        print(f"\n{'='*70}")
        print(f"  Time Watcher Status - {len(targets)} targets")
        print(f"{'='*70}\n")

        for t in targets:
            sub_count = self.db.fetchone(
                "SELECT COUNT(*) as c FROM subdomains WHERE domain = ?", (t["domain"],)
            )["c"]
            change_count = self.db.fetchone(
                "SELECT COUNT(*) as c FROM changes WHERE domain = ? AND detected_at > datetime('now', '-7 days')",
                (t["domain"],),
            )["c"]
            status = "enabled" if t["enabled"] else "disabled"
            print(f"  {t['domain']:40s} [{status}]")
            print(f"    Last checked: {t['last_checked'] or 'never'}")
            print(f"    Interval: {t['check_interval_seconds']}s | Subdomains: {sub_count} | Changes (7d): {change_count}")
            print()

    def show_history(self, domain: str, limit: int = 30):
        """Show change history for a domain."""
        changes = self.db.fetchall(
            "SELECT * FROM changes WHERE domain = ? ORDER BY detected_at DESC LIMIT ?",
            (domain, limit),
        )
        print(f"\n  Change History for {domain} (last {limit}):\n")
        for c in changes:
            print(f"  [{c['detected_at']}] {c['change_type']}: {c['description']}")
            if c["old_value"]:
                print(f"    Old: {c['old_value'][:100]}")
            if c["new_value"]:
                print(f"    New: {c['new_value'][:100]}")


def parse_interval(interval_str: str) -> int:
    """Parse interval string like '1h', '30m', '1d' to seconds."""
    multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    match = re.match(r"(\d+)([smhd])?", interval_str)
    if match:
        value = int(match.group(1))
        unit = match.group(2) or "s"
        return value * multipliers.get(unit, 1)
    return 3600


def main():
    parser = argparse.ArgumentParser(description="Time Watcher - Target Monitor")
    subparsers = parser.add_subparsers(dest="command")

    # Add target
    add_p = subparsers.add_parser("add", help="Add target to monitor")
    add_p.add_argument("domain", help="Domain to monitor")
    add_p.add_argument("--interval", default="1h", help="Check interval (e.g., 30m, 1h, 1d)")
    add_p.add_argument("--webhook", help="Webhook URL for alerts")
    add_p.add_argument("--telegram", help="Telegram config (BOT_TOKEN:CHAT_ID)")

    # Check single
    check_p = subparsers.add_parser("check", help="Check a target now")
    check_p.add_argument("domain", help="Domain to check")

    # Check all
    subparsers.add_parser("check-all", help="Check all due targets")

    # Status
    subparsers.add_parser("status", help="Show monitoring status")

    # History
    hist_p = subparsers.add_parser("history", help="Show change history")
    hist_p.add_argument("domain", help="Domain")
    hist_p.add_argument("--last", type=int, default=30, help="Number of changes")

    # Setup cron
    cron_p = subparsers.add_parser("setup-cron", help="Install cron job")
    cron_p.add_argument("--interval", default="1h", help="Cron interval")

    args = parser.parse_args()
    watcher = TimeWatcher()

    if args.command == "add":
        interval = parse_interval(args.interval)
        watcher.add_target(args.domain, interval, args.webhook, args.telegram)
    elif args.command == "check":
        watcher.check_target(args.domain)
    elif args.command == "check-all":
        watcher.check_all()
    elif args.command == "status":
        watcher.show_status()
    elif args.command == "history":
        watcher.show_history(args.domain, args.last)
    elif args.command == "setup-cron":
        interval = parse_interval(args.interval)
        script_path = os.path.abspath(__file__)
        if interval < 3600:
            cron_expr = f"*/{interval // 60} * * * *"
        else:
            cron_expr = f"0 */{interval // 3600} * * *"
        cron_line = f"{cron_expr} /usr/bin/python3 {script_path} check-all >> ~/.time_watcher/cron.log 2>&1"
        print(f"Add this to crontab (crontab -e):\n{cron_line}")
        # Or use systemd timer
        print(f"\nOr create systemd timer:")
        print(f"  sudo systemctl edit --force time-watcher.timer")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
```

## Cron / Systemd Setup

### Crontab entry
```bash
# Check all targets every hour
0 * * * * /usr/bin/python3 /path/to/time_watcher.py check-all >> ~/.time_watcher/cron.log 2>&1
```

### Systemd timer
```ini
# /etc/systemd/system/time-watcher.service
[Unit]
Description=Time Watcher Bug Bounty Monitor

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /path/to/time_watcher.py check-all
User=bounty

# /etc/systemd/system/time-watcher.timer
[Unit]
Description=Run Time Watcher hourly

[Timer]
OnCalendar=hourly
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
sudo systemctl enable --now time-watcher.timer
```

## Quick Commands

### Add target with Slack alerts
```bash
python3 time_watcher.py add target.com --interval 30m --webhook "https://hooks.slack.com/services/T.../B.../..."
```

### Add target with Telegram alerts
```bash
python3 time_watcher.py add target.com --interval 1h --telegram "123456:ABCdefGHI:987654321"
```

### View what changed recently
```bash
python3 time_watcher.py history target.com --last 50
```

### Monitor multiple programs
```bash
for domain in uber.com shopify.com github.com; do
  python3 time_watcher.py add "$domain" --interval 2h
done
python3 time_watcher.py status
```

## Integration with Other Agents

### Alert triggers cors-chain test on new subdomains
```bash
# In a wrapper script triggered by webhook:
python3 time_watcher.py check-all 2>&1 | grep "new_subdomain" | \
  awk '{print $NF}' | while read sub; do
    python3 ../cors-chain/cors_chain.py "https://${sub}" --skip-recon
  done
```

### Feed new subdomains to spray-scanner
```bash
sqlite3 ~/.time_watcher/state.db \
  "SELECT subdomain FROM subdomains WHERE first_seen > datetime('now', '-1 day')" | \
  python3 ../spray-scanner/spray_scanner.py --stdin --workers 10
```
