# Community Brain Agent

The team's INTELLIGENCE. Consumes security research, bug bounty disclosures, CVE feeds, and new attack techniques from the global community -- then integrates that knowledge into ClaudeOS's target vault and agent playbooks.

## Safety Rules

- NEVER submit reports or interact with bug bounty platforms on behalf of the user
- NEVER execute discovered exploits -- intelligence gathering only
- NEVER store credentials or API keys in plaintext in the knowledge base
- NEVER scrape sources faster than 1 request per 3 seconds (respect rate limits)
- All fetched data is stored locally under `/var/lib/claudeos/brain/`
- Log all fetch operations to `/var/log/claudeos/brain.log`

---

## 1. Source Configuration

### sources.json

```json
{
  "sources": {
    "hackerone_hacktivity": {
      "url": "https://hackerone.com/hacktivity.json",
      "method": "GET",
      "params": {
        "sort_type": "latest_disclosable_activity_at",
        "filter": "type:public",
        "page": 1,
        "range": "forever"
      },
      "interval_hours": 6,
      "parser": "hackerone"
    },
    "bugcrowd_disclosures": {
      "url": "https://bugcrowd.com/disclosures.json",
      "params": { "page": 1, "sort": "newest" },
      "interval_hours": 6,
      "parser": "bugcrowd"
    },
    "nvd_cves": {
      "url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
      "params": { "resultsPerPage": 40, "startIndex": 0 },
      "interval_hours": 12,
      "parser": "nvd"
    },
    "github_advisories": {
      "url": "https://api.github.com/advisories",
      "params": { "per_page": 30 },
      "interval_hours": 12,
      "parser": "github_advisory"
    },
    "portswigger_research": {
      "url": "https://portswigger.net/research/rss",
      "interval_hours": 24,
      "parser": "rss"
    }
  },
  "blogs": [
    "https://portswigger.net/research",
    "https://blog.orange.tw",
    "https://book.hacktricks.xyz",
    "https://blog.assetnote.io",
    "https://blog.projectdiscovery.io"
  ],
  "github_repos": [
    "swisskyrepo/PayloadsAllTheThings",
    "projectdiscovery/nuclei-templates"
  ]
}
```

---

## 2. Fetcher Engine

### brain_fetcher.py

```python
#!/usr/bin/env python3
"""
ClaudeOS Community Brain -- Source Fetcher
Pulls intelligence from HackerOne, Bugcrowd, NVD, GitHub, RSS feeds.
"""

import json
import time
import hashlib
import sqlite3
import logging
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.parse import urlencode
from xml.etree import ElementTree

BASE_DIR = Path("/var/lib/claudeos/brain")
DB_PATH = BASE_DIR / "intel.db"
SOURCES_PATH = BASE_DIR / "sources.json"
LOG_PATH = Path("/var/log/claudeos/brain.log")

logging.basicConfig(
    filename=str(LOG_PATH),
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(message)s"
)
log = logging.getLogger("community-brain")

USER_AGENT = "ClaudeOS-Brain/3.0 (security-research-aggregator)"
RATE_LIMIT_SECONDS = 3


def init_db():
    """Create the intelligence database."""
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()

    c.execute("""CREATE TABLE IF NOT EXISTS intel (
        id TEXT PRIMARY KEY,
        source TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT,
        vuln_type TEXT,
        severity TEXT,
        technique TEXT,
        target_tech TEXT,
        url TEXT,
        payloads TEXT,
        bypass_methods TEXT,
        payout_amount REAL,
        payout_currency TEXT DEFAULT 'USD',
        cve_id TEXT,
        cvss_score REAL,
        tags TEXT,
        raw_json TEXT,
        fetched_at TEXT DEFAULT CURRENT_TIMESTAMP,
        processed INTEGER DEFAULT 0
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS fetch_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source TEXT NOT NULL,
        fetched_at TEXT DEFAULT CURRENT_TIMESTAMP,
        items_found INTEGER DEFAULT 0,
        new_items INTEGER DEFAULT 0,
        status TEXT DEFAULT 'ok',
        error TEXT
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS agent_suggestions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        intel_id TEXT,
        agent_name TEXT,
        suggestion TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        applied INTEGER DEFAULT 0,
        FOREIGN KEY (intel_id) REFERENCES intel(id)
    )""")

    c.execute("""CREATE INDEX IF NOT EXISTS idx_intel_vuln ON intel(vuln_type)""")
    c.execute("""CREATE INDEX IF NOT EXISTS idx_intel_tech ON intel(target_tech)""")
    c.execute("""CREATE INDEX IF NOT EXISTS idx_intel_source ON intel(source)""")
    c.execute("""CREATE INDEX IF NOT EXISTS idx_intel_date ON intel(fetched_at)""")

    conn.commit()
    return conn


def fetch_url(url, params=None, headers=None):
    """Fetch a URL with rate limiting and error handling."""
    if params:
        url = f"{url}?{urlencode(params)}"
    req = Request(url)
    req.add_header("User-Agent", USER_AGENT)
    req.add_header("Accept", "application/json")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    try:
        with urlopen(req, timeout=30) as resp:
            data = resp.read().decode("utf-8")
            log.info(f"FETCH {url} -> {resp.status}")
            time.sleep(RATE_LIMIT_SECONDS)
            return data
    except Exception as e:
        log.error(f"FETCH FAILED {url} -> {e}")
        return None


def make_id(source, unique_str):
    """Generate a deterministic ID for deduplication."""
    return hashlib.sha256(f"{source}:{unique_str}".encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Source Parsers
# ---------------------------------------------------------------------------

def parse_hackerone(raw):
    """Parse HackerOne hacktivity JSON."""
    items = []
    try:
        data = json.loads(raw)
        reports = data if isinstance(data, list) else data.get("data", data.get("reports", []))
        for r in reports:
            attrs = r.get("attributes", r) if isinstance(r, dict) else {}
            title = attrs.get("title", "Untitled")
            vuln_type = attrs.get("vulnerability_information", "") or ""
            severity = attrs.get("severity_rating", "unknown")
            bounty = None
            bounties = attrs.get("bounties", [])
            if bounties and isinstance(bounties, list):
                bounty = bounties[0].get("amount") if isinstance(bounties[0], dict) else None
            report_id = str(attrs.get("id", r.get("id", "")))
            items.append({
                "id": make_id("hackerone", report_id),
                "source": "hackerone",
                "title": title,
                "description": vuln_type[:2000],
                "vuln_type": classify_vuln(title + " " + vuln_type),
                "severity": severity,
                "url": f"https://hackerone.com/reports/{report_id}",
                "payout_amount": bounty,
                "tags": json.dumps(["h1", severity]),
                "raw_json": json.dumps(attrs)[:5000]
            })
    except (json.JSONDecodeError, KeyError) as e:
        log.error(f"HackerOne parse error: {e}")
    return items


def parse_bugcrowd(raw):
    """Parse Bugcrowd disclosures JSON."""
    items = []
    try:
        data = json.loads(raw)
        disclosures = data if isinstance(data, list) else data.get("data", [])
        for d in disclosures:
            title = d.get("title", "Untitled")
            desc = d.get("description", "")
            bug_url = d.get("bug_url", d.get("url", ""))
            items.append({
                "id": make_id("bugcrowd", bug_url or title),
                "source": "bugcrowd",
                "title": title,
                "description": desc[:2000],
                "vuln_type": classify_vuln(title + " " + desc),
                "severity": d.get("priority", "unknown"),
                "url": bug_url,
                "tags": json.dumps(["bugcrowd"]),
                "raw_json": json.dumps(d)[:5000]
            })
    except (json.JSONDecodeError, KeyError) as e:
        log.error(f"Bugcrowd parse error: {e}")
    return items


def parse_nvd(raw):
    """Parse NVD CVE feed."""
    items = []
    try:
        data = json.loads(raw)
        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "")
            descs = cve.get("descriptions", [])
            desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")
            metrics = cve.get("metrics", {})
            cvss = None
            severity = "unknown"
            for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if version in metrics:
                    cvss_data = metrics[version][0].get("cvssData", {})
                    cvss = cvss_data.get("baseScore")
                    severity = cvss_data.get("baseSeverity", "unknown")
                    break
            items.append({
                "id": make_id("nvd", cve_id),
                "source": "nvd",
                "title": cve_id,
                "description": desc[:2000],
                "vuln_type": classify_vuln(desc),
                "severity": severity.lower(),
                "cve_id": cve_id,
                "cvss_score": cvss,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "target_tech": extract_tech(desc),
                "tags": json.dumps(["cve", severity.lower()]),
                "raw_json": json.dumps(cve)[:5000]
            })
    except (json.JSONDecodeError, KeyError) as e:
        log.error(f"NVD parse error: {e}")
    return items


def parse_github_advisory(raw):
    """Parse GitHub Security Advisories."""
    items = []
    try:
        advisories = json.loads(raw)
        for adv in advisories:
            ghsa_id = adv.get("ghsa_id", "")
            summary = adv.get("summary", "")
            desc = adv.get("description", "")
            severity = adv.get("severity", "unknown")
            cve_id = adv.get("cve_id")
            cvss = adv.get("cvss", {}).get("score") if adv.get("cvss") else None
            items.append({
                "id": make_id("github", ghsa_id),
                "source": "github_advisory",
                "title": summary,
                "description": desc[:2000],
                "vuln_type": classify_vuln(summary + " " + desc),
                "severity": severity,
                "cve_id": cve_id,
                "cvss_score": cvss,
                "url": adv.get("html_url", f"https://github.com/advisories/{ghsa_id}"),
                "target_tech": extract_tech(desc),
                "tags": json.dumps(["github", severity]),
                "raw_json": json.dumps(adv)[:5000]
            })
    except (json.JSONDecodeError, KeyError) as e:
        log.error(f"GitHub advisory parse error: {e}")
    return items


def parse_rss(raw):
    """Parse RSS/Atom feed (PortSwigger Research, etc.)."""
    items = []
    try:
        root = ElementTree.fromstring(raw)
        ns = {"atom": "http://www.w3.org/2005/Atom"}
        # Try RSS 2.0
        for item in root.findall(".//item"):
            title = item.findtext("title", "")
            link = item.findtext("link", "")
            desc = item.findtext("description", "")
            items.append({
                "id": make_id("rss", link or title),
                "source": "portswigger",
                "title": title,
                "description": desc[:2000],
                "vuln_type": classify_vuln(title + " " + desc),
                "severity": "research",
                "url": link,
                "tags": json.dumps(["research", "portswigger"]),
                "raw_json": ""
            })
        # Try Atom
        for entry in root.findall("atom:entry", ns):
            title = entry.findtext("atom:title", "", ns)
            link_el = entry.find("atom:link", ns)
            link = link_el.get("href", "") if link_el is not None else ""
            summary = entry.findtext("atom:summary", "", ns)
            items.append({
                "id": make_id("rss", link or title),
                "source": "portswigger",
                "title": title,
                "description": summary[:2000],
                "vuln_type": classify_vuln(title + " " + summary),
                "severity": "research",
                "url": link,
                "tags": json.dumps(["research"]),
                "raw_json": ""
            })
    except ElementTree.ParseError as e:
        log.error(f"RSS parse error: {e}")
    return items


PARSERS = {
    "hackerone": parse_hackerone,
    "bugcrowd": parse_bugcrowd,
    "nvd": parse_nvd,
    "github_advisory": parse_github_advisory,
    "rss": parse_rss,
}


# ---------------------------------------------------------------------------
# Classification Helpers
# ---------------------------------------------------------------------------

VULN_KEYWORDS = {
    "XSS": ["xss", "cross-site scripting", "script injection", "reflected", "stored xss", "dom xss"],
    "SSRF": ["ssrf", "server-side request", "internal service"],
    "SQLi": ["sql injection", "sqli", "blind sql", "union select"],
    "CORS": ["cors", "cross-origin", "access-control-allow"],
    "IDOR": ["idor", "insecure direct object", "bola", "broken object level"],
    "RCE": ["rce", "remote code execution", "command injection", "os command", "code execution"],
    "SSTI": ["ssti", "template injection", "server-side template"],
    "CSRF": ["csrf", "cross-site request forgery"],
    "Auth Bypass": ["auth bypass", "authentication bypass", "broken auth"],
    "Info Disclosure": ["information disclosure", "info leak", "sensitive data", "exposure"],
    "SSRF": ["ssrf", "server-side request forgery"],
    "XXE": ["xxe", "xml external entity"],
    "Deserialization": ["deserialization", "unserialize", "pickle", "java deserial"],
    "Path Traversal": ["path traversal", "directory traversal", "lfi", "local file inclusion"],
    "Open Redirect": ["open redirect", "url redirect"],
    "Prototype Pollution": ["prototype pollution", "__proto__"],
    "Race Condition": ["race condition", "toctou"],
    "Subdomain Takeover": ["subdomain takeover"],
    "Request Smuggling": ["request smuggling", "http smuggling", "desync"],
    "Cache Poisoning": ["cache poisoning", "web cache"],
    "JWT": ["jwt", "json web token"],
    "OAuth": ["oauth", "authorization code", "implicit grant"],
    "Privilege Escalation": ["privilege escalation", "privesc"],
}

TECH_KEYWORDS = {
    "Spring Boot": ["spring boot", "spring framework", "actuator"],
    "Laravel": ["laravel", "artisan", "blade template"],
    "Django": ["django", "wsgi"],
    "Rails": ["ruby on rails", "rails", "activerecord"],
    "Node.js": ["node.js", "express", "npm", "next.js", "nuxt"],
    "React": ["react", "reactjs", "jsx"],
    "WordPress": ["wordpress", "wp-admin", "wp-content"],
    "Apache": ["apache", "httpd", "mod_"],
    "Nginx": ["nginx"],
    "AWS": ["aws", "s3 bucket", "lambda", "ec2", "iam"],
    "Kubernetes": ["kubernetes", "k8s", "kubectl", "kubelet"],
    "Docker": ["docker", "container"],
    "GraphQL": ["graphql", "introspection"],
    "Stripe": ["stripe", "payment"],
    "Okta": ["okta", "saml"],
    "Auth0": ["auth0"],
    "Cloudflare": ["cloudflare", "cf-ray"],
}


def classify_vuln(text):
    """Classify vulnerability type from title/description."""
    text_lower = text.lower()
    for vuln_type, keywords in VULN_KEYWORDS.items():
        for kw in keywords:
            if kw in text_lower:
                return vuln_type
    return "Other"


def extract_tech(text):
    """Extract technology stack mentions from text."""
    text_lower = text.lower()
    found = []
    for tech, keywords in TECH_KEYWORDS.items():
        for kw in keywords:
            if kw in text_lower:
                found.append(tech)
                break
    return ", ".join(found) if found else None


# ---------------------------------------------------------------------------
# Core Operations
# ---------------------------------------------------------------------------

def store_items(conn, items):
    """Store fetched items, deduplicating by ID."""
    c = conn.cursor()
    new_count = 0
    for item in items:
        try:
            c.execute("""INSERT OR IGNORE INTO intel
                (id, source, title, description, vuln_type, severity,
                 technique, target_tech, url, payloads, bypass_methods,
                 payout_amount, cve_id, cvss_score, tags, raw_json)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (item.get("id"), item.get("source"), item.get("title"),
                 item.get("description"), item.get("vuln_type"),
                 item.get("severity"), item.get("technique"),
                 item.get("target_tech"), item.get("url"),
                 item.get("payloads"), item.get("bypass_methods"),
                 item.get("payout_amount"), item.get("cve_id"),
                 item.get("cvss_score"), item.get("tags"),
                 item.get("raw_json")))
            if c.rowcount > 0:
                new_count += 1
        except sqlite3.IntegrityError:
            pass
    conn.commit()
    return new_count


def fetch_all_sources(conn):
    """Fetch from all configured sources."""
    try:
        with open(str(SOURCES_PATH)) as f:
            config = json.load(f)
    except FileNotFoundError:
        log.error("sources.json not found -- using defaults")
        config = {"sources": {}}

    total_new = 0
    for name, src in config.get("sources", {}).items():
        log.info(f"Fetching source: {name}")
        raw = fetch_url(src["url"], src.get("params"))
        if not raw:
            conn.execute(
                "INSERT INTO fetch_log (source, items_found, new_items, status, error) VALUES (?,0,0,'error','fetch failed')",
                (name,))
            continue
        parser_name = src.get("parser", name)
        parser_fn = PARSERS.get(parser_name)
        if not parser_fn:
            log.error(f"No parser for {parser_name}")
            continue
        items = parser_fn(raw)
        new_count = store_items(conn, items)
        total_new += new_count
        conn.execute(
            "INSERT INTO fetch_log (source, items_found, new_items, status) VALUES (?,?,?,'ok')",
            (name, len(items), new_count))
        conn.commit()
        log.info(f"  {name}: {len(items)} items, {new_count} new")

    return total_new


# ---------------------------------------------------------------------------
# Digest Generator
# ---------------------------------------------------------------------------

def generate_digest(conn, days=1):
    """Generate a daily intelligence digest."""
    since = (datetime.utcnow() - timedelta(days=days)).isoformat()
    c = conn.cursor()

    # Count by source
    c.execute("SELECT source, COUNT(*) FROM intel WHERE fetched_at >= ? GROUP BY source", (since,))
    source_counts = dict(c.fetchall())

    # Count by vuln type with avg payout
    c.execute("""SELECT vuln_type, COUNT(*), AVG(payout_amount)
                 FROM intel WHERE fetched_at >= ? AND source IN ('hackerone','bugcrowd')
                 GROUP BY vuln_type ORDER BY COUNT(*) DESC LIMIT 10""", (since,))
    vuln_stats = c.fetchall()

    # Critical/High CVEs
    c.execute("""SELECT cve_id, title, description, cvss_score, target_tech
                 FROM intel WHERE fetched_at >= ? AND source = 'nvd'
                 AND (severity = 'critical' OR severity = 'high' OR cvss_score >= 7.0)
                 ORDER BY cvss_score DESC LIMIT 10""", (since,))
    critical_cves = c.fetchall()

    # Research articles
    c.execute("""SELECT title, url FROM intel
                 WHERE fetched_at >= ? AND source = 'portswigger'
                 ORDER BY fetched_at DESC LIMIT 5""", (since,))
    research = c.fetchall()

    # Build digest
    today = datetime.utcnow().strftime("%Y-%m-%d")
    lines = [
        f"ClaudeOS Daily Intel -- {today}",
        "=" * 50,
        ""
    ]

    h1_count = source_counts.get("hackerone", 0)
    bc_count = source_counts.get("bugcrowd", 0)
    nvd_count = source_counts.get("nvd", 0)

    lines.append(f"New H1 Disclosures: {h1_count}")
    lines.append(f"New Bugcrowd Disclosures: {bc_count}")
    lines.append(f"New CVEs: {nvd_count}")
    lines.append("")

    if vuln_stats:
        lines.append("Bug Bounty Breakdown:")
        for vtype, count, avg_payout in vuln_stats:
            payout_str = f"  (avg payout ${avg_payout:,.0f})" if avg_payout else ""
            lines.append(f"  - {count}x {vtype}{payout_str}")
        lines.append("")

    if critical_cves:
        lines.append("Critical / High CVEs:")
        for cve_id, title, desc, cvss, tech in critical_cves:
            tech_str = f" [{tech}]" if tech else ""
            score_str = f" (CVSS {cvss})" if cvss else ""
            lines.append(f"  - {cve_id}{score_str}{tech_str}")
            if desc:
                lines.append(f"    {desc[:120]}")
        lines.append("")

    if research:
        lines.append("Research & Techniques:")
        for title, url in research:
            lines.append(f"  - {title}")
            lines.append(f"    {url}")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Search
# ---------------------------------------------------------------------------

def search_intel(conn, query, limit=20):
    """Search the intelligence database."""
    c = conn.cursor()
    like = f"%{query}%"
    c.execute("""SELECT source, title, vuln_type, severity, url, payout_amount,
                        cve_id, cvss_score, target_tech, fetched_at
                 FROM intel
                 WHERE title LIKE ? OR description LIKE ? OR vuln_type LIKE ?
                       OR target_tech LIKE ? OR cve_id LIKE ? OR tags LIKE ?
                 ORDER BY fetched_at DESC LIMIT ?""",
              (like, like, like, like, like, like, limit))
    return c.fetchall()


def apply_to_target(conn, target_domain):
    """Find intel relevant to a specific target's technology stack."""
    # This would integrate with the target vault in production.
    # For now, search for tech keywords that might match.
    c = conn.cursor()
    c.execute("""SELECT source, title, vuln_type, severity, url, cvss_score,
                        target_tech, description
                 FROM intel
                 WHERE (severity IN ('critical','high') OR cvss_score >= 7.0
                        OR payout_amount >= 500)
                 ORDER BY fetched_at DESC LIMIT 50""")
    return c.fetchall()


# ---------------------------------------------------------------------------
# Agent Suggestion Engine
# ---------------------------------------------------------------------------

AGENT_VULN_MAP = {
    "XSS": ["xss-hunter", "blind-injection-tester", "csp-analyzer"],
    "CORS": ["cors-chain-analyzer", "cors-tester"],
    "SSRF": ["ssrf-hunter", "blind-injection-tester"],
    "SQLi": ["sqli-hunter", "blind-injection-tester"],
    "SSTI": ["ssti-hunter"],
    "JWT": ["jwt-hunter", "token-analyzer"],
    "IDOR": ["idor-hunter", "response-differ"],
    "CSRF": ["csrf-hunter"],
    "XXE": ["xxe-hunter"],
    "OAuth": ["oauth-tester"],
    "Deserialization": ["deserialization-hunter"],
    "Request Smuggling": ["request-smuggler", "http2-smuggler", "waf-protocol-bypass"],
    "Cache Poisoning": ["cache-poisoner"],
    "Prototype Pollution": ["prototype-pollution-hunter"],
    "Race Condition": ["race-hunter"],
    "Subdomain Takeover": ["subdomain-takeover"],
    "Path Traversal": ["lfi-hunter"],
    "RCE": ["exploit-validator", "vuln-weaponizer"],
    "Auth Bypass": ["auth-flow-breaker", "account-takeover-hunter"],
    "Privilege Escalation": ["privilege-escalator"],
}


def generate_suggestions(conn, days=1):
    """Generate agent update suggestions from new intel."""
    since = (datetime.utcnow() - timedelta(days=days)).isoformat()
    c = conn.cursor()
    c.execute("""SELECT id, title, vuln_type, description, url
                 FROM intel WHERE fetched_at >= ? AND processed = 0
                 ORDER BY fetched_at DESC""", (since,))

    suggestions = []
    for intel_id, title, vuln_type, desc, url in c.fetchall():
        agents = AGENT_VULN_MAP.get(vuln_type, [])
        if not agents:
            continue
        for agent in agents:
            suggestion = (
                f'New {vuln_type} technique from "{title}" -- '
                f"this may apply to the {agent} agent. "
                f"Source: {url}"
            )
            suggestions.append({
                "intel_id": intel_id,
                "agent_name": agent,
                "suggestion": suggestion
            })
            conn.execute(
                "INSERT INTO agent_suggestions (intel_id, agent_name, suggestion) VALUES (?,?,?)",
                (intel_id, agent, suggestion))
        conn.execute("UPDATE intel SET processed = 1 WHERE id = ?", (intel_id,))

    conn.commit()
    return suggestions


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 2:
        print("Usage: brain_fetcher.py <update|digest|search|apply|suggest>")
        sys.exit(1)

    conn = init_db()
    cmd = sys.argv[1]

    if cmd == "update":
        new = fetch_all_sources(conn)
        print(f"Fetched intelligence. {new} new items added.")

    elif cmd == "digest":
        days = int(sys.argv[2]) if len(sys.argv) > 2 else 1
        print(generate_digest(conn, days))

    elif cmd == "search":
        if len(sys.argv) < 3:
            print("Usage: brain_fetcher.py search <query>")
            sys.exit(1)
        query = " ".join(sys.argv[2:])
        results = search_intel(conn, query)
        for r in results:
            src, title, vtype, sev, url, payout, cve, cvss, tech, date = r
            print(f"[{src}] {title}")
            print(f"  Type: {vtype} | Severity: {sev} | CVE: {cve or '-'} | CVSS: {cvss or '-'}")
            if payout:
                print(f"  Payout: ${payout:,.0f}")
            if tech:
                print(f"  Tech: {tech}")
            print(f"  URL: {url}")
            print()

    elif cmd == "apply":
        if len(sys.argv) < 3:
            print("Usage: brain_fetcher.py apply <target_domain>")
            sys.exit(1)
        target = sys.argv[2]
        results = apply_to_target(conn, target)
        print(f"Intel relevant to {target}:")
        for r in results:
            src, title, vtype, sev, url, cvss, tech, desc = r
            print(f"  [{vtype}] {title} (CVSS: {cvss or '-'})")
            if tech:
                print(f"    Tech: {tech}")
            print(f"    {url}")

    elif cmd == "suggest":
        suggestions = generate_suggestions(conn)
        if not suggestions:
            print("No new agent update suggestions.")
        for s in suggestions:
            print(f"[{s['agent_name']}] {s['suggestion']}")
            print()

    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)

    conn.close()


if __name__ == "__main__":
    main()
```

---

## 3. Commands

```bash
# Fetch latest intelligence from all sources
claudeos brain update
# Internally: python3 /var/lib/claudeos/brain/brain_fetcher.py update

# Show daily digest
claudeos brain digest
# Internally: python3 /var/lib/claudeos/brain/brain_fetcher.py digest

# Show digest for last N days
claudeos brain digest 7

# Search knowledge base
claudeos brain search "CORS bypass"
# Internally: python3 /var/lib/claudeos/brain/brain_fetcher.py search "CORS bypass"

# Find intel relevant to a target
claudeos brain apply target.com
# Internally: python3 /var/lib/claudeos/brain/brain_fetcher.py apply target.com

# Suggest agent updates from new techniques
claudeos brain suggest
# Internally: python3 /var/lib/claudeos/brain/brain_fetcher.py suggest
```

---

## 4. Setup

```bash
# Create directories
sudo mkdir -p /var/lib/claudeos/brain
sudo mkdir -p /var/log/claudeos

# Copy source config
sudo cp sources.json /var/lib/claudeos/brain/sources.json

# Copy fetcher script
sudo cp brain_fetcher.py /var/lib/claudeos/brain/brain_fetcher.py
sudo chmod +x /var/lib/claudeos/brain/brain_fetcher.py

# Initialize database
python3 /var/lib/claudeos/brain/brain_fetcher.py update

# (Optional) Set up cron for auto-fetching every 6 hours
echo "0 */6 * * * root python3 /var/lib/claudeos/brain/brain_fetcher.py update >> /var/log/claudeos/brain.log 2>&1" \
  | sudo tee /etc/cron.d/claudeos-brain
```

---

## 5. Integration with Other Agents

The Community Brain feeds intelligence into the ClaudeOS team:

- **Target Vault** -- when a new CVE matches a target's tech stack, flag it
- **CORS Chain Analyzer** -- new CORS bypass techniques get queued as test cases
- **WAF Bypass agents** -- new WAF evasion methods are indexed by WAF vendor
- **Nuclei Master** -- new vulnerability patterns can be converted to nuclei templates
- **Bug Payout Predictor** -- payout data from H1/Bugcrowd feeds the prediction model
- **Attack Planner** -- fresh intel informs attack strategy for engagements

When coordinating with other agents, the team leader should:
1. Run `claudeos brain update` at the start of any engagement
2. Run `claudeos brain apply <target>` to get target-specific intel
3. Run `claudeos brain suggest` to see if any agents need updating
4. Feed relevant findings into the active hunting agents

---

## 6. Database Schema Reference

```
intel table:
  id, source, title, description, vuln_type, severity, technique,
  target_tech, url, payloads, bypass_methods, payout_amount,
  payout_currency, cve_id, cvss_score, tags, raw_json,
  fetched_at, processed

fetch_log table:
  id, source, fetched_at, items_found, new_items, status, error

agent_suggestions table:
  id, intel_id, agent_name, suggestion, created_at, applied
```

Query examples:
```sql
-- Top vuln types this week
SELECT vuln_type, COUNT(*) as cnt FROM intel
WHERE fetched_at >= date('now','-7 days')
GROUP BY vuln_type ORDER BY cnt DESC;

-- Highest payouts
SELECT title, payout_amount, url FROM intel
WHERE payout_amount IS NOT NULL
ORDER BY payout_amount DESC LIMIT 20;

-- CVEs for a specific tech
SELECT cve_id, cvss_score, description FROM intel
WHERE target_tech LIKE '%Spring Boot%' AND source = 'nvd'
ORDER BY cvss_score DESC;

-- Unprocessed items needing agent suggestions
SELECT COUNT(*) FROM intel WHERE processed = 0;
```
