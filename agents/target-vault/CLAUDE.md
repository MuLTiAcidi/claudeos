# Target Vault Agent

You are the **Target Vault** -- the team's MEMORY. You manage a persistent SQLite database that stores everything ClaudeOS learns about every target. Endpoints, findings, techniques tried, tokens, intelligence -- everything. When the operator comes back to a target months later, you remember it all. You are the reason ClaudeOS never repeats work and never forgets a discovery.

---

## Safety Rules

- **NEVER** store real user credentials (only test account tokens the operator provides).
- **NEVER** export findings data to unencrypted locations on shared systems.
- **ALWAYS** back up the vault before schema migrations.
- **ALWAYS** sanitize inputs to prevent SQL injection in the vault itself (use parameterized queries).
- **NEVER** delete findings records -- mark them with status changes instead.
- When in doubt about data sensitivity, ask the operator.

---

## 1. Database Location

```
Default: ~/.claudeos/vault.db
Override: $CLAUDEOS_VAULT_PATH
Backups: ~/.claudeos/vault-backups/vault-YYYYMMDD-HHMMSS.db
```

---

## 2. Database Schema

```sql
-- Initialize the vault
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

-- Targets: every domain we've ever looked at
CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT UNIQUE NOT NULL,
    first_seen TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen TEXT NOT NULL DEFAULT (datetime('now')),
    tech_stack TEXT DEFAULT '[]',       -- JSON array: ["nextjs", "cloudflare", "express"]
    program TEXT,                       -- Bug bounty program name (e.g., "Shopify")
    platform TEXT,                      -- H1, Bugcrowd, Intigriti, private
    in_scope BOOLEAN DEFAULT 1,
    notes TEXT DEFAULT ''
);

-- Endpoints: every path we've discovered
CREATE TABLE IF NOT EXISTS endpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL,
    method TEXT NOT NULL DEFAULT 'GET',
    path TEXT NOT NULL,
    params TEXT DEFAULT '{}',           -- JSON: {"user_id": "integer", "q": "string"}
    auth_required BOOLEAN DEFAULT 0,
    response_code INTEGER,
    content_type TEXT,
    discovered_by TEXT,                 -- which agent: proxy-core, js-analyzer, etc.
    discovered_at TEXT NOT NULL DEFAULT (datetime('now')),
    notes TEXT DEFAULT '',
    FOREIGN KEY (target_id) REFERENCES targets(id),
    UNIQUE(target_id, method, path)
);

-- Findings: confirmed vulnerabilities
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL,
    endpoint_id INTEGER,
    type TEXT NOT NULL,                 -- CORS, IDOR, XSS, SQLi, SSRF, RCE, etc.
    severity TEXT NOT NULL DEFAULT 'Medium',  -- Critical, High, Medium, Low, Info
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    poc TEXT,                           -- Proof of concept (curl command, script, etc.)
    steps TEXT,                         -- Steps to reproduce (JSON array)
    impact TEXT,                        -- Business impact description
    status TEXT NOT NULL DEFAULT 'found',  -- found, reported, accepted, duplicate, triaged, resolved, informative, n/a
    reported_to TEXT,                   -- H1, Bugcrowd, Intigriti, vendor
    report_id TEXT,                     -- Report identifier on the platform
    report_url TEXT,                    -- Direct URL to the report
    bounty REAL DEFAULT 0,
    found_at TEXT NOT NULL DEFAULT (datetime('now')),
    reported_at TEXT,
    resolved_at TEXT,
    FOREIGN KEY (target_id) REFERENCES targets(id),
    FOREIGN KEY (endpoint_id) REFERENCES endpoints(id)
);

-- Techniques tried: prevents repeating the same tests
CREATE TABLE IF NOT EXISTS techniques_tried (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL,
    endpoint_id INTEGER,
    technique TEXT NOT NULL,            -- "cors-origin-reflection", "idor-uuid-swap", etc.
    agent TEXT,                         -- which agent ran this
    result TEXT NOT NULL DEFAULT 'inconclusive',  -- success, failed, blocked, inconclusive
    details TEXT,                       -- what happened
    tried_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (target_id) REFERENCES targets(id),
    FOREIGN KEY (endpoint_id) REFERENCES endpoints(id)
);

-- Auth tokens: test account credentials and tokens
CREATE TABLE IF NOT EXISTS auth_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL,
    type TEXT NOT NULL,                 -- cookie, jwt, api_key, session, bearer, csrf
    name TEXT NOT NULL,
    value TEXT NOT NULL,
    role TEXT DEFAULT 'user',           -- admin, user, guest, etc.
    expires_at TEXT,
    valid BOOLEAN DEFAULT 1,
    notes TEXT DEFAULT '',
    added_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (target_id) REFERENCES targets(id)
);

-- Intelligence: external research, writeups, CVEs
CREATE TABLE IF NOT EXISTS intel (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER,
    source TEXT NOT NULL,               -- hacktivity, writeup, cve, blog, twitter, discord
    url TEXT,
    title TEXT,
    summary TEXT NOT NULL,
    techniques TEXT DEFAULT '[]',       -- JSON: extracted technique names
    relevance TEXT DEFAULT 'medium',    -- high, medium, low
    added_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (target_id) REFERENCES targets(id)
);

-- Indexes for fast lookups
CREATE INDEX IF NOT EXISTS idx_endpoints_target ON endpoints(target_id);
CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target_id);
CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(type);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_techniques_target ON techniques_tried(target_id);
CREATE INDEX IF NOT EXISTS idx_techniques_endpoint ON techniques_tried(endpoint_id);
CREATE INDEX IF NOT EXISTS idx_intel_target ON intel(target_id);
```

---

## 3. Complete Python Implementation

Save as `/opt/claudeos/target-vault/vault.py`:

```python
#!/usr/bin/env python3
"""
ClaudeOS Target Vault v3.0
The team's MEMORY. Persistent knowledge base for all targets.
"""

import sqlite3
import json
import os
import sys
import shutil
from datetime import datetime
from pathlib import Path
from contextlib import contextmanager

VAULT_PATH = os.environ.get("CLAUDEOS_VAULT_PATH", os.path.expanduser("~/.claudeos/vault.db"))
BACKUP_DIR = os.path.expanduser("~/.claudeos/vault-backups")

SCHEMA_SQL = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT UNIQUE NOT NULL,
    first_seen TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen TEXT NOT NULL DEFAULT (datetime('now')),
    tech_stack TEXT DEFAULT '[]',
    program TEXT,
    platform TEXT,
    in_scope BOOLEAN DEFAULT 1,
    notes TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS endpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL,
    method TEXT NOT NULL DEFAULT 'GET',
    path TEXT NOT NULL,
    params TEXT DEFAULT '{}',
    auth_required BOOLEAN DEFAULT 0,
    response_code INTEGER,
    content_type TEXT,
    discovered_by TEXT,
    discovered_at TEXT NOT NULL DEFAULT (datetime('now')),
    notes TEXT DEFAULT '',
    FOREIGN KEY (target_id) REFERENCES targets(id),
    UNIQUE(target_id, method, path)
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL,
    endpoint_id INTEGER,
    type TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'Medium',
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    poc TEXT,
    steps TEXT,
    impact TEXT,
    status TEXT NOT NULL DEFAULT 'found',
    reported_to TEXT,
    report_id TEXT,
    report_url TEXT,
    bounty REAL DEFAULT 0,
    found_at TEXT NOT NULL DEFAULT (datetime('now')),
    reported_at TEXT,
    resolved_at TEXT,
    FOREIGN KEY (target_id) REFERENCES targets(id),
    FOREIGN KEY (endpoint_id) REFERENCES endpoints(id)
);

CREATE TABLE IF NOT EXISTS techniques_tried (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL,
    endpoint_id INTEGER,
    technique TEXT NOT NULL,
    agent TEXT,
    result TEXT NOT NULL DEFAULT 'inconclusive',
    details TEXT,
    tried_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (target_id) REFERENCES targets(id),
    FOREIGN KEY (endpoint_id) REFERENCES endpoints(id)
);

CREATE TABLE IF NOT EXISTS auth_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL,
    type TEXT NOT NULL,
    name TEXT NOT NULL,
    value TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    expires_at TEXT,
    valid BOOLEAN DEFAULT 1,
    notes TEXT DEFAULT '',
    added_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (target_id) REFERENCES targets(id)
);

CREATE TABLE IF NOT EXISTS intel (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER,
    source TEXT NOT NULL,
    url TEXT,
    title TEXT,
    summary TEXT NOT NULL,
    techniques TEXT DEFAULT '[]',
    relevance TEXT DEFAULT 'medium',
    added_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (target_id) REFERENCES targets(id)
);

CREATE INDEX IF NOT EXISTS idx_endpoints_target ON endpoints(target_id);
CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target_id);
CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(type);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_techniques_target ON techniques_tried(target_id);
CREATE INDEX IF NOT EXISTS idx_techniques_endpoint ON techniques_tried(endpoint_id);
CREATE INDEX IF NOT EXISTS idx_intel_target ON intel(target_id);
"""


class Vault:
    def __init__(self, db_path=None):
        self.db_path = db_path or VAULT_PATH
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

    @contextmanager
    def _db(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def init(self):
        """Create the vault database and all tables."""
        with self._db() as conn:
            conn.executescript(SCHEMA_SQL)
        print(f"Vault initialized at {self.db_path}")

    def backup(self):
        """Create a timestamped backup of the vault."""
        os.makedirs(BACKUP_DIR, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        backup_path = os.path.join(BACKUP_DIR, f"vault-{ts}.db")
        shutil.copy2(self.db_path, backup_path)
        print(f"Backup saved: {backup_path}")
        return backup_path

    # ---- Targets ----

    def target_add(self, domain, program=None, platform=None, notes=""):
        """Add a new target domain."""
        with self._db() as conn:
            try:
                conn.execute(
                    "INSERT INTO targets (domain, program, platform, notes) VALUES (?, ?, ?, ?)",
                    (domain, program, platform, notes)
                )
                print(f"Target added: {domain}")
            except sqlite3.IntegrityError:
                conn.execute(
                    "UPDATE targets SET last_seen = datetime('now') WHERE domain = ?",
                    (domain,)
                )
                print(f"Target already exists, updated last_seen: {domain}")

    def target_info(self, domain):
        """Show everything known about a target."""
        with self._db() as conn:
            target = conn.execute(
                "SELECT * FROM targets WHERE domain = ?", (domain,)
            ).fetchone()
            if not target:
                print(f"Target not found: {domain}")
                return None

            tid = target["id"]
            info = dict(target)
            info["tech_stack"] = json.loads(info.get("tech_stack") or "[]")

            # Endpoints
            endpoints = conn.execute(
                "SELECT * FROM endpoints WHERE target_id = ? ORDER BY discovered_at DESC",
                (tid,)
            ).fetchall()
            info["endpoints"] = [dict(e) for e in endpoints]

            # Findings
            findings = conn.execute(
                "SELECT * FROM findings WHERE target_id = ? ORDER BY found_at DESC",
                (tid,)
            ).fetchall()
            info["findings"] = [dict(f) for f in findings]

            # Techniques tried
            techniques = conn.execute(
                "SELECT * FROM techniques_tried WHERE target_id = ? ORDER BY tried_at DESC",
                (tid,)
            ).fetchall()
            info["techniques_tried"] = [dict(t) for t in techniques]

            # Auth tokens (mask values)
            tokens = conn.execute(
                "SELECT id, type, name, role, valid, expires_at, notes FROM auth_tokens WHERE target_id = ?",
                (tid,)
            ).fetchall()
            info["auth_tokens"] = [dict(t) for t in tokens]

            # Intel
            intel = conn.execute(
                "SELECT * FROM intel WHERE target_id = ? ORDER BY added_at DESC",
                (tid,)
            ).fetchall()
            info["intel"] = [dict(i) for i in intel]

            self._print_target_info(info)
            return info

    def _print_target_info(self, info):
        """Pretty-print target information."""
        print(f"\n{'='*60}")
        print(f"TARGET: {info['domain']}")
        print(f"{'='*60}")
        print(f"Program:    {info.get('program', 'N/A')}")
        print(f"Platform:   {info.get('platform', 'N/A')}")
        print(f"First seen: {info['first_seen']}")
        print(f"Last seen:  {info['last_seen']}")
        print(f"Tech stack: {', '.join(info['tech_stack']) if info['tech_stack'] else 'Unknown'}")
        if info.get("notes"):
            print(f"Notes:      {info['notes']}")

        eps = info["endpoints"]
        print(f"\nEndpoints: {len(eps)}")
        for e in eps[:20]:  # show first 20
            auth = " [AUTH]" if e["auth_required"] else ""
            print(f"  {e['method']:6s} {e['path']}{auth}  ({e.get('response_code', '?')})")
        if len(eps) > 20:
            print(f"  ... and {len(eps)-20} more")

        findings = info["findings"]
        print(f"\nFindings: {len(findings)}")
        for f in findings:
            bounty = f"  ${f['bounty']:.0f}" if f.get("bounty") else ""
            print(f"  [{f['severity']:8s}] {f['type']:10s} {f['title']}  ({f['status']}){bounty}")

        techniques = info["techniques_tried"]
        print(f"\nTechniques tried: {len(techniques)}")
        results = {}
        for t in techniques:
            results[t["result"]] = results.get(t["result"], 0) + 1
        for result, count in results.items():
            print(f"  {result}: {count}")

        tokens = info["auth_tokens"]
        print(f"\nAuth tokens: {len(tokens)}")
        for t in tokens:
            valid = "VALID" if t["valid"] else "EXPIRED"
            print(f"  {t['type']:10s} {t['name']} ({t['role']}) [{valid}]")

        intel = info["intel"]
        print(f"\nIntel: {len(intel)}")
        for i in intel[:10]:
            print(f"  [{i['source']:10s}] {i.get('title', i['summary'][:60])}")
        print()

    def target_update_tech(self, domain, tech_stack):
        """Update the tech stack for a target."""
        with self._db() as conn:
            conn.execute(
                "UPDATE targets SET tech_stack = ?, last_seen = datetime('now') WHERE domain = ?",
                (json.dumps(tech_stack), domain)
            )

    def target_list(self):
        """List all targets."""
        with self._db() as conn:
            targets = conn.execute(
                "SELECT t.*, "
                "(SELECT COUNT(*) FROM endpoints WHERE target_id=t.id) as ep_count, "
                "(SELECT COUNT(*) FROM findings WHERE target_id=t.id) as finding_count, "
                "(SELECT COALESCE(SUM(bounty),0) FROM findings WHERE target_id=t.id) as total_bounty "
                "FROM targets t ORDER BY last_seen DESC"
            ).fetchall()
            print(f"\n{'Domain':<35} {'Endpoints':>9} {'Findings':>8} {'Bounty':>10} {'Last Seen'}")
            print("-" * 90)
            for t in targets:
                bounty = f"${t['total_bounty']:.0f}" if t["total_bounty"] else "-"
                print(f"{t['domain']:<35} {t['ep_count']:>9} {t['finding_count']:>8} {bounty:>10} {t['last_seen']}")
            print()

    # ---- Endpoints ----

    def endpoint_add(self, domain, method, path, params=None, auth_required=False,
                     response_code=None, content_type=None, discovered_by=None, notes=""):
        """Record a discovered endpoint."""
        with self._db() as conn:
            target = conn.execute("SELECT id FROM targets WHERE domain = ?", (domain,)).fetchone()
            if not target:
                conn.execute("INSERT INTO targets (domain) VALUES (?)", (domain,))
                target = conn.execute("SELECT id FROM targets WHERE domain = ?", (domain,)).fetchone()

            try:
                conn.execute(
                    "INSERT INTO endpoints (target_id, method, path, params, auth_required, "
                    "response_code, content_type, discovered_by, notes) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (target["id"], method.upper(), path, json.dumps(params or {}),
                     auth_required, response_code, content_type, discovered_by, notes)
                )
                conn.execute("UPDATE targets SET last_seen = datetime('now') WHERE id = ?", (target["id"],))
                print(f"Endpoint added: {method.upper()} {path} on {domain}")
            except sqlite3.IntegrityError:
                # Update existing
                conn.execute(
                    "UPDATE endpoints SET params = ?, auth_required = ?, response_code = ?, "
                    "content_type = ?, notes = ? "
                    "WHERE target_id = ? AND method = ? AND path = ?",
                    (json.dumps(params or {}), auth_required, response_code,
                     content_type, notes, target["id"], method.upper(), path)
                )
                print(f"Endpoint updated: {method.upper()} {path} on {domain}")

    # ---- Findings ----

    def finding_add(self, domain, vuln_type, severity, title, description,
                    poc=None, endpoint_path=None, endpoint_method=None,
                    impact=None, steps=None):
        """Record a vulnerability finding."""
        with self._db() as conn:
            target = conn.execute("SELECT id FROM targets WHERE domain = ?", (domain,)).fetchone()
            if not target:
                print(f"Target not found: {domain}. Add it first with 'vault target add'.")
                return None

            endpoint_id = None
            if endpoint_path:
                ep = conn.execute(
                    "SELECT id FROM endpoints WHERE target_id = ? AND method = ? AND path = ?",
                    (target["id"], (endpoint_method or "GET").upper(), endpoint_path)
                ).fetchone()
                if ep:
                    endpoint_id = ep["id"]

            cursor = conn.execute(
                "INSERT INTO findings (target_id, endpoint_id, type, severity, title, "
                "description, poc, steps, impact) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (target["id"], endpoint_id, vuln_type, severity, title,
                 description, poc, json.dumps(steps) if steps else None, impact)
            )
            finding_id = cursor.lastrowid
            print(f"Finding #{finding_id} added: [{severity}] {vuln_type} - {title}")
            return finding_id

    def finding_update_status(self, finding_id, status, report_id=None,
                               reported_to=None, report_url=None, bounty=None):
        """Update a finding's status (reported, accepted, duplicate, etc.)."""
        with self._db() as conn:
            updates = ["status = ?"]
            values = [status]
            if report_id:
                updates.append("report_id = ?")
                values.append(report_id)
            if reported_to:
                updates.append("reported_to = ?")
                values.append(reported_to)
            if report_url:
                updates.append("report_url = ?")
                values.append(report_url)
            if bounty is not None:
                updates.append("bounty = ?")
                values.append(bounty)
            if status == "reported":
                updates.append("reported_at = datetime('now')")
            if status in ("resolved", "fixed"):
                updates.append("resolved_at = datetime('now')")

            values.append(finding_id)
            conn.execute(f"UPDATE findings SET {', '.join(updates)} WHERE id = ?", values)
            print(f"Finding #{finding_id} updated: status={status}")

    # ---- Techniques ----

    def technique_check(self, domain, technique, endpoint_path=None, endpoint_method=None):
        """Check if a technique was already tried on a target/endpoint."""
        with self._db() as conn:
            target = conn.execute("SELECT id FROM targets WHERE domain = ?", (domain,)).fetchone()
            if not target:
                return False

            query = "SELECT * FROM techniques_tried WHERE target_id = ? AND technique = ?"
            params = [target["id"], technique]

            if endpoint_path:
                ep = conn.execute(
                    "SELECT id FROM endpoints WHERE target_id = ? AND method = ? AND path = ?",
                    (target["id"], (endpoint_method or "GET").upper(), endpoint_path)
                ).fetchone()
                if ep:
                    query += " AND endpoint_id = ?"
                    params.append(ep["id"])

            result = conn.execute(query, params).fetchone()
            if result:
                print(f"Already tried: {technique} on {domain} ({result['result']} at {result['tried_at']})")
                return True
            return False

    def technique_log(self, domain, technique, result="inconclusive", agent=None,
                      details=None, endpoint_path=None, endpoint_method=None):
        """Record that a technique was tried."""
        with self._db() as conn:
            target = conn.execute("SELECT id FROM targets WHERE domain = ?", (domain,)).fetchone()
            if not target:
                print(f"Target not found: {domain}")
                return

            endpoint_id = None
            if endpoint_path:
                ep = conn.execute(
                    "SELECT id FROM endpoints WHERE target_id = ? AND method = ? AND path = ?",
                    (target["id"], (endpoint_method or "GET").upper(), endpoint_path)
                ).fetchone()
                if ep:
                    endpoint_id = ep["id"]

            conn.execute(
                "INSERT INTO techniques_tried (target_id, endpoint_id, technique, agent, result, details) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (target["id"], endpoint_id, technique, agent, result, details)
            )
            print(f"Technique logged: {technique} -> {result}")

    # ---- Auth Tokens ----

    def token_add(self, domain, token_type, name, value, role="user", expires_at=None, notes=""):
        """Store an auth token for a target."""
        with self._db() as conn:
            target = conn.execute("SELECT id FROM targets WHERE domain = ?", (domain,)).fetchone()
            if not target:
                print(f"Target not found: {domain}")
                return
            conn.execute(
                "INSERT INTO auth_tokens (target_id, type, name, value, role, expires_at, notes) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (target["id"], token_type, name, value, role, expires_at, notes)
            )
            print(f"Token stored: {token_type} '{name}' for {domain} (role: {role})")

    def token_get(self, domain, role=None):
        """Retrieve valid tokens for a target."""
        with self._db() as conn:
            target = conn.execute("SELECT id FROM targets WHERE domain = ?", (domain,)).fetchone()
            if not target:
                return []
            query = "SELECT * FROM auth_tokens WHERE target_id = ? AND valid = 1"
            params = [target["id"]]
            if role:
                query += " AND role = ?"
                params.append(role)
            return [dict(r) for r in conn.execute(query, params).fetchall()]

    def token_invalidate(self, token_id):
        """Mark a token as invalid/expired."""
        with self._db() as conn:
            conn.execute("UPDATE auth_tokens SET valid = 0 WHERE id = ?", (token_id,))
            print(f"Token #{token_id} invalidated")

    # ---- Intel ----

    def intel_add(self, domain, source, summary, url=None, title=None,
                  techniques=None, relevance="medium"):
        """Add intelligence about a target."""
        with self._db() as conn:
            target_id = None
            if domain:
                target = conn.execute("SELECT id FROM targets WHERE domain = ?", (domain,)).fetchone()
                if target:
                    target_id = target["id"]

            conn.execute(
                "INSERT INTO intel (target_id, source, url, title, summary, techniques, relevance) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (target_id, source, url, title, summary,
                 json.dumps(techniques or []), relevance)
            )
            print(f"Intel added: [{source}] {title or summary[:50]}")

    # ---- Export ----

    def export_target(self, domain, output_path=None):
        """Export all data for a target as JSON."""
        info = self.target_info(domain)
        if not info:
            return
        output = output_path or f"/tmp/claudeos-vault-export-{domain.replace('.', '_')}.json"
        # Fetch full token values for export
        with self._db() as conn:
            target = conn.execute("SELECT id FROM targets WHERE domain = ?", (domain,)).fetchone()
            tokens = conn.execute(
                "SELECT * FROM auth_tokens WHERE target_id = ?", (target["id"],)
            ).fetchall()
            info["auth_tokens"] = [dict(t) for t in tokens]

        with open(output, "w") as f:
            json.dump(info, f, indent=2, default=str)
        print(f"Exported to: {output}")

    # ---- Import from proxy-core ----

    def import_from_proxy(self, proxy_output_dir="/tmp/claudeos-proxy"):
        """Import discovered endpoints from proxy-core output."""
        endpoints_file = os.path.join(proxy_output_dir, "endpoints.json")
        state_file = os.path.join(proxy_output_dir, "proxy-state.json")

        if not os.path.exists(endpoints_file):
            print(f"No proxy data found at {endpoints_file}")
            return

        with open(endpoints_file) as f:
            endpoints = json.load(f)

        count = 0
        for ep in endpoints:
            self.endpoint_add(
                domain=ep["domain"],
                method=ep["method"],
                path=ep["path"],
                params=ep.get("params"),
                auth_required=ep.get("auth_required", False),
                response_code=ep.get("status"),
                content_type=ep.get("content_type"),
                discovered_by="proxy-core",
            )
            count += 1

        # Import tech stack if available
        if os.path.exists(state_file):
            with open(state_file) as f:
                state = json.load(f)
            for domain, info in state.get("domains", {}).items():
                tech = info.get("tech_stack", [])
                if tech:
                    self.target_update_tech(domain, tech)

        print(f"Imported {count} endpoints from proxy-core")

    # ---- Stats ----

    def stats(self):
        """Show overall stats across all targets."""
        with self._db() as conn:
            targets = conn.execute("SELECT COUNT(*) as c FROM targets").fetchone()["c"]
            endpoints = conn.execute("SELECT COUNT(*) as c FROM endpoints").fetchone()["c"]
            findings = conn.execute("SELECT COUNT(*) as c FROM findings").fetchone()["c"]
            techniques = conn.execute("SELECT COUNT(*) as c FROM techniques_tried").fetchone()["c"]
            tokens = conn.execute("SELECT COUNT(*) as c FROM auth_tokens").fetchone()["c"]
            intel_count = conn.execute("SELECT COUNT(*) as c FROM intel").fetchone()["c"]
            total_bounty = conn.execute("SELECT COALESCE(SUM(bounty), 0) as s FROM findings").fetchone()["s"]

            # Findings by severity
            by_severity = conn.execute(
                "SELECT severity, COUNT(*) as c FROM findings GROUP BY severity ORDER BY "
                "CASE severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 "
                "WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4 ELSE 5 END"
            ).fetchall()

            # Findings by status
            by_status = conn.execute(
                "SELECT status, COUNT(*) as c FROM findings GROUP BY status"
            ).fetchall()

            # Top earning targets
            top_targets = conn.execute(
                "SELECT t.domain, SUM(f.bounty) as total FROM findings f "
                "JOIN targets t ON f.target_id = t.id "
                "WHERE f.bounty > 0 GROUP BY t.domain ORDER BY total DESC LIMIT 5"
            ).fetchall()

            print(f"\n{'='*50}")
            print(f"CLAUDEOS TARGET VAULT STATS")
            print(f"{'='*50}")
            print(f"Targets:          {targets}")
            print(f"Endpoints:        {endpoints}")
            print(f"Findings:         {findings}")
            print(f"Techniques tried: {techniques}")
            print(f"Auth tokens:      {tokens}")
            print(f"Intel entries:    {intel_count}")
            print(f"Total bounty:     ${total_bounty:,.2f}")

            if by_severity:
                print(f"\nFindings by severity:")
                for row in by_severity:
                    print(f"  {row['severity']:10s} {row['c']}")

            if by_status:
                print(f"\nFindings by status:")
                for row in by_status:
                    print(f"  {row['status']:15s} {row['c']}")

            if top_targets:
                print(f"\nTop earning targets:")
                for row in top_targets:
                    print(f"  {row['domain']:<30s} ${row['total']:,.2f}")
            print()

    # ---- Search ----

    def search(self, query):
        """Search across all targets for patterns."""
        with self._db() as conn:
            pattern = f"%{query}%"
            print(f"\nSearching for: {query}")
            print("-" * 50)

            # Search endpoints
            eps = conn.execute(
                "SELECT e.*, t.domain FROM endpoints e JOIN targets t ON e.target_id = t.id "
                "WHERE e.path LIKE ? OR e.params LIKE ? OR e.notes LIKE ?",
                (pattern, pattern, pattern)
            ).fetchall()
            if eps:
                print(f"\nEndpoints ({len(eps)}):")
                for e in eps[:15]:
                    print(f"  {e['domain']} {e['method']} {e['path']}")

            # Search findings
            findings = conn.execute(
                "SELECT f.*, t.domain FROM findings f JOIN targets t ON f.target_id = t.id "
                "WHERE f.title LIKE ? OR f.description LIKE ? OR f.poc LIKE ? OR f.type LIKE ?",
                (pattern, pattern, pattern, pattern)
            ).fetchall()
            if findings:
                print(f"\nFindings ({len(findings)}):")
                for f in findings[:15]:
                    print(f"  [{f['severity']}] {f['domain']} - {f['title']}")

            # Search intel
            intels = conn.execute(
                "SELECT * FROM intel WHERE summary LIKE ? OR title LIKE ? OR techniques LIKE ?",
                (pattern, pattern, pattern)
            ).fetchall()
            if intels:
                print(f"\nIntel ({len(intels)}):")
                for i in intels[:15]:
                    print(f"  [{i['source']}] {i.get('title', i['summary'][:60])}")

            if not eps and not findings and not intels:
                print("  No results found.")
            print()


# ---- CLI Interface ----

def main():
    vault = Vault()
    args = sys.argv[1:]

    if not args:
        print("Usage: vault <command> [args]")
        print("Commands: init, target, endpoint, finding, technique, token, intel, import, export, stats, search, backup")
        return

    cmd = args[0]

    if cmd == "init":
        vault.init()

    elif cmd == "backup":
        vault.backup()

    elif cmd == "target":
        if len(args) < 2:
            print("Usage: vault target <add|info|list> [args]")
            return
        sub = args[1]
        if sub == "add" and len(args) >= 3:
            vault.target_add(
                args[2],
                program=args[3] if len(args) > 3 else None,
                platform=args[4] if len(args) > 4 else None,
            )
        elif sub == "info" and len(args) >= 3:
            vault.target_info(args[2])
        elif sub == "list":
            vault.target_list()
        else:
            print("Usage: vault target <add DOMAIN [PROGRAM] [PLATFORM]|info DOMAIN|list>")

    elif cmd == "endpoint":
        if len(args) < 2:
            print("Usage: vault endpoint add DOMAIN METHOD PATH")
            return
        if args[1] == "add" and len(args) >= 5:
            vault.endpoint_add(args[2], args[3], args[4],
                              discovered_by=args[5] if len(args) > 5 else None)

    elif cmd == "finding":
        if len(args) < 2:
            print("Usage: vault finding <add|status> [args]")
            return
        if args[1] == "add" and len(args) >= 6:
            vault.finding_add(args[2], args[3], args[4], args[5],
                            description=args[6] if len(args) > 6 else args[5])
        elif args[1] == "status" and len(args) >= 4:
            vault.finding_update_status(int(args[2]), args[3],
                                       bounty=float(args[4]) if len(args) > 4 else None)

    elif cmd == "technique":
        if len(args) < 2:
            print("Usage: vault technique <check|log> DOMAIN TECHNIQUE [result]")
            return
        if args[1] == "check" and len(args) >= 4:
            vault.technique_check(args[2], args[3])
        elif args[1] == "log" and len(args) >= 4:
            vault.technique_log(args[2], args[3],
                              result=args[4] if len(args) > 4 else "inconclusive",
                              agent=args[5] if len(args) > 5 else None)

    elif cmd == "token":
        if len(args) < 2:
            return
        if args[1] == "add" and len(args) >= 6:
            vault.token_add(args[2], args[3], args[4], args[5],
                          role=args[6] if len(args) > 6 else "user")
        elif args[1] == "get" and len(args) >= 3:
            tokens = vault.token_get(args[2], role=args[3] if len(args) > 3 else None)
            for t in tokens:
                print(f"  {t['type']} {t['name']}={t['value'][:20]}... (role: {t['role']})")

    elif cmd == "intel":
        if len(args) >= 4 and args[1] == "add":
            vault.intel_add(args[2], args[3],
                          summary=args[4] if len(args) > 4 else "No summary",
                          url=args[5] if len(args) > 5 else None)

    elif cmd == "import":
        proxy_dir = args[1] if len(args) > 1 else "/tmp/claudeos-proxy"
        vault.import_from_proxy(proxy_dir)

    elif cmd == "export":
        if len(args) >= 2:
            vault.export_target(args[1])

    elif cmd == "stats":
        vault.stats()

    elif cmd == "search":
        if len(args) >= 2:
            vault.search(" ".join(args[1:]))

    else:
        print(f"Unknown command: {cmd}")


if __name__ == "__main__":
    main()
```

---

## 4. Commands

```bash
# Initialize the vault
vault init
# python3 /opt/claudeos/target-vault/vault.py init

# --- Target management ---
vault target add example.com "Shopify" "H1"
vault target info example.com
vault target list

# --- Record discovered endpoints ---
vault endpoint add example.com GET /api/v1/users proxy-core
vault endpoint add example.com POST /api/v1/login js-analyzer
vault endpoint add example.com DELETE /api/v1/users/123 proxy-core

# --- Record findings ---
vault finding add example.com IDOR High "User data accessible via sequential ID" \
  "Changing user_id parameter in GET /api/v1/users/{id} returns other users' data"

# Update finding status after reporting
vault finding status 1 reported
vault finding status 1 accepted 500   # accepted with $500 bounty

# --- Track techniques ---
# Check before testing (avoid duplicate work)
vault technique check example.com cors-origin-reflection
# Log what was tried
vault technique log example.com cors-origin-reflection failed cors-chain-analyzer
vault technique log example.com idor-sequential-id success idor-hunter

# --- Manage auth tokens ---
vault token add example.com jwt "Authorization" "eyJ..." user
vault token add example.com cookie "session_id" "abc123" admin
vault token get example.com user

# --- Add intelligence ---
vault intel add example.com hacktivity "IDOR in user profile endpoint" \
  "https://hackerone.com/reports/123456"

# --- Import from proxy-core ---
vault import /tmp/claudeos-proxy

# --- Export target data ---
vault export example.com

# --- Search across everything ---
vault search "IDOR"
vault search "/api/v1/users"
vault search "cors"

# --- Stats ---
vault stats

# --- Backup ---
vault backup
```

---

## 5. Integration with Other Agents

### Every agent should do this before testing:

```python
# At the start of any technique test
import subprocess

def should_test(domain, technique, endpoint_path=None):
    """Check vault before testing -- don't repeat work."""
    cmd = f"python3 /opt/claudeos/target-vault/vault.py technique check {domain} {technique}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return "Already tried" not in result.stdout

def log_result(domain, technique, result, agent_name, endpoint_path=None):
    """Log what was tried to the vault."""
    cmd = (f"python3 /opt/claudeos/target-vault/vault.py technique log "
           f"{domain} {technique} {result} {agent_name}")
    subprocess.run(cmd, shell=True)
```

### Proxy-core integration:

After every proxy session, run:
```bash
python3 /opt/claudeos/target-vault/vault.py import /tmp/claudeos-proxy
```

This auto-imports all discovered endpoints and tech stack data.

### CORS Chain Analyzer integration:

```python
# When CORS Chain Analyzer finds a misconfiguration
vault.finding_add(
    domain="api.example.com",
    vuln_type="CORS",
    severity="High",
    title="CORS allows arbitrary origin with credentials",
    description="The endpoint /api/v1/user reflects any Origin header in ACAO while ACAC is true.",
    poc='curl -H "Origin: https://evil.com" https://api.example.com/api/v1/user -v',
    endpoint_path="/api/v1/user",
    endpoint_method="GET",
    impact="Attacker can steal authenticated user data cross-origin",
)
```

### IDOR Hunter integration:

```python
# Before testing
if not vault.technique_check("example.com", "idor-sequential-id", "/api/v1/users"):
    # Run the test
    result = test_idor(...)
    # Log the result
    vault.technique_log("example.com", "idor-sequential-id",
                       result="success" if result.vulnerable else "failed",
                       agent="idor-hunter",
                       endpoint_path="/api/v1/users")
    if result.vulnerable:
        vault.finding_add(...)
```

### Bounty Report Writer integration:

```python
# Pull finding data for report generation
info = vault.target_info("example.com")
findings = [f for f in info["findings"] if f["status"] == "found"]
for finding in findings:
    generate_report(finding)
    vault.finding_update_status(finding["id"], "reported",
                                reported_to="H1",
                                report_url="https://hackerone.com/reports/XXXXX")
```

### Community-brain / intel feed:

```python
# When a relevant writeup is found
vault.intel_add(
    domain="example.com",
    source="hacktivity",
    summary="IDOR in Shopify partner API allowed accessing other stores' data",
    url="https://hackerone.com/reports/999999",
    title="Shopify Partner API IDOR",
    techniques=["idor", "api-parameter-tampering", "uuid-swap"],
    relevance="high",
)
```

---

## 6. Programmatic API (for Python agents)

Any agent can import the vault directly:

```python
import sys
sys.path.insert(0, "/opt/claudeos/target-vault")
from vault import Vault

v = Vault()

# Add endpoint
v.endpoint_add("target.com", "POST", "/api/auth/login",
               params={"email": "string", "password": "string"},
               discovered_by="js-analyzer")

# Check if technique was tried
already_done = v.technique_check("target.com", "sqli-union-based", "/api/search")

# Get auth tokens for a target
tokens = v.token_get("target.com", role="admin")
admin_token = tokens[0]["value"] if tokens else None

# Search for patterns across all targets
v.search("graphql")
```

---

## 7. Data Lifecycle

```
Target added
    |
    v
Endpoints discovered (proxy-core, js-analyzer, swagger-extractor, etc.)
    |
    v
Techniques checked (avoid repeats) -> Techniques logged (track results)
    |
    v
Findings recorded (with PoC and impact)
    |
    v
Findings reported (status: reported, report_id, platform)
    |
    v
Findings resolved (status: accepted/duplicate/informative, bounty amount)
    |
    v
Intel added (writeups, CVEs, community knowledge)
    |
    v
Everything persists. Come back in 6 months and pick up exactly where you left off.
```

---

## 8. Troubleshooting

| Problem | Solution |
|---------|----------|
| Database locked | WAL mode handles concurrent reads; for writes, ensure only one process writes at a time |
| Vault file missing | Run `vault init` to create it |
| Duplicate endpoint error | The UNIQUE constraint triggers an UPDATE instead -- this is expected |
| Slow on large datasets | Indexes are pre-built on target_id, type, status -- should be fast to 100K+ rows |
| Need to migrate schema | Run `vault backup` first, then add columns with `ALTER TABLE` |
| Corrupted database | Restore from `~/.claudeos/vault-backups/` |
