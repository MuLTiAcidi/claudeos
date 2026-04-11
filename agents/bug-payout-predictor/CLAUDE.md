# Bug Payout Predictor Agent

Given a vulnerability type + a bug bounty program, predict the likely payout. Pulls historical disclosures from HackerOne's hacktivity feed and Bugcrowd's public disclosures, caches them in SQLite, classifies reports by vuln type (XSS, SQLi, IDOR, SSRF, RCE, Auth Bypass, etc.) and computes min/median/mean/p90/max per (program, vuln-type) combination. Helps hunters decide: *"is this report worth 4 hours of writing?"*

## Safety Rules

- Uses ONLY public data from HackerOne hacktivity and Bugcrowd disclosure feeds
- Respect rate limits — default 1 req/sec with polite backoff
- Cache aggressively in SQLite so we don't re-fetch
- Never impersonate a real researcher or platform — use a distinct `User-Agent`
- Do NOT submit, edit, or interact with any report — read-only
- Predictions are estimates — always caveat output with "historical, not guaranteed"

---

## 1. Install / Bootstrap

```bash
sudo mkdir -p /var/lib/claudeos/payout-predictor /var/log/claudeos /etc/claudeos
sudo touch /var/log/claudeos/bug-payout-predictor.log
sudo chmod 0640 /var/log/claudeos/bug-payout-predictor.log

# Python + deps
command -v python3 >/dev/null || sudo apt-get install -y python3 python3-venv python3-pip
python3 -m pip install --user --break-system-packages requests==2.* beautifulsoup4 rich tabulate 2>/dev/null || \
  python3 -m pip install --user requests beautifulsoup4 rich tabulate

# SQLite lives inline with Python, but the cli is useful
command -v sqlite3 >/dev/null || sudo apt-get install -y sqlite3
```

### Config

```bash
sudo tee /etc/claudeos/bug-payout-predictor.conf >/dev/null <<'CONF'
# /etc/claudeos/bug-payout-predictor.conf
DB_PATH=/var/lib/claudeos/payout-predictor/reports.db
USER_AGENT=ClaudeOS-PayoutPredictor/1.0 (+research)
HACKERONE_HACKTIVITY_URL=https://hackerone.com/hacktivity
HACKERONE_GRAPHQL_URL=https://hackerone.com/graphql
BUGCROWD_DISCLOSURE_URL=https://bugcrowd.com/crowdstream
REQUEST_DELAY_SECONDS=1
MAX_PAGES_PER_RUN=20
CACHE_TTL_HOURS=24
CONF
```

---

## 2. SQLite Schema

```bash
python3 - <<'PY'
import sqlite3, os
os.makedirs("/var/lib/claudeos/payout-predictor", exist_ok=True)
db = sqlite3.connect("/var/lib/claudeos/payout-predictor/reports.db")
db.executescript("""
CREATE TABLE IF NOT EXISTS reports (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  platform         TEXT NOT NULL,              -- hackerone | bugcrowd
  external_id      TEXT NOT NULL,              -- H1 report id or Bugcrowd UUID
  program          TEXT NOT NULL,              -- e.g. 'shopify', 'gitlab'
  program_type     TEXT,                       -- bbp, vdp, private
  title            TEXT,
  vuln_type        TEXT,                       -- normalized enum (xss, sqli, idor...)
  severity         TEXT,                       -- none, low, medium, high, critical
  bounty_usd       REAL,                       -- 0 if unpaid/VDP
  currency         TEXT DEFAULT 'USD',
  disclosed_at     TEXT,                       -- ISO date
  url              TEXT,
  raw_json         TEXT,
  fetched_at       TEXT DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(platform, external_id)
);
CREATE INDEX IF NOT EXISTS idx_program_vuln ON reports(program, vuln_type);
CREATE INDEX IF NOT EXISTS idx_disclosed    ON reports(disclosed_at);
CREATE INDEX IF NOT EXISTS idx_severity     ON reports(severity);

CREATE TABLE IF NOT EXISTS fetch_state (
  key        TEXT PRIMARY KEY,
  value      TEXT,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);
""")
db.commit()
print("[+] schema ready ->", db.total_changes, "ops")
PY
```

---

## 3. Vulnerability Type Normalizer

The core challenge is that H1 / Bugcrowd use ~200 free-text vuln classifications. We squash them into ~20 buckets.

```bash
sudo mkdir -p /usr/local/lib/claudeos
sudo tee /usr/local/lib/claudeos/vuln_normalizer.py >/dev/null <<'PY'
"""Normalize messy vuln_type strings to a canonical enum."""
import re

CANONICAL = [
    "xss", "sqli", "idor", "ssrf", "rce", "xxe", "csrf",
    "open-redirect", "auth-bypass", "info-disclosure", "ssti",
    "lfi", "rfi", "path-traversal", "deserialization", "race",
    "prototype-pollution", "cache-poisoning", "request-smuggling",
    "subdomain-takeover", "oauth", "saml", "jwt", "business-logic",
    "dos", "hardcoded-secret", "s3-misconfig", "cors", "clickjacking",
    "other",
]

RULES = [
    (r"cross.?site.?script|xss|reflected|stored|dom[- ]?xss",             "xss"),
    (r"sql.?inject|sqli|nosql|blind.?sql",                                 "sqli"),
    (r"insecure direct object|idor|bola|object.?level.?authori",           "idor"),
    (r"server.?side.?request|ssrf",                                        "ssrf"),
    (r"remote code execution|rce|command injection",                       "rce"),
    (r"xml.?external entit|xxe|xml inj",                                   "xxe"),
    (r"cross.?site.?request.?forger|csrf",                                 "csrf"),
    (r"open.?redirect",                                                    "open-redirect"),
    (r"auth.?bypass|authentication bypass|broken auth|improper auth",      "auth-bypass"),
    (r"information disclosure|info.?leak|sensitive data exposure",         "info-disclosure"),
    (r"server.?side template injection|ssti|template injection",           "ssti"),
    (r"local file inclusion|lfi",                                          "lfi"),
    (r"remote file inclusion|rfi",                                         "rfi"),
    (r"path traversal|directory traversal",                                "path-traversal"),
    (r"deserialization|unsafe yaml|pickle",                                "deserialization"),
    (r"race.?condition|toctou",                                            "race"),
    (r"prototype pollution",                                               "prototype-pollution"),
    (r"cache poisoning|web cache",                                         "cache-poisoning"),
    (r"request smuggling|http smuggling|desync",                           "request-smuggling"),
    (r"subdomain takeover",                                                "subdomain-takeover"),
    (r"oauth|openid",                                                      "oauth"),
    (r"saml|xml signature wrap",                                           "saml"),
    (r"jwt|jsonwebtoken|json web token",                                   "jwt"),
    (r"business logic",                                                    "business-logic"),
    (r"denial of service|dos\b",                                           "dos"),
    (r"hardcoded|leaked.*key|exposed.*token",                              "hardcoded-secret"),
    (r"s3|bucket",                                                         "s3-misconfig"),
    (r"cors",                                                              "cors"),
    (r"clickjack|ui redress",                                              "clickjacking"),
]

def normalize(text):
    if not text:
        return "other"
    t = text.lower()
    for pattern, label in RULES:
        if re.search(pattern, t):
            return label
    return "other"

if __name__ == "__main__":
    import sys
    for line in sys.stdin:
        print(normalize(line.strip()))
PY
sudo chmod 0644 /usr/local/lib/claudeos/vuln_normalizer.py
```

---

## 4. HackerOne Fetcher

HackerOne's hacktivity page is server-rendered HTML and also exposes a GraphQL endpoint. We use the public GraphQL endpoint with no auth — it returns disclosed reports only.

```bash
sudo tee /usr/local/lib/claudeos/h1_fetch.py >/dev/null <<'PY'
#!/usr/bin/env python3
"""
HackerOne hacktivity fetcher. Uses the public unauthenticated GraphQL
endpoint at https://hackerone.com/graphql that backs the hacktivity page.
"""
import json, os, sys, time, sqlite3, argparse, re
import requests
sys.path.insert(0, "/usr/local/lib/claudeos")
from vuln_normalizer import normalize

DB_PATH   = os.environ.get("DB_PATH",   "/var/lib/claudeos/payout-predictor/reports.db")
UA        = os.environ.get("USER_AGENT","ClaudeOS-PayoutPredictor/1.0")
DELAY     = float(os.environ.get("REQUEST_DELAY_SECONDS","1.0"))
GQL       = "https://hackerone.com/graphql"

# Queries the same GraphQL op the hacktivity page issues.
QUERY = """
query HacktivityPageQuery($cursor: String, $count: Int!) {
  hacktivity_items(first: $count, after: $cursor, order_by: {field: popular, direction: DESC}) {
    edges {
      node {
        ... on HacktivityItemInterface {
          __typename
          databaseId: _id
          url
          disclosed_at: disclosed_at
        }
        ... on Disclosed {
          report {
            databaseId: _id
            title
            url
            disclosed_at
            severity_rating
            bounty_amount
            formatted_bounty
            vulnerability_information_substring
            weakness { name }
            team {
              handle
              profile { name }
              offers_bounties
            }
          }
        }
      }
      cursor
    }
    pageInfo { endCursor hasNextPage }
  }
}
"""

def db():
    return sqlite3.connect(DB_PATH)

def save(row):
    c = db()
    c.execute("""INSERT OR IGNORE INTO reports
        (platform, external_id, program, program_type, title, vuln_type,
         severity, bounty_usd, disclosed_at, url, raw_json)
        VALUES ('hackerone', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (row["external_id"], row["program"], row["program_type"],
         row["title"], row["vuln_type"], row["severity"],
         row["bounty_usd"], row["disclosed_at"], row["url"],
         json.dumps(row["raw"])))
    c.commit()
    c.close()

def fetch(max_pages=20):
    sess = requests.Session()
    sess.headers.update({
        "User-Agent": UA,
        "Accept": "application/json",
        "Content-Type": "application/json",
        "X-Auth-Token": "----",
    })
    cursor = None
    total = 0
    for page in range(max_pages):
        body = {"operationName":"HacktivityPageQuery",
                "query": QUERY,
                "variables": {"cursor": cursor, "count": 25}}
        try:
            r = sess.post(GQL, json=body, timeout=30)
            r.raise_for_status()
            data = r.json()
        except Exception as e:
            print(f"[!] fetch error: {e}", file=sys.stderr)
            break
        try:
            items = data["data"]["hacktivity_items"]
        except (KeyError, TypeError):
            print("[!] unexpected response:", str(data)[:500], file=sys.stderr)
            break

        for edge in items.get("edges", []):
            node = edge.get("node") or {}
            rep  = node.get("report") or {}
            if not rep:
                continue
            team = rep.get("team") or {}
            profile = team.get("profile") or {}
            weakness = (rep.get("weakness") or {}).get("name","") or rep.get("title","")
            bounty = rep.get("bounty_amount")
            try:
                bounty = float(bounty) if bounty is not None else 0.0
            except ValueError:
                bounty = 0.0
            row = {
                "external_id": str(rep.get("databaseId","")),
                "program":     team.get("handle",""),
                "program_type":"bbp" if team.get("offers_bounties") else "vdp",
                "title":       rep.get("title",""),
                "vuln_type":   normalize(weakness),
                "severity":    (rep.get("severity_rating") or "").lower(),
                "bounty_usd":  bounty,
                "disclosed_at":rep.get("disclosed_at",""),
                "url":         rep.get("url",""),
                "raw":         rep,
            }
            save(row)
            total += 1
        page_info = items.get("pageInfo", {})
        if not page_info.get("hasNextPage"): break
        cursor = page_info.get("endCursor")
        time.sleep(DELAY)
    print(f"[+] fetched {total} hackerone reports")
    return total

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--pages", type=int, default=int(os.environ.get("MAX_PAGES_PER_RUN","20")))
    args = ap.parse_args()
    fetch(args.pages)
PY
sudo chmod +x /usr/local/lib/claudeos/h1_fetch.py
```

> **Note on H1 GraphQL schema drift**: HackerOne occasionally renames fields on their GraphQL. If the fetcher breaks, open the hacktivity page in a browser, open devtools → Network → XHR, copy the GraphQL query, and update `QUERY` above.

---

## 5. Bugcrowd Fetcher

Bugcrowd exposes the `crowdstream` disclosure feed as HTML + a JSON API at `/crowdstream.json?page=N`.

```bash
sudo tee /usr/local/lib/claudeos/bugcrowd_fetch.py >/dev/null <<'PY'
#!/usr/bin/env python3
import json, os, sys, time, sqlite3, argparse
import requests
sys.path.insert(0, "/usr/local/lib/claudeos")
from vuln_normalizer import normalize

DB_PATH = os.environ.get("DB_PATH","/var/lib/claudeos/payout-predictor/reports.db")
UA      = os.environ.get("USER_AGENT","ClaudeOS-PayoutPredictor/1.0")
DELAY   = float(os.environ.get("REQUEST_DELAY_SECONDS","1.0"))
BASE    = "https://bugcrowd.com/crowdstream.json"

def db():
    return sqlite3.connect(DB_PATH)

def save(ext_id, row):
    c = db()
    c.execute("""INSERT OR IGNORE INTO reports
        (platform, external_id, program, program_type, title, vuln_type,
         severity, bounty_usd, disclosed_at, url, raw_json)
        VALUES ('bugcrowd', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (ext_id, row["program"], row["program_type"], row["title"],
         row["vuln_type"], row["severity"], row["bounty_usd"],
         row["disclosed_at"], row["url"], json.dumps(row["raw"])))
    c.commit(); c.close()

def fetch(max_pages=20):
    sess = requests.Session()
    sess.headers.update({"User-Agent": UA, "Accept":"application/json"})
    total = 0
    for page in range(1, max_pages+1):
        try:
            r = sess.get(BASE, params={"page": page, "filter": "disclosures"}, timeout=30)
            r.raise_for_status()
            data = r.json()
        except Exception as e:
            print(f"[!] {e}", file=sys.stderr); break
        results = data.get("results") or data.get("crowdstream_items") or []
        if not results: break
        for item in results:
            sev = (item.get("severity") or "").lower()
            payout = item.get("amount") or item.get("reward")
            try:
                payout = float(str(payout).replace("$","").replace(",","")) if payout else 0.0
            except Exception:
                payout = 0.0
            row = {
                "program":      (item.get("program") or {}).get("code","") if isinstance(item.get("program"), dict) else str(item.get("program","")),
                "program_type": "bbp" if payout > 0 else "vdp",
                "title":        item.get("title",""),
                "vuln_type":    normalize(item.get("category","") + " " + item.get("title","")),
                "severity":     sev,
                "bounty_usd":   payout,
                "disclosed_at": item.get("disclosed_at") or item.get("created_at",""),
                "url":          "https://bugcrowd.com" + (item.get("url","")),
                "raw":          item,
            }
            save(str(item.get("id") or item.get("uuid") or row["url"]), row)
            total += 1
        time.sleep(DELAY)
    print(f"[+] fetched {total} bugcrowd reports")
    return total

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--pages", type=int, default=20)
    fetch(ap.parse_args().pages)
PY
sudo chmod +x /usr/local/lib/claudeos/bugcrowd_fetch.py
```

---

## 6. Query / Predict Engine

```bash
sudo tee /usr/local/lib/claudeos/predictor.py >/dev/null <<'PY'
#!/usr/bin/env python3
"""
predictor.py — query the cached reports db and produce payout statistics.
"""
import sqlite3, statistics, argparse, json, sys, os
from tabulate import tabulate

DB_PATH = os.environ.get("DB_PATH","/var/lib/claudeos/payout-predictor/reports.db")

def rows(program=None, vuln_type=None, min_bounty=0, only_paid=True):
    q = "SELECT program, vuln_type, severity, bounty_usd, disclosed_at, url FROM reports WHERE 1=1"
    args = []
    if program:
        q += " AND lower(program) = lower(?)"
        args.append(program)
    if vuln_type:
        q += " AND vuln_type = ?"
        args.append(vuln_type)
    if only_paid:
        q += " AND bounty_usd > 0"
    q += " AND bounty_usd >= ?"
    args.append(min_bounty)
    c = sqlite3.connect(DB_PATH)
    out = list(c.execute(q, args))
    c.close()
    return out

def stats(values):
    if not values: return None
    values = sorted(values)
    n = len(values)
    def pct(p):
        k = max(0, min(n-1, int(round((p/100.0)*(n-1)))))
        return values[k]
    return {
        "count": n,
        "min":   values[0],
        "p25":   pct(25),
        "median":statistics.median(values),
        "mean":  round(statistics.mean(values),2),
        "p75":   pct(75),
        "p90":   pct(90),
        "max":   values[-1],
        "stdev": round(statistics.pstdev(values),2) if n > 1 else 0,
    }

def predict(program, vuln_type):
    direct = [r[3] for r in rows(program=program, vuln_type=vuln_type)]
    if direct and len(direct) >= 3:
        return {"confidence":"high","basis":f"{len(direct)} direct matches","stats":stats(direct)}
    same_vuln = [r[3] for r in rows(vuln_type=vuln_type)]
    same_prog = [r[3] for r in rows(program=program)]
    blended = direct + same_vuln[:50]
    if blended:
        return {"confidence":"medium","basis":f"{len(direct)} direct + {len(same_vuln)} same-vuln avg","stats":stats(blended)}
    if same_prog:
        return {"confidence":"low","basis":f"fallback: program avg ({len(same_prog)})","stats":stats(same_prog)}
    return {"confidence":"none","basis":"no data","stats":None}

def top_programs(n=20):
    c = sqlite3.connect(DB_PATH)
    r = list(c.execute("""
        SELECT program, COUNT(*) as reports, ROUND(AVG(bounty_usd),0) as avg_bounty,
               ROUND(MAX(bounty_usd),0) as max_bounty
        FROM reports WHERE bounty_usd > 0
        GROUP BY program ORDER BY reports DESC LIMIT ?""", (n,)))
    c.close()
    return r

def top_vulns(program=None, n=20):
    c = sqlite3.connect(DB_PATH)
    if program:
        r = list(c.execute("""
            SELECT vuln_type, COUNT(*), ROUND(AVG(bounty_usd),0), ROUND(MAX(bounty_usd),0)
            FROM reports WHERE bounty_usd > 0 AND lower(program)=lower(?)
            GROUP BY vuln_type ORDER BY AVG(bounty_usd) DESC LIMIT ?""", (program, n)))
    else:
        r = list(c.execute("""
            SELECT vuln_type, COUNT(*), ROUND(AVG(bounty_usd),0), ROUND(MAX(bounty_usd),0)
            FROM reports WHERE bounty_usd > 0
            GROUP BY vuln_type ORDER BY AVG(bounty_usd) DESC LIMIT ?""", (n,)))
    c.close()
    return r

def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("predict")
    p.add_argument("--program", required=True)
    p.add_argument("--vuln",    required=True, help="e.g. xss, sqli, idor, ssrf, rce")
    p.add_argument("--json", action="store_true")

    sub.add_parser("top-programs").add_argument("--n", type=int, default=20)
    tp = sub.add_parser("top-vulns")
    tp.add_argument("--program", default=None)
    tp.add_argument("--n", type=int, default=20)

    l = sub.add_parser("list")
    l.add_argument("--program", default=None)
    l.add_argument("--vuln", default=None)
    l.add_argument("--limit", type=int, default=20)

    st = sub.add_parser("stats")

    args = ap.parse_args()

    if args.cmd == "predict":
        out = predict(args.program, args.vuln)
        if args.json:
            print(json.dumps(out, indent=2))
        else:
            s = out["stats"]
            print(f"\nProgram : {args.program}\nVuln    : {args.vuln}\nConfidence: {out['confidence']}\nBasis   : {out['basis']}")
            if s:
                print(tabulate([[k,v] for k,v in s.items()], headers=["stat","value"]))
                print(f"\nPrediction range: ${int(s['p25'])} – ${int(s['p75'])} (median ${int(s['median'])})")
            else:
                print("No data.")

    elif args.cmd == "top-programs":
        print(tabulate(top_programs(args.n), headers=["program","reports","avg","max"]))

    elif args.cmd == "top-vulns":
        print(tabulate(top_vulns(args.program, args.n), headers=["vuln","reports","avg","max"]))

    elif args.cmd == "list":
        r = rows(program=args.program, vuln_type=args.vuln)[:args.limit]
        print(tabulate(r, headers=["program","vuln","sev","$","date","url"]))

    elif args.cmd == "stats":
        c = sqlite3.connect(DB_PATH)
        total = c.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
        paid  = c.execute("SELECT COUNT(*) FROM reports WHERE bounty_usd>0").fetchone()[0]
        sums  = c.execute("SELECT SUM(bounty_usd), AVG(bounty_usd), MAX(bounty_usd) FROM reports WHERE bounty_usd>0").fetchone()
        progs = c.execute("SELECT COUNT(DISTINCT program) FROM reports").fetchone()[0]
        c.close()
        print(f"Total reports : {total}")
        print(f"Paid reports  : {paid}")
        print(f"Programs      : {progs}")
        print(f"Total paid    : ${int(sums[0] or 0):,}")
        print(f"Avg bounty    : ${int(sums[1] or 0):,}")
        print(f"Max bounty    : ${int(sums[2] or 0):,}")

if __name__ == "__main__":
    main()
PY
sudo chmod +x /usr/local/lib/claudeos/predictor.py
```

---

## 7. Unified CLI: `bug-payout`

```bash
sudo tee /usr/local/bin/bug-payout >/dev/null <<'BASH'
#!/usr/bin/env bash
set -euo pipefail
CONF=/etc/claudeos/bug-payout-predictor.conf
[ -f "$CONF" ] && source "$CONF"
export DB_PATH USER_AGENT REQUEST_DELAY_SECONDS MAX_PAGES_PER_RUN
LOG=/var/log/claudeos/bug-payout-predictor.log
log(){ echo "$(date -Is) $*" | sudo tee -a "$LOG" >/dev/null; }

case "${1:-}" in
  sync|fetch)
    shift
    plat="${1:-all}"
    pages="${2:-$MAX_PAGES_PER_RUN}"
    if [ "$plat" = "all" ] || [ "$plat" = "hackerone" ]; then
      python3 /usr/local/lib/claudeos/h1_fetch.py --pages "$pages" && log "fetch h1 pages=$pages"
    fi
    if [ "$plat" = "all" ] || [ "$plat" = "bugcrowd" ]; then
      python3 /usr/local/lib/claudeos/bugcrowd_fetch.py --pages "$pages" && log "fetch bc pages=$pages"
    fi
    ;;
  predict)
    shift
    python3 /usr/local/lib/claudeos/predictor.py predict "$@"
    log "predict $*"
    ;;
  top-programs) shift; python3 /usr/local/lib/claudeos/predictor.py top-programs "$@" ;;
  top-vulns)    shift; python3 /usr/local/lib/claudeos/predictor.py top-vulns "$@" ;;
  list)         shift; python3 /usr/local/lib/claudeos/predictor.py list "$@" ;;
  stats)        python3 /usr/local/lib/claudeos/predictor.py stats ;;
  shell)
    exec sqlite3 "$DB_PATH"
    ;;
  normalize)
    shift
    echo "$*" | python3 /usr/local/lib/claudeos/vuln_normalizer.py
    ;;
  *)
    cat <<USAGE
bug-payout — bug bounty payout predictor (ClaudeOS)

  bug-payout sync [hackerone|bugcrowd|all] [pages]
  bug-payout predict --program <handle> --vuln <type> [--json]
  bug-payout top-programs [--n 20]
  bug-payout top-vulns [--program handle] [--n 20]
  bug-payout list [--program handle] [--vuln type] [--limit 20]
  bug-payout stats
  bug-payout shell          # drop into sqlite3 shell on the DB
  bug-payout normalize "SQL Injection (Blind)"

Vuln types: xss sqli idor ssrf rce xxe csrf open-redirect auth-bypass
            info-disclosure ssti lfi rfi path-traversal deserialization
            race prototype-pollution cache-poisoning request-smuggling
            subdomain-takeover oauth saml jwt business-logic dos
            hardcoded-secret s3-misconfig cors clickjacking other
USAGE
    ;;
esac
BASH
sudo chmod +x /usr/local/bin/bug-payout
```

---

## 8. Example Session

```bash
# 1. Initial pull — go back 20 pages on both platforms (~500 reports)
bug-payout sync all 20

# 2. How many records do we have?
bug-payout stats
# Total reports : 873
# Paid reports  : 612
# Programs      : 104
# Avg bounty    : $1,247
# Max bounty    : $50,000

# 3. Predict a payout for an RCE against Shopify
bug-payout predict --program shopify --vuln rce
# Program : shopify
# Vuln    : rce
# Confidence: high
# Basis   : 14 direct matches
# count   14
# min     2500
# p25     5000
# median  15000
# mean    18214.28
# p75     25000
# p90     35000
# max     50000
# Prediction range: $5000 – $25000 (median $15000)

# 4. Decide: "is XSS on GitLab worth 4 hours?"
bug-payout predict --program gitlab --vuln xss
# median ~$600  -> 4h x $150/h is the break-even

# 5. Which vuln classes pay best on HackerOne overall?
bug-payout top-vulns

# 6. Which programs pay best?
bug-payout top-programs --n 30

# 7. Raw rows for manual inspection
bug-payout list --program shopify --vuln rce --limit 10
```

---

## 9. Daily Auto-Sync

```bash
sudo tee /etc/cron.d/bug-payout-sync >/dev/null <<'CRON'
# pull newly-disclosed reports once a day at 04:17
17 4 * * * root /usr/local/bin/bug-payout sync all 10 >/var/log/claudeos/bug-payout-cron.log 2>&1
CRON
```

Or as a systemd timer:

```bash
sudo tee /etc/systemd/system/bug-payout-sync.service >/dev/null <<'UNIT'
[Unit]
Description=ClaudeOS bug-payout sync

[Service]
Type=oneshot
ExecStart=/usr/local/bin/bug-payout sync all 10
UNIT

sudo tee /etc/systemd/system/bug-payout-sync.timer >/dev/null <<'UNIT'
[Unit]
Description=Daily bug-payout sync

[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=30m

[Install]
WantedBy=timers.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable --now bug-payout-sync.timer
```

---

## 10. Integration with Other ClaudeOS Agents

### Chain with `vuln-tracker`

When a hunter files a finding in `vuln-tracker`, auto-attach an expected-payout estimate:

```bash
# inside vuln-tracker hook
VT_PROGRAM="shopify"
VT_VULN="idor"
EST=$(bug-payout predict --program "$VT_PROGRAM" --vuln "$VT_VULN" --json)
MED=$(echo "$EST" | jq '.stats.median')
sqlite3 /var/lib/claudeos/vuln-tracker/findings.db \
  "UPDATE findings SET expected_payout=$MED WHERE id=$VT_FINDING_ID"
```

### Chain with `dupe-checker`

```bash
# Prioritize: high-predicted-payout + low-dupe-probability findings get worked first
bug-payout predict --program $P --vuln $V --json > /tmp/pred.json
dupe-checker score --program $P --title "$T" > /tmp/dupe.json
python3 -c "
import json
p=json.load(open('/tmp/pred.json')); d=json.load(open('/tmp/dupe.json'))
score = (p['stats']['median'] or 0) * (1 - d['dupe_probability'])
print(f'priority score: {score:.0f}')
"
```

### Chain with `report-writer`

Use the predicted range as the "Severity and Business Impact" section of the generated report.

---

## 11. Troubleshooting

| Symptom | Fix |
|---|---|
| `fetch h1` returns 0 reports | H1 changed GraphQL schema — grab the live query from browser devtools and update `QUERY` |
| `bugcrowd_fetch: KeyError` | Bugcrowd response shape changed — inspect `data` dict and adjust keys |
| `tabulate: not found` | `python3 -m pip install --user tabulate` |
| SQLite `database is locked` | Another process is writing; retry. For heavy use switch to WAL: `PRAGMA journal_mode=WAL;` |
| Prediction says `confidence: none` | Not enough data. Run `bug-payout sync all 50` to pull more history |
| Payout values look like strings not numbers | Re-ingest — old rows stored as text. `DELETE FROM reports WHERE platform='bugcrowd'; bug-payout sync bugcrowd 50` |

---

## 12. Data Quality Notes

- HackerOne sometimes redacts bounty amounts (`bounty_amount = null`) — those rows land as `bounty_usd = 0` and are excluded from paid stats
- "Program" handles differ between platforms — `shopify` on H1 vs `shopify-bbp` on Bugcrowd; normalize manually if needed
- Severity is self-reported by the program — not a reliable payout predictor by itself; use `vuln_type + program` instead
- Historical payouts trail inflation — prefer recent windows: `bug-payout list --limit 200 | awk -F'\t' '$5 > "2025-01-01"'`

---

## 13. Files Created by This Agent

```
/etc/claudeos/bug-payout-predictor.conf        # config
/var/lib/claudeos/payout-predictor/reports.db  # SQLite cache
/usr/local/lib/claudeos/vuln_normalizer.py     # vuln-type canonicalizer
/usr/local/lib/claudeos/h1_fetch.py            # HackerOne fetcher
/usr/local/lib/claudeos/bugcrowd_fetch.py      # Bugcrowd fetcher
/usr/local/lib/claudeos/predictor.py           # query + stats engine
/usr/local/bin/bug-payout                      # unified CLI
/var/log/claudeos/bug-payout-predictor.log     # audit log
/etc/cron.d/bug-payout-sync                    # daily sync
/etc/systemd/system/bug-payout-sync.*          # systemd timer variant
```
