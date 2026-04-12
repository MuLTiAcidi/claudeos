# Ghost Recon Agent
# Zero-Packet Passive Reconnaissance
# Never sends a single packet to the target

## Purpose
Gather maximum intelligence about a target using ONLY external/third-party sources.
Zero direct contact with the target infrastructure. Every query goes to a public
database, search engine, or archive service.

## Usage
```
ghost-recon <target_domain> [--output-dir ./recon] [--deep] [--api-keys keys.json]
```

## Environment Requirements
- curl, jq, python3
- Optional: shodan CLI (`pip install shodan`), subfinder, amass (passive mode only)
- API keys (optional but recommended): Shodan, SecurityTrails, VirusTotal, Censys

## API Keys Configuration
```json
{
  "shodan": "YOUR_SHODAN_KEY",
  "securitytrails": "YOUR_ST_KEY",
  "virustotal": "YOUR_VT_KEY",
  "censys_id": "YOUR_CENSYS_ID",
  "censys_secret": "YOUR_CENSYS_SECRET",
  "github_token": "YOUR_GITHUB_PAT"
}
```

## Source 1: Certificate Transparency (crt.sh)

### Find all subdomains from CT logs
```bash
TARGET="target.com"
curl -s "https://crt.sh/?q=%25.${TARGET}&output=json" | \
  jq -r '.[].name_value' | \
  sort -u | \
  sed 's/\*\.//g' | \
  sort -u > crtsh_subdomains.txt
echo "[+] Found $(wc -l < crtsh_subdomains.txt) unique subdomains from crt.sh"
```

### Extract organization info from certificates
```bash
curl -s "https://crt.sh/?q=%25.${TARGET}&output=json" | \
  jq -r '.[].issuer_name' | sort | uniq -c | sort -rn | head -20
```

### Find recently issued certificates (last 30 days)
```bash
curl -s "https://crt.sh/?q=%25.${TARGET}&output=json" | \
  jq -r '.[] | select(.not_before > "2026-03-10") | "\(.not_before) \(.name_value)"' | sort -u
```

## Source 2: Wayback Machine CDX API

### Discover historical URLs and endpoints
```bash
curl -s "https://web.archive.org/cdx/search/cdx?url=*.${TARGET}/*&output=json&fl=original,statuscode,mimetype&collapse=urlkey&limit=10000" | \
  python3 -c "
import json, sys
data = json.load(sys.stdin)
for row in data[1:]:  # skip header
    print(row[0])
" | sort -u > wayback_urls.txt
```

### Extract interesting endpoints (APIs, admin, config)
```bash
cat wayback_urls.txt | grep -iE "(api|admin|config|env|backup|debug|swagger|graphql|internal|staging|dev|test)" | sort -u > interesting_urls.txt
```

### Find old JavaScript files (may contain hardcoded secrets)
```bash
cat wayback_urls.txt | grep -iE "\.js(\?|$)" | sort -u > js_files.txt
# Fetch archived versions of JS files
while read url; do
  ts=$(curl -s "https://archive.org/wayback/available?url=$url" | jq -r '.archived_snapshots.closest.timestamp // empty')
  if [ -n "$ts" ]; then
    echo "https://web.archive.org/web/${ts}id_/${url}"
  fi
done < js_files.txt > js_archive_urls.txt
```

### Find removed/hidden pages
```bash
curl -s "https://web.archive.org/cdx/search/cdx?url=${TARGET}/*&output=json&fl=original,statuscode&filter=statuscode:200&collapse=urlkey&limit=5000" | \
  python3 -c "
import json, sys
data = json.load(sys.stdin)
for row in data[1:]:
    print(row[0])
" | sort -u > wayback_200_urls.txt
```

## Source 3: GitHub Code Search

### Search for leaked credentials, API keys, config files
```bash
# Requires GITHUB_TOKEN for authenticated search (higher rate limits)
GITHUB_TOKEN="your_token"

# Search patterns
PATTERNS=(
  "\"${TARGET}\" password"
  "\"${TARGET}\" api_key"
  "\"${TARGET}\" secret"
  "\"${TARGET}\" token"
  "\"${TARGET}\" AWS_ACCESS"
  "\"${TARGET}\" authorization"
  "\"${TARGET}\" jdbc:"
  "\"${TARGET}\" mongodb://"
  "\"${TARGET}\" BEGIN RSA"
  "\"${TARGET}\" smtp"
)

for pattern in "${PATTERNS[@]}"; do
  echo "=== Searching: $pattern ==="
  curl -s -H "Authorization: token $GITHUB_TOKEN" \
    "https://api.github.com/search/code?q=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$pattern'))")&per_page=10" | \
    jq -r '.items[]? | "\(.repository.full_name): \(.html_url)"'
  sleep 2  # Rate limiting
done
```

### Search for internal documentation referencing the target
```bash
curl -s -H "Authorization: token $GITHUB_TOKEN" \
  "https://api.github.com/search/code?q=%22${TARGET}%22+filename:README&per_page=20" | \
  jq -r '.items[]? | "\(.repository.full_name): \(.path)"'
```

### Search for exposed .env files
```bash
curl -s -H "Authorization: token $GITHUB_TOKEN" \
  "https://api.github.com/search/code?q=%22${TARGET}%22+filename:.env&per_page=10" | \
  jq -r '.items[]? | .html_url'
```

## Source 4: Shodan CLI

### Query Shodan for the target's infrastructure
```bash
# By hostname
shodan search "hostname:${TARGET}" --fields ip_str,port,org,product,version --limit 100

# By SSL certificate
shodan search "ssl.cert.subject.cn:${TARGET}" --fields ip_str,port,org --limit 100

# By favicon hash (find related infrastructure)
shodan search "http.favicon.hash:HASH_HERE" --fields ip_str,port,hostname --limit 100

# By HTTP title
shodan search "http.title:\"${TARGET}\"" --fields ip_str,port,org --limit 50
```

### Get detailed host info without touching target
```bash
# Look up known IPs from DNS (resolved externally)
shodan host $(dig +short ${TARGET} @8.8.8.8 | head -1)
```

### Find related infrastructure via organization
```bash
shodan search "org:\"Target Corp\"" --fields ip_str,port,hostname,product --limit 200
```

## Source 5: SecurityTrails

### Historical DNS records
```bash
ST_KEY="your_key"

# Current DNS
curl -s -H "APIKEY: $ST_KEY" "https://api.securitytrails.com/v1/domain/${TARGET}" | jq .

# Subdomains
curl -s -H "APIKEY: $ST_KEY" "https://api.securitytrails.com/v1/domain/${TARGET}/subdomains" | \
  jq -r '.subdomains[]' | sed "s/$/.${TARGET}/"

# DNS history (A records)
curl -s -H "APIKEY: $ST_KEY" "https://api.securitytrails.com/v1/history/${TARGET}/dns/a" | \
  jq -r '.records[] | "\(.first_seen) - \(.last_seen): \(.values[].ip)"'

# Associated domains (same IP or nameserver)
curl -s -H "APIKEY: $ST_KEY" "https://api.securitytrails.com/v1/domain/${TARGET}/associated" | \
  jq -r '.records[].hostname'
```

## Source 6: DNS History and Passive DNS

### DNSDumpster data
```bash
# Via API (if available) or scraping
curl -s "https://api.hackertarget.com/hostsearch/?q=${TARGET}" | \
  cut -d',' -f1 | sort -u > dns_subdomains.txt
```

### VirusTotal passive DNS
```bash
VT_KEY="your_key"
curl -s -H "x-apikey: $VT_KEY" "https://www.virustotal.com/api/v3/domains/${TARGET}/subdomains?limit=40" | \
  jq -r '.data[].id'
```

### Reverse IP lookup (find co-hosted domains)
```bash
TARGET_IP=$(dig +short ${TARGET} @8.8.8.8 | head -1)
curl -s "https://api.hackertarget.com/reverseiplookup/?q=${TARGET_IP}"
```

## Source 7: Google Dorking Patterns

### Automated Google dorks (use responsibly, respect rate limits)
```bash
DORKS=(
  "site:${TARGET} inurl:admin"
  "site:${TARGET} intitle:\"index of\""
  "site:${TARGET} ext:sql OR ext:db OR ext:log OR ext:bak"
  "site:${TARGET} inurl:api"
  "site:${TARGET} inurl:swagger OR inurl:openapi"
  "site:${TARGET} filetype:pdf confidential"
  "site:${TARGET} inurl:wp-content OR inurl:wp-admin"
  "site:${TARGET} inurl:phpinfo OR inurl:debug"
  "site:${TARGET} intitle:\"login\" OR intitle:\"sign in\""
  "\"${TARGET}\" site:pastebin.com OR site:paste.ee"
  "\"${TARGET}\" site:trello.com"
  "\"${TARGET}\" site:notion.so"
  "\"${TARGET}\" site:docs.google.com"
  "\"${TARGET}\" inurl:jira OR inurl:confluence"
  "\"${TARGET}\" filetype:env OR filetype:yml password"
  "site:${TARGET} inurl:graphql OR inurl:graphiql"
  "site:${TARGET} inurl:callback OR inurl:redirect OR inurl:return"
  "site:${TARGET} inurl:upload OR inurl:file"
  "site:*.${TARGET} -www"
)

for dork in "${DORKS[@]}"; do
  echo "=== $dork ==="
  # Output the dork for manual use or use a search API
  echo "https://www.google.com/search?q=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$dork'))")"
done
```

## Source 8: S3 Bucket and Cloud Storage Patterns

### Generate candidate bucket names
```bash
COMPANY=$(echo "$TARGET" | sed 's/\..*//')
PATTERNS=(
  "$COMPANY"
  "${COMPANY}-dev"
  "${COMPANY}-staging"
  "${COMPANY}-prod"
  "${COMPANY}-backup"
  "${COMPANY}-assets"
  "${COMPANY}-uploads"
  "${COMPANY}-media"
  "${COMPANY}-static"
  "${COMPANY}-data"
  "${COMPANY}-logs"
  "${COMPANY}-internal"
  "${COMPANY}-test"
  "${COMPANY}-api"
  "${COMPANY}-cdn"
  "${COMPANY}-public"
  "${COMPANY}-private"
  "${COMPANY}-db-backups"
  "backup-${COMPANY}"
  "dev-${COMPANY}"
  "staging-${COMPANY}"
)

# Check via DNS (passive - no direct bucket access)
for bucket in "${PATTERNS[@]}"; do
  result=$(dig +short "${bucket}.s3.amazonaws.com" @8.8.8.8 2>/dev/null)
  if [ -n "$result" ]; then
    echo "[EXISTS] ${bucket}.s3.amazonaws.com -> $result"
  fi
done

# Also check Azure and GCP
for bucket in "${PATTERNS[@]}"; do
  # Azure
  az_result=$(dig +short "${bucket}.blob.core.windows.net" @8.8.8.8 2>/dev/null)
  [ -n "$az_result" ] && echo "[AZURE] ${bucket}.blob.core.windows.net -> $az_result"

  # GCP
  gcp_result=$(dig +short "${bucket}.storage.googleapis.com" @8.8.8.8 2>/dev/null)
  [ -n "$gcp_result" ] && echo "[GCP] ${bucket}.storage.googleapis.com -> $gcp_result"
done
```

## Source 9: Favicon Hashing

### Calculate favicon hash to find related infrastructure on Shodan
```bash
# Fetch favicon from Wayback Machine (passive!)
FAVICON_URL="https://web.archive.org/web/2026/${TARGET}/favicon.ico"

python3 -c "
import mmh3
import codecs
import requests
import sys

# Get favicon from archive (not from target directly)
url = sys.argv[1]
try:
    resp = requests.get(url, timeout=10)
    if resp.status_code == 200:
        favicon = codecs.encode(resp.content, 'base64')
        hash_val = mmh3.hash(favicon)
        print(f'Favicon hash: {hash_val}')
        print(f'Shodan query: http.favicon.hash:{hash_val}')
    else:
        print('Favicon not found in archive')
except Exception as e:
    print(f'Error: {e}')
" "$FAVICON_URL"
```

## Full Orchestration Script

```python
#!/usr/bin/env python3
"""
ghost_recon.py - Zero-Packet Passive Reconnaissance
Usage: python3 ghost_recon.py target.com [--output-dir ./recon] [--deep]
"""

import argparse
import json
import os
import subprocess
import sys
import time
from urllib.parse import quote
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

try:
    import requests
except ImportError:
    print("[!] pip install requests")
    sys.exit(1)


class GhostRecon:
    def __init__(self, target, output_dir="./recon", api_keys=None, deep=False):
        self.target = target
        self.company = target.split(".")[0]
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.api_keys = api_keys or {}
        self.deep = deep
        self.findings = {
            "target": target,
            "timestamp": datetime.utcnow().isoformat(),
            "subdomains": set(),
            "urls": set(),
            "ips": set(),
            "technologies": [],
            "cloud_assets": [],
            "leaked_secrets": [],
            "interesting_endpoints": [],
            "dns_history": [],
            "related_domains": [],
        }

    def run_all(self):
        """Run all passive recon sources."""
        print(f"\n{'='*60}")
        print(f"  Ghost Recon: {self.target}")
        print(f"  Mode: {'Deep' if self.deep else 'Standard'}")
        print(f"  Timestamp: {self.findings['timestamp']}")
        print(f"{'='*60}\n")

        sources = [
            ("crt.sh", self.source_crtsh),
            ("Wayback Machine", self.source_wayback),
            ("GitHub Search", self.source_github),
            ("Shodan", self.source_shodan),
            ("SecurityTrails", self.source_securitytrails),
            ("HackerTarget DNS", self.source_hackertarget),
            ("VirusTotal", self.source_virustotal),
            ("S3 Bucket Enum", self.source_s3_enum),
        ]

        for name, func in sources:
            print(f"\n[*] Source: {name}")
            try:
                func()
                print(f"    [+] Complete")
            except Exception as e:
                print(f"    [!] Error: {e}")

        self.save_results()
        self.print_summary()

    def source_crtsh(self):
        resp = requests.get(
            f"https://crt.sh/?q=%25.{self.target}&output=json",
            timeout=30,
        )
        if resp.status_code == 200:
            for entry in resp.json():
                names = entry.get("name_value", "").split("\n")
                for name in names:
                    name = name.strip().replace("*.", "")
                    if name:
                        self.findings["subdomains"].add(name)
            print(f"    Found {len(self.findings['subdomains'])} subdomains")

    def source_wayback(self):
        resp = requests.get(
            f"https://web.archive.org/cdx/search/cdx?url=*.{self.target}/*&output=json&fl=original,statuscode,mimetype&collapse=urlkey&limit=10000",
            timeout=60,
        )
        if resp.status_code == 200:
            data = resp.json()
            for row in data[1:]:
                self.findings["urls"].add(row[0])
            interesting = [
                u for u in self.findings["urls"]
                if any(kw in u.lower() for kw in [
                    "api", "admin", "config", "env", "debug",
                    "swagger", "graphql", "internal", "backup",
                    "phpinfo", ".sql", ".bak", ".log",
                ])
            ]
            self.findings["interesting_endpoints"].extend(interesting)
            print(f"    Found {len(self.findings['urls'])} URLs, {len(interesting)} interesting")

    def source_github(self):
        token = self.api_keys.get("github_token")
        if not token:
            print("    [!] No GitHub token, skipping")
            return
        headers = {"Authorization": f"token {token}"}
        search_terms = [
            f'"{self.target}" password',
            f'"{self.target}" api_key',
            f'"{self.target}" secret',
            f'"{self.target}" token',
        ]
        for term in search_terms:
            resp = requests.get(
                f"https://api.github.com/search/code?q={quote(term)}&per_page=5",
                headers=headers,
                timeout=15,
            )
            if resp.status_code == 200:
                for item in resp.json().get("items", []):
                    self.findings["leaked_secrets"].append({
                        "repo": item["repository"]["full_name"],
                        "file": item["path"],
                        "url": item["html_url"],
                        "search_term": term,
                    })
            time.sleep(2)
        print(f"    Found {len(self.findings['leaked_secrets'])} potential leaks")

    def source_shodan(self):
        key = self.api_keys.get("shodan")
        if not key:
            print("    [!] No Shodan key, skipping")
            return
        resp = requests.get(
            f"https://api.shodan.io/dns/domain/{self.target}?key={key}",
            timeout=15,
        )
        if resp.status_code == 200:
            data = resp.json()
            for sub in data.get("subdomains", []):
                self.findings["subdomains"].add(f"{sub}.{self.target}")
            for record in data.get("data", []):
                if record.get("type") == "A":
                    self.findings["ips"].add(record.get("value", ""))

    def source_securitytrails(self):
        key = self.api_keys.get("securitytrails")
        if not key:
            print("    [!] No SecurityTrails key, skipping")
            return
        headers = {"APIKEY": key}
        resp = requests.get(
            f"https://api.securitytrails.com/v1/domain/{self.target}/subdomains",
            headers=headers,
            timeout=15,
        )
        if resp.status_code == 200:
            for sub in resp.json().get("subdomains", []):
                self.findings["subdomains"].add(f"{sub}.{self.target}")

        # DNS history
        resp = requests.get(
            f"https://api.securitytrails.com/v1/history/{self.target}/dns/a",
            headers=headers,
            timeout=15,
        )
        if resp.status_code == 200:
            for rec in resp.json().get("records", []):
                for val in rec.get("values", []):
                    self.findings["dns_history"].append({
                        "ip": val.get("ip", ""),
                        "first_seen": rec.get("first_seen", ""),
                        "last_seen": rec.get("last_seen", ""),
                    })

    def source_hackertarget(self):
        resp = requests.get(
            f"https://api.hackertarget.com/hostsearch/?q={self.target}",
            timeout=15,
        )
        if resp.status_code == 200 and "error" not in resp.text.lower():
            for line in resp.text.strip().split("\n"):
                parts = line.split(",")
                if len(parts) >= 2:
                    self.findings["subdomains"].add(parts[0])
                    self.findings["ips"].add(parts[1])

    def source_virustotal(self):
        key = self.api_keys.get("virustotal")
        if not key:
            print("    [!] No VirusTotal key, skipping")
            return
        headers = {"x-apikey": key}
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{self.target}/subdomains?limit=40",
            headers=headers,
            timeout=15,
        )
        if resp.status_code == 200:
            for item in resp.json().get("data", []):
                self.findings["subdomains"].add(item["id"])

    def source_s3_enum(self):
        suffixes = [
            "", "-dev", "-staging", "-prod", "-backup", "-assets",
            "-uploads", "-media", "-static", "-data", "-logs",
            "-internal", "-test", "-api", "-cdn", "-public",
        ]
        for suffix in suffixes:
            bucket = f"{self.company}{suffix}"
            try:
                result = subprocess.run(
                    ["dig", "+short", f"{bucket}.s3.amazonaws.com", "@8.8.8.8"],
                    capture_output=True, text=True, timeout=5,
                )
                if result.stdout.strip():
                    self.findings["cloud_assets"].append({
                        "type": "s3",
                        "name": bucket,
                        "resolved": True,
                    })
            except Exception:
                pass
        print(f"    Found {len(self.findings['cloud_assets'])} cloud assets")

    def save_results(self):
        output = {
            **self.findings,
            "subdomains": sorted(self.findings["subdomains"]),
            "urls": sorted(list(self.findings["urls"])[:500]),
            "ips": sorted(self.findings["ips"]),
        }
        outfile = self.output_dir / f"{self.target}_recon.json"
        with open(outfile, "w") as f:
            json.dump(output, f, indent=2)
        print(f"\n[+] Results saved to {outfile}")

        # Also save subdomains as plain text
        subfile = self.output_dir / f"{self.target}_subdomains.txt"
        with open(subfile, "w") as f:
            f.write("\n".join(sorted(self.findings["subdomains"])))

    def print_summary(self):
        print(f"\n{'='*60}")
        print(f"  RECON SUMMARY: {self.target}")
        print(f"{'='*60}")
        print(f"  Subdomains:          {len(self.findings['subdomains'])}")
        print(f"  Historical URLs:     {len(self.findings['urls'])}")
        print(f"  Unique IPs:          {len(self.findings['ips'])}")
        print(f"  Interesting URLs:    {len(self.findings['interesting_endpoints'])}")
        print(f"  Potential leaks:     {len(self.findings['leaked_secrets'])}")
        print(f"  Cloud assets:        {len(self.findings['cloud_assets'])}")
        print(f"  DNS history records: {len(self.findings['dns_history'])}")
        print(f"{'='*60}")


def main():
    parser = argparse.ArgumentParser(description="Zero-Packet Passive Recon")
    parser.add_argument("target", help="Target domain")
    parser.add_argument("--output-dir", default="./recon", help="Output directory")
    parser.add_argument("--api-keys", help="JSON file with API keys")
    parser.add_argument("--deep", action="store_true", help="Deep mode (more queries)")
    args = parser.parse_args()

    api_keys = {}
    if args.api_keys:
        with open(args.api_keys) as f:
            api_keys = json.load(f)

    recon = GhostRecon(args.target, args.output_dir, api_keys, args.deep)
    recon.run_all()


if __name__ == "__main__":
    main()
```

## Integration Points

### Feed subdomains to cors-chain
```bash
python3 ghost_recon.py target.com --output-dir ./recon
cat ./recon/target.com_subdomains.txt | httpx -silent | while read url; do
  python3 ../cors-chain/cors_chain.py "$url/api/v1/user" --skip-recon
done
```

### Feed to spray-scanner
```bash
python3 ghost_recon.py target.com --output-dir ./recon
cp ./recon/target.com_subdomains.txt ../spray-scanner/targets.txt
```

### Feed to vuln-predictor
```bash
jq -r '.technologies[]' ./recon/target.com_recon.json | \
  xargs -I{} python3 ../vuln-predictor/predict.py --tech "{}"
```
