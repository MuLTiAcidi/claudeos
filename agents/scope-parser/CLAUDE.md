# Scope Parser Agent
# Bug Bounty Program Scope Extractor
# Parse scope from HackerOne and Bugcrowd into structured JSON

## Purpose
Extract bug bounty program scope information from HackerOne and Bugcrowd.
Outputs structured JSON consumed by other agents (spray-scanner, bounty-arbitrage).
Includes: in-scope domains, out-of-scope exclusions, bounty ranges, program rules.

## Usage
```
scope-parser <program_handle> [--platform h1|bugcrowd|auto] [--output scope.json]
scope-parser --list-programs [--min-bounty 1000] [--managed-only]
scope-parser --bulk programs.txt --output-dir ./scopes/
```

## Environment Requirements
- Python 3.10+, requests, beautifulsoup4
- Optional: h1-cli, jq

## HackerOne API Access

### Public program data via GraphQL
```bash
# HackerOne GraphQL endpoint for public data
H1_GRAPHQL="https://hackerone.com/graphql"

# Fetch program scope
curl -s -X POST "$H1_GRAPHQL" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "query { team(handle: \"PROGRAM_HANDLE\") { name handle url offers_bounties allows_bounty_splitting structured_scopes { edges { node { asset_type asset_identifier instruction eligible_for_bounty eligible_for_submission max_severity } } } } }"
  }' | jq .
```

### Fetch program policy
```bash
curl -s -X POST "$H1_GRAPHQL" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "query { team(handle: \"PROGRAM_HANDLE\") { policy submission_state started_accepting_at triage_active response_efficiency_percentage } }"
  }' | jq .
```

### Fetch bounty table
```bash
curl -s -X POST "$H1_GRAPHQL" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "query { team(handle: \"PROGRAM_HANDLE\") { bounty_table { bounty_table_rows { low medium high critical } } } }"
  }' | jq .
```

### Fetch recent hacktivity (public disclosures)
```bash
curl -s -X POST "$H1_GRAPHQL" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "query { hacktivity_items(first: 25, filter_by: { team: { handle: { _eq: \"PROGRAM_HANDLE\" } } }) { edges { node { ... on HacktivityItemInterface { id reporter { username } severity_rating total_awarded_amount vulnerability_information_html disclosed_at } } } } }"
  }' | jq .
```

## Bugcrowd Public Data

### Scrape program page
```bash
# Bugcrowd program pages are server-rendered
curl -s "https://bugcrowd.com/PROGRAM_HANDLE" \
  -H "User-Agent: Mozilla/5.0" | \
  python3 -c "
from bs4 import BeautifulSoup
import sys, json

html = sys.stdin.read()
soup = BeautifulSoup(html, 'html.parser')

# Extract scope table
scope_items = []
for row in soup.select('.bc-panel__main table tr'):
    cells = row.find_all('td')
    if len(cells) >= 2:
        scope_items.append({
            'target': cells[0].get_text(strip=True),
            'type': cells[1].get_text(strip=True) if len(cells) > 1 else '',
        })

print(json.dumps(scope_items, indent=2))
"
```

### Bugcrowd API (if available)
```bash
# Some program data is available via API
curl -s "https://bugcrowd.com/programs/organizations/PROGRAM_HANDLE.json" \
  -H "Accept: application/json" \
  -H "User-Agent: Mozilla/5.0" | jq .
```

## Full Implementation

```python
#!/usr/bin/env python3
"""
scope_parser.py - Bug Bounty Scope Parser
Usage: python3 scope_parser.py <program_handle> [--platform h1|bugcrowd]
"""

import argparse
import json
import re
import sys
import time
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict
from datetime import datetime

try:
    import requests
except ImportError:
    print("[!] pip install requests")
    sys.exit(1)

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False


@dataclass
class ScopeTarget:
    asset_identifier: str
    asset_type: str  # domain, wildcard, url, ios, android, api, other
    eligible_for_bounty: bool = True
    eligible_for_submission: bool = True
    max_severity: str = "critical"
    instruction: str = ""
    is_wildcard: bool = False


@dataclass
class BountyTable:
    none: float = 0
    low: float = 0
    medium: float = 0
    high: float = 0
    critical: float = 0


@dataclass
class ProgramScope:
    handle: str
    platform: str
    name: str = ""
    url: str = ""
    in_scope: List[ScopeTarget] = field(default_factory=list)
    out_of_scope: List[ScopeTarget] = field(default_factory=list)
    bounty_range: Optional[BountyTable] = None
    offers_bounties: bool = False
    managed: bool = False
    policy: str = ""
    response_time_days: float = 0
    domains: List[str] = field(default_factory=list)  # Flat list of in-scope domains
    wildcard_domains: List[str] = field(default_factory=list)
    exclusions: List[str] = field(default_factory=list)
    rules: List[str] = field(default_factory=list)
    timestamp: str = ""

    def extract_domains(self):
        """Extract flat domain lists from scope targets."""
        for target in self.in_scope:
            identifier = target.asset_identifier.strip()
            if target.asset_type in ("URL", "DOMAIN", "WILDCARD"):
                # Clean up the identifier
                clean = re.sub(r'^https?://', '', identifier)
                clean = clean.split('/')[0]  # Remove paths
                clean = clean.split(':')[0]  # Remove ports

                if clean.startswith("*."):
                    self.wildcard_domains.append(clean)
                    self.domains.append(clean[2:])  # Add base domain too
                else:
                    self.domains.append(clean)

        for target in self.out_of_scope:
            identifier = target.asset_identifier.strip()
            clean = re.sub(r'^https?://', '', identifier)
            clean = clean.split('/')[0]
            self.exclusions.append(clean)

        self.domains = sorted(set(self.domains))
        self.wildcard_domains = sorted(set(self.wildcard_domains))
        self.exclusions = sorted(set(self.exclusions))


class HackerOneParser:
    GRAPHQL_URL = "https://hackerone.com/graphql"

    def __init__(self, session=None):
        self.session = session or requests.Session()
        self.session.headers.update({
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        })

    def fetch_program(self, handle: str) -> ProgramScope:
        """Fetch full program scope from HackerOne."""
        scope = ProgramScope(
            handle=handle,
            platform="hackerone",
            url=f"https://hackerone.com/{handle}",
            timestamp=datetime.utcnow().isoformat(),
        )

        # Fetch scope and basic info
        query = """
        query TeamScope($handle: String!) {
          team(handle: $handle) {
            name
            handle
            url
            offers_bounties
            allows_bounty_splitting
            state
            triage_active
            submission_state
            started_accepting_at
            response_efficiency_percentage
            policy
            structured_scopes(first: 100) {
              edges {
                node {
                  asset_type
                  asset_identifier
                  eligible_for_bounty
                  eligible_for_submission
                  max_severity
                  instruction
                }
              }
            }
          }
        }
        """
        try:
            resp = self.session.post(self.GRAPHQL_URL, json={
                "query": query,
                "variables": {"handle": handle},
            }, timeout=15)

            if resp.status_code != 200:
                print(f"[!] H1 API returned {resp.status_code}")
                return scope

            data = resp.json()
            team = data.get("data", {}).get("team")
            if not team:
                print(f"[!] Program '{handle}' not found on HackerOne")
                return scope

            scope.name = team.get("name", "")
            scope.offers_bounties = team.get("offers_bounties", False)
            scope.policy = team.get("policy", "")

            # Parse response time
            efficiency = team.get("response_efficiency_percentage")
            if efficiency:
                scope.response_time_days = round(100 / max(efficiency, 1), 1)

            # Parse structured scopes
            scopes = team.get("structured_scopes", {}).get("edges", [])
            for edge in scopes:
                node = edge.get("node", {})
                target = ScopeTarget(
                    asset_identifier=node.get("asset_identifier", ""),
                    asset_type=node.get("asset_type", "OTHER"),
                    eligible_for_bounty=node.get("eligible_for_bounty", False),
                    eligible_for_submission=node.get("eligible_for_submission", True),
                    max_severity=node.get("max_severity", ""),
                    instruction=node.get("instruction", ""),
                    is_wildcard=node.get("asset_identifier", "").startswith("*."),
                )
                if target.eligible_for_submission:
                    scope.in_scope.append(target)
                else:
                    scope.out_of_scope.append(target)

        except Exception as e:
            print(f"[!] Error fetching H1 data: {e}")

        # Fetch bounty table
        try:
            bounty_query = """
            query BountyTable($handle: String!) {
              team(handle: $handle) {
                bounty_table {
                  bounty_table_rows {
                    low
                    medium
                    high
                    critical
                  }
                }
              }
            }
            """
            resp = self.session.post(self.GRAPHQL_URL, json={
                "query": bounty_query,
                "variables": {"handle": handle},
            }, timeout=15)

            if resp.status_code == 200:
                data = resp.json()
                rows = (data.get("data", {}).get("team", {})
                        .get("bounty_table", {}).get("bounty_table_rows", []))
                if rows:
                    # Take the highest bounty row
                    best = rows[0]
                    scope.bounty_range = BountyTable(
                        low=float(best.get("low", 0) or 0),
                        medium=float(best.get("medium", 0) or 0),
                        high=float(best.get("high", 0) or 0),
                        critical=float(best.get("critical", 0) or 0),
                    )
        except Exception as e:
            print(f"[!] Error fetching bounty table: {e}")

        # Extract rules from policy
        if scope.policy:
            scope.rules = extract_rules(scope.policy)

        scope.extract_domains()
        return scope


class BugcrowdParser:
    BASE_URL = "https://bugcrowd.com"

    def __init__(self, session=None):
        self.session = session or requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        })

    def fetch_program(self, handle: str) -> ProgramScope:
        """Fetch program scope from Bugcrowd."""
        scope = ProgramScope(
            handle=handle,
            platform="bugcrowd",
            url=f"https://bugcrowd.com/{handle}",
            timestamp=datetime.utcnow().isoformat(),
        )

        if not HAS_BS4:
            print("[!] beautifulsoup4 required for Bugcrowd parsing: pip install beautifulsoup4")
            return scope

        try:
            resp = self.session.get(f"{self.BASE_URL}/{handle}", timeout=15)
            if resp.status_code != 200:
                print(f"[!] Bugcrowd returned {resp.status_code}")
                return scope

            soup = BeautifulSoup(resp.text, "html.parser")

            # Extract program name
            title = soup.find("h1")
            if title:
                scope.name = title.get_text(strip=True)

            # Extract scope from target tables
            scope_sections = soup.find_all("div", class_=re.compile(r"scope|target"))
            for section in scope_sections:
                rows = section.find_all("tr")
                for row in rows:
                    cells = row.find_all("td")
                    if len(cells) >= 2:
                        identifier = cells[0].get_text(strip=True)
                        asset_type = cells[1].get_text(strip=True) if len(cells) > 1 else "OTHER"
                        target = ScopeTarget(
                            asset_identifier=identifier,
                            asset_type=asset_type.upper(),
                            eligible_for_bounty=True,
                        )
                        scope.in_scope.append(target)

            # Extract bounty range from page content
            bounty_text = resp.text
            bounty_match = re.search(r'\$[\d,]+\s*[-–]\s*\$[\d,]+', bounty_text)
            if bounty_match:
                parts = re.findall(r'\$([\d,]+)', bounty_match.group())
                if len(parts) >= 2:
                    scope.bounty_range = BountyTable(
                        low=float(parts[0].replace(",", "")),
                        critical=float(parts[1].replace(",", "")),
                    )
                    scope.offers_bounties = True

            # Extract policy/rules
            policy_section = soup.find(class_=re.compile(r"brief|description|policy"))
            if policy_section:
                scope.policy = policy_section.get_text()
                scope.rules = extract_rules(scope.policy)

        except Exception as e:
            print(f"[!] Error fetching Bugcrowd data: {e}")

        scope.extract_domains()
        return scope


def extract_rules(policy_text: str) -> List[str]:
    """Extract important rules from policy text."""
    rules = []
    keywords = [
        "do not", "must not", "forbidden", "prohibited",
        "out of scope", "excluded", "not eligible",
        "safe harbor", "disclosure", "report",
        "duplicate", "chain", "severity",
        "automated", "scanner", "rate limit",
    ]

    lines = policy_text.split("\n")
    for line in lines:
        line = line.strip()
        if any(kw in line.lower() for kw in keywords) and len(line) > 20:
            rules.append(line[:300])

    return rules[:20]  # Limit to 20 rules


def auto_detect_platform(handle: str) -> str:
    """Try to detect which platform a program is on."""
    try:
        resp = requests.head(f"https://hackerone.com/{handle}", timeout=5, allow_redirects=True)
        if resp.status_code == 200:
            return "h1"
    except Exception:
        pass

    try:
        resp = requests.head(f"https://bugcrowd.com/{handle}", timeout=5, allow_redirects=True)
        if resp.status_code == 200:
            return "bugcrowd"
    except Exception:
        pass

    return "unknown"


def format_output(scope: ProgramScope) -> dict:
    """Format scope for JSON output."""
    output = {
        "program": {
            "handle": scope.handle,
            "name": scope.name,
            "platform": scope.platform,
            "url": scope.url,
            "offers_bounties": scope.offers_bounties,
            "response_time_days": scope.response_time_days,
        },
        "scope": {
            "in_scope": [asdict(t) for t in scope.in_scope],
            "out_of_scope": [asdict(t) for t in scope.out_of_scope],
            "domains": scope.domains,
            "wildcard_domains": scope.wildcard_domains,
            "exclusions": scope.exclusions,
        },
        "bounty_range": asdict(scope.bounty_range) if scope.bounty_range else None,
        "rules": scope.rules,
        "timestamp": scope.timestamp,
    }
    return output


def main():
    parser = argparse.ArgumentParser(description="Bug Bounty Scope Parser")
    parser.add_argument("handle", nargs="?", help="Program handle")
    parser.add_argument("--platform", choices=["h1", "bugcrowd", "auto"], default="auto")
    parser.add_argument("--output", help="Output JSON file")
    parser.add_argument("--bulk", help="File with program handles (one per line)")
    parser.add_argument("--output-dir", default="./scopes", help="Output directory for bulk mode")
    parser.add_argument("--domains-only", action="store_true", help="Output only domain list")
    args = parser.parse_args()

    if args.bulk:
        import os
        os.makedirs(args.output_dir, exist_ok=True)
        with open(args.bulk) as f:
            handles = [line.strip() for line in f if line.strip() and not line.startswith("#")]

        for handle in handles:
            print(f"\n[*] Parsing: {handle}")
            platform = args.platform
            if platform == "auto":
                platform = auto_detect_platform(handle)
                print(f"    Platform: {platform}")

            if platform == "h1":
                scope = HackerOneParser().fetch_program(handle)
            elif platform == "bugcrowd":
                scope = BugcrowdParser().fetch_program(handle)
            else:
                print(f"    [!] Could not detect platform for {handle}")
                continue

            outfile = os.path.join(args.output_dir, f"{handle}.json")
            with open(outfile, "w") as f:
                json.dump(format_output(scope), f, indent=2)
            print(f"    [+] Saved to {outfile}")
            print(f"    Domains: {len(scope.domains)}, Wildcards: {len(scope.wildcard_domains)}")
            time.sleep(1)
        return

    if not args.handle:
        parser.print_help()
        return

    platform = args.platform
    if platform == "auto":
        print(f"[*] Auto-detecting platform for '{args.handle}'...")
        platform = auto_detect_platform(args.handle)
        print(f"[+] Detected: {platform}")

    if platform == "h1":
        scope = HackerOneParser().fetch_program(args.handle)
    elif platform == "bugcrowd":
        scope = BugcrowdParser().fetch_program(args.handle)
    else:
        print(f"[!] Could not detect platform. Use --platform h1 or --platform bugcrowd")
        return

    if args.domains_only:
        for d in scope.domains:
            print(d)
        for d in scope.wildcard_domains:
            print(d)
        return

    # Print summary
    print(f"\n{'='*60}")
    print(f"  Program: {scope.name} ({scope.handle})")
    print(f"  Platform: {scope.platform}")
    print(f"  Bounties: {'Yes' if scope.offers_bounties else 'No'}")
    if scope.bounty_range:
        print(f"  Bounty Range: ${scope.bounty_range.low} - ${scope.bounty_range.critical}")
    print(f"{'='*60}")
    print(f"\n  In-Scope Domains ({len(scope.domains)}):")
    for d in scope.domains[:20]:
        print(f"    - {d}")
    if scope.wildcard_domains:
        print(f"\n  Wildcard Domains ({len(scope.wildcard_domains)}):")
        for d in scope.wildcard_domains[:10]:
            print(f"    - {d}")
    if scope.exclusions:
        print(f"\n  Exclusions ({len(scope.exclusions)}):")
        for d in scope.exclusions[:10]:
            print(f"    - {d}")
    if scope.rules:
        print(f"\n  Key Rules:")
        for r in scope.rules[:5]:
            print(f"    - {r[:120]}")
    print()

    if args.output:
        with open(args.output, "w") as f:
            json.dump(format_output(scope), f, indent=2)
        print(f"[+] Saved to {args.output}")


if __name__ == "__main__":
    main()
```

## Quick Commands

### Get domains for spray-scanner
```bash
python3 scope_parser.py uber --platform h1 --domains-only > uber_domains.txt
python3 ../spray-scanner/spray_scanner.py uber_domains.txt --workers 20
```

### Bulk parse multiple programs
```bash
echo -e "uber\nshopify\ngithub\ntwitter" > programs.txt
python3 scope_parser.py --bulk programs.txt --output-dir ./scopes/
```

### Feed to bounty-arbitrage
```bash
# Parse scope and feed domains to arbitrage scanner
python3 scope_parser.py shopify --output shopify_scope.json
jq -r '.scope.domains[]' shopify_scope.json >> all_targets.txt
```

### Check bounty ranges across programs
```bash
for prog in uber shopify github airbnb; do
  python3 scope_parser.py "$prog" --platform h1 --output "/dev/stdout" 2>/dev/null | \
    jq -r "\"$prog: \(.bounty_range.critical // \"N/A\")\""
done
```

## Output Schema

The JSON output follows this schema for consumption by other agents:
```json
{
  "program": {
    "handle": "string",
    "name": "string",
    "platform": "h1|bugcrowd",
    "url": "string",
    "offers_bounties": true,
    "response_time_days": 5.0
  },
  "scope": {
    "in_scope": [{"asset_identifier": "*.example.com", "asset_type": "WILDCARD", ...}],
    "out_of_scope": [...],
    "domains": ["example.com", "api.example.com"],
    "wildcard_domains": ["*.example.com"],
    "exclusions": ["blog.example.com"]
  },
  "bounty_range": {"low": 100, "medium": 500, "high": 2000, "critical": 10000},
  "rules": ["Do not test production systems during business hours", ...],
  "timestamp": "2026-04-10T12:00:00"
}
```
