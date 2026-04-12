# Bounty Arbitrage Agent
# Find One Vulnerability Pattern Across Multiple Programs Simultaneously
# The CLEAR CORS pattern tested across 50 programs at once

## Purpose
Take a single vulnerability pattern (e.g., CORS wildcard, missing HSTS on auth endpoints,
open redirect) and test it across multiple bug bounty programs simultaneously.
Estimate bounty per program, generate draft reports for each hit.

## Usage
```
bounty-arbitrage <vuln_type> <programs_file> [--workers 20] [--output results.json]
bounty-arbitrage --list-patterns
bounty-arbitrage cors-wildcard programs.txt --min-bounty 500 --output cors_results.json
bounty-arbitrage missing-hsts-on-auth programs.txt --generate-reports ./reports/
```

## Environment Requirements
- Python 3.10+, requests
- scope-parser agent (for program scope data)
- Optional: cors-chain agent (for deep CORS testing)

## Supported Vulnerability Patterns

### Pattern: cors-wildcard
Test for CORS misconfigurations (origin reflection, null, subdomain wildcard).
```
Typical bounty: $500-$5000 per program
CVSS: 7.0-8.1 (with credentials)
Test time: ~5s per target
```

### Pattern: missing-hsts-on-auth
Authentication endpoints without Strict-Transport-Security.
```
Typical bounty: $100-$500 per program
CVSS: 4.0-5.0
Test time: ~2s per target
```

### Pattern: open-redirect
Unvalidated redirects on login/OAuth callback URLs.
```
Typical bounty: $150-$1000 per program
CVSS: 4.0-6.0
Test time: ~3s per target
```

### Pattern: graphql-introspection
GraphQL endpoints with introspection enabled in production.
```
Typical bounty: $200-$1500 per program
CVSS: 5.0-6.0
Test time: ~3s per target
```

### Pattern: exposed-env
.env, .git/HEAD, or other sensitive file exposure.
```
Typical bounty: $500-$5000 per program
CVSS: 7.0-9.0
Test time: ~5s per target
```

### Pattern: missing-csp-on-user-content
Pages rendering user content without Content-Security-Policy.
```
Typical bounty: $200-$1000 per program
CVSS: 4.0-6.0
Test time: ~3s per target
```

### Pattern: cookie-no-secure
Session cookies without Secure flag on HTTPS endpoints.
```
Typical bounty: $100-$500 per program
CVSS: 3.0-4.0
Test time: ~2s per target
```

### Pattern: subdomain-takeover
CNAME records pointing to unclaimed services.
```
Typical bounty: $500-$3000 per program
CVSS: 7.0-8.0
Test time: ~10s per target (DNS lookup + service check)
```

## Programs Input Format

```
# programs.txt
# Format: program_handle platform domain [bounty_range]
# platform: h1 = HackerOne, bc = Bugcrowd, custom = direct
uber h1 *.uber.com 500-10000
shopify h1 *.shopify.com 500-50000
github h1 *.github.com 617-30000
twitter h1 *.twitter.com 140-15000
airbnb h1 *.airbnb.com 500-15000
paypal h1 *.paypal.com 50-10000
dropbox h1 *.dropbox.com 216-10000
slack h1 *.slack.com 200-5000
gitlab h1 *.gitlab.com 100-12000
automattic h1 *.wordpress.com 50-7500
```

## Full Implementation

```python
#!/usr/bin/env python3
"""
bounty_arbitrage.py - Cross-Program Vulnerability Pattern Testing
Usage: python3 bounty_arbitrage.py cors-wildcard programs.txt [--output results.json]
"""

import argparse
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Callable
from datetime import datetime
from urllib.parse import urlparse

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("[!] pip install requests")
    sys.exit(1)


@dataclass
class Program:
    handle: str
    platform: str
    domain_pattern: str
    bounty_min: float = 0
    bounty_max: float = 0
    targets: List[str] = field(default_factory=list)


@dataclass
class ArbitrageResult:
    program: str
    domain: str
    pattern: str
    vulnerable: bool
    severity: str = "info"
    evidence: str = ""
    estimated_bounty_min: float = 0
    estimated_bounty_max: float = 0
    confidence: str = "low"  # low, medium, high
    draft_report: str = ""
    test_time: float = 0
    timestamp: str = ""


# ============================================================
# VULNERABILITY PATTERN IMPLEMENTATIONS
# ============================================================

def test_cors_wildcard(target: str, timeout: int = 10) -> ArbitrageResult:
    """Test for CORS misconfiguration with credentials."""
    result = ArbitrageResult(
        program="", domain=target, pattern="cors-wildcard",
        vulnerable=False, timestamp=datetime.utcnow().isoformat(),
    )
    start = time.time()

    origins = [
        ("https://evil.com", "exact_reflection"),
        ("null", "null_origin"),
    ]

    # Also try subdomain wildcard if we can parse the domain
    parsed = urlparse(target if "://" in target else f"https://{target}")
    hostname = parsed.hostname or target
    origins.append((f"https://evil.{hostname}", "subdomain_wildcard"))

    for origin, bypass_type in origins:
        try:
            resp = requests.get(
                target if "://" in target else f"https://{target}",
                headers={"Origin": origin, "User-Agent": "Mozilla/5.0"},
                timeout=timeout,
                verify=False,
                allow_redirects=False,
            )
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")

            if acao == origin:
                has_creds = acac.lower() == "true"
                result.vulnerable = True
                result.severity = "critical" if has_creds else "medium"
                result.confidence = "high"
                result.evidence = (
                    f"Origin: {origin} -> ACAO: {acao}, ACAC: {acac} "
                    f"(bypass: {bypass_type})"
                )
                result.estimated_bounty_min = 1000 if has_creds else 200
                result.estimated_bounty_max = 5000 if has_creds else 1000
                break
        except Exception:
            continue

    result.test_time = round(time.time() - start, 3)
    return result


def test_missing_hsts(target: str, timeout: int = 10) -> ArbitrageResult:
    """Test for missing HSTS on authentication endpoints."""
    result = ArbitrageResult(
        program="", domain=target, pattern="missing-hsts-on-auth",
        vulnerable=False, timestamp=datetime.utcnow().isoformat(),
    )
    start = time.time()

    auth_paths = ["/login", "/signin", "/auth", "/account", "/api/auth", "/oauth"]
    base = target if "://" in target else f"https://{target}"

    for path in auth_paths:
        try:
            resp = requests.get(
                f"{base}{path}",
                timeout=timeout,
                verify=False,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0"},
            )
            if resp.status_code in (200, 302, 301):
                hsts = resp.headers.get("Strict-Transport-Security", "")
                if not hsts:
                    result.vulnerable = True
                    result.severity = "medium"
                    result.confidence = "high"
                    result.evidence = f"No HSTS on {base}{path} (status: {resp.status_code})"
                    result.estimated_bounty_min = 100
                    result.estimated_bounty_max = 500
                    break
                elif "max-age" in hsts:
                    max_age = re.search(r"max-age=(\d+)", hsts)
                    if max_age and int(max_age.group(1)) < 31536000:
                        result.vulnerable = True
                        result.severity = "low"
                        result.confidence = "medium"
                        result.evidence = f"Weak HSTS max-age ({max_age.group(1)}s) on {base}{path}"
                        result.estimated_bounty_min = 50
                        result.estimated_bounty_max = 200
        except Exception:
            continue

    result.test_time = round(time.time() - start, 3)
    return result


def test_open_redirect(target: str, timeout: int = 10) -> ArbitrageResult:
    """Test for open redirect vulnerabilities."""
    result = ArbitrageResult(
        program="", domain=target, pattern="open-redirect",
        vulnerable=False, timestamp=datetime.utcnow().isoformat(),
    )
    start = time.time()

    base = target if "://" in target else f"https://{target}"
    redirect_payloads = [
        "/login?redirect=https://evil.com",
        "/login?next=https://evil.com",
        "/login?return_to=https://evil.com",
        "/login?redirect_uri=https://evil.com",
        "/login?continue=https://evil.com",
        "/auth?redirect=//evil.com",
        "/logout?next=https://evil.com",
        "/sso?returnUrl=https://evil.com",
    ]

    for payload in redirect_payloads:
        try:
            resp = requests.get(
                f"{base}{payload}",
                timeout=timeout,
                verify=False,
                allow_redirects=False,
                headers={"User-Agent": "Mozilla/5.0"},
            )
            location = resp.headers.get("Location", "")
            if resp.status_code in (301, 302, 303, 307, 308):
                if "evil.com" in location:
                    result.vulnerable = True
                    result.severity = "medium"
                    result.confidence = "high"
                    result.evidence = f"Open redirect: {base}{payload} -> {location}"
                    result.estimated_bounty_min = 150
                    result.estimated_bounty_max = 1000
                    break
        except Exception:
            continue

    result.test_time = round(time.time() - start, 3)
    return result


def test_graphql_introspection(target: str, timeout: int = 10) -> ArbitrageResult:
    """Test for GraphQL introspection enabled in production."""
    result = ArbitrageResult(
        program="", domain=target, pattern="graphql-introspection",
        vulnerable=False, timestamp=datetime.utcnow().isoformat(),
    )
    start = time.time()

    base = target if "://" in target else f"https://{target}"
    gql_paths = ["/graphql", "/api/graphql", "/v1/graphql", "/gql", "/query"]
    introspection_query = '{"query":"{ __schema { types { name } } }"}'

    for path in gql_paths:
        try:
            resp = requests.post(
                f"{base}{path}",
                data=introspection_query,
                headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
                timeout=timeout,
                verify=False,
            )
            if resp.status_code == 200 and "__schema" in resp.text:
                result.vulnerable = True
                result.severity = "medium"
                result.confidence = "high"
                type_count = resp.text.count('"name"')
                result.evidence = f"Introspection enabled at {base}{path} ({type_count} types exposed)"
                result.estimated_bounty_min = 200
                result.estimated_bounty_max = 1500
                break
        except Exception:
            continue

    result.test_time = round(time.time() - start, 3)
    return result


def test_exposed_env(target: str, timeout: int = 10) -> ArbitrageResult:
    """Test for exposed .env, .git, and other sensitive files."""
    result = ArbitrageResult(
        program="", domain=target, pattern="exposed-env",
        vulnerable=False, timestamp=datetime.utcnow().isoformat(),
    )
    start = time.time()

    base = target if "://" in target else f"https://{target}"
    checks = [
        ("/.env", ["APP_KEY", "DB_PASSWORD", "SECRET", "AWS_", "API_KEY"]),
        ("/.git/HEAD", ["ref: refs/"]),
        ("/.git/config", ["[core]", "[remote"]),
        ("/config.json", ['"password"', '"secret"', '"apiKey"']),
        ("/wp-config.php.bak", ["DB_NAME", "DB_PASSWORD"]),
        ("/.svn/entries", ["dir", "svn"]),
    ]

    for path, indicators in checks:
        try:
            resp = requests.get(
                f"{base}{path}",
                timeout=timeout,
                verify=False,
                allow_redirects=False,
                headers={"User-Agent": "Mozilla/5.0"},
            )
            if resp.status_code == 200:
                content = resp.text[:5000]
                if any(ind.lower() in content.lower() for ind in indicators):
                    result.vulnerable = True
                    result.severity = "critical"
                    result.confidence = "high"
                    result.evidence = f"Sensitive file exposed: {base}{path} (matched indicators)"
                    result.estimated_bounty_min = 500
                    result.estimated_bounty_max = 5000
                    break
        except Exception:
            continue

    result.test_time = round(time.time() - start, 3)
    return result


def test_missing_csp(target: str, timeout: int = 10) -> ArbitrageResult:
    """Test for missing CSP on pages with user content."""
    result = ArbitrageResult(
        program="", domain=target, pattern="missing-csp-on-user-content",
        vulnerable=False, timestamp=datetime.utcnow().isoformat(),
    )
    start = time.time()

    base = target if "://" in target else f"https://{target}"

    try:
        resp = requests.get(
            base,
            timeout=timeout,
            verify=False,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        csp = resp.headers.get("Content-Security-Policy", "")
        has_user_content = any(
            kw in resp.text.lower()
            for kw in ["user-content", "comment", "profile", "post", "message",
                       "textarea", "editor", "richtext", "wysiwyg"]
        )

        if not csp and has_user_content:
            result.vulnerable = True
            result.severity = "medium"
            result.confidence = "medium"
            result.evidence = f"No CSP on {base} which appears to render user content"
            result.estimated_bounty_min = 200
            result.estimated_bounty_max = 1000
        elif not csp:
            result.vulnerable = True
            result.severity = "low"
            result.confidence = "low"
            result.evidence = f"No CSP on {base}"
            result.estimated_bounty_min = 100
            result.estimated_bounty_max = 500
    except Exception:
        pass

    result.test_time = round(time.time() - start, 3)
    return result


def test_cookie_no_secure(target: str, timeout: int = 10) -> ArbitrageResult:
    """Test for session cookies without Secure flag."""
    result = ArbitrageResult(
        program="", domain=target, pattern="cookie-no-secure",
        vulnerable=False, timestamp=datetime.utcnow().isoformat(),
    )
    start = time.time()

    base = target if "://" in target else f"https://{target}"

    try:
        resp = requests.get(base, timeout=timeout, verify=False, allow_redirects=True)
        cookies = resp.headers.get("Set-Cookie", "")
        if cookies:
            # Check each cookie
            for cookie in cookies.split(","):
                cookie_lower = cookie.lower()
                is_session = any(
                    name in cookie_lower
                    for name in ["session", "sess", "sid", "token", "auth", "jwt"]
                )
                if is_session and "secure" not in cookie_lower:
                    result.vulnerable = True
                    result.severity = "medium"
                    result.confidence = "high"
                    result.evidence = f"Session cookie without Secure flag: {cookie.split(';')[0][:50]}"
                    result.estimated_bounty_min = 100
                    result.estimated_bounty_max = 500
                    break
    except Exception:
        pass

    result.test_time = round(time.time() - start, 3)
    return result


def test_subdomain_takeover(target: str, timeout: int = 15) -> ArbitrageResult:
    """Test for subdomain takeover via dangling CNAME."""
    result = ArbitrageResult(
        program="", domain=target, pattern="subdomain-takeover",
        vulnerable=False, timestamp=datetime.utcnow().isoformat(),
    )
    start = time.time()

    import subprocess

    # Vulnerable CNAME targets
    takeover_indicators = {
        "s3.amazonaws.com": ("NoSuchBucket", "AWS S3"),
        "herokuapp.com": ("No such app", "Heroku"),
        "herokudns.com": ("No such app", "Heroku"),
        "github.io": ("There isn't a GitHub Pages site here", "GitHub Pages"),
        "pantheonsite.io": ("404 error unknown site", "Pantheon"),
        "domains.tumblr.com": ("There's nothing here", "Tumblr"),
        "wordpress.com": ("Do you want to register", "WordPress"),
        "ghost.io": ("404 — Page not found", "Ghost"),
        "surge.sh": ("project not found", "Surge"),
        "bitbucket.io": ("Repository not found", "Bitbucket"),
        "shopify.com": ("Sorry, this shop is currently unavailable", "Shopify"),
        "fastly.net": ("Fastly error: unknown domain", "Fastly"),
        "zendesk.com": ("Help Center Closed", "Zendesk"),
        "azurewebsites.net": ("404 Web Site not found", "Azure"),
        "cloudfront.net": ("Bad Request", "CloudFront"),
    }

    domain = target.replace("https://", "").replace("http://", "").split("/")[0]

    try:
        cname_result = subprocess.run(
            ["dig", "+short", "CNAME", domain, "@8.8.8.8"],
            capture_output=True, text=True, timeout=10,
        )
        cname = cname_result.stdout.strip().rstrip(".")

        if cname:
            for indicator_domain, (body_text, service) in takeover_indicators.items():
                if indicator_domain in cname:
                    # Verify by checking the response
                    try:
                        resp = requests.get(
                            f"https://{domain}",
                            timeout=timeout,
                            verify=False,
                            allow_redirects=True,
                        )
                        if body_text.lower() in resp.text.lower() or resp.status_code == 404:
                            result.vulnerable = True
                            result.severity = "high"
                            result.confidence = "high"
                            result.evidence = (
                                f"CNAME {domain} -> {cname} ({service}) "
                                f"returns takeover indicator"
                            )
                            result.estimated_bounty_min = 500
                            result.estimated_bounty_max = 3000
                            break
                    except requests.ConnectionError:
                        # Connection error might also indicate takeover
                        result.vulnerable = True
                        result.severity = "high"
                        result.confidence = "medium"
                        result.evidence = (
                            f"CNAME {domain} -> {cname} ({service}) "
                            f"connection refused - likely takeover candidate"
                        )
                        result.estimated_bounty_min = 500
                        result.estimated_bounty_max = 3000
                        break
    except Exception:
        pass

    result.test_time = round(time.time() - start, 3)
    return result


# ============================================================
# PATTERN REGISTRY
# ============================================================

PATTERNS: Dict[str, Dict] = {
    "cors-wildcard": {
        "function": test_cors_wildcard,
        "description": "CORS misconfiguration with credential reflection",
        "typical_bounty": "$500-$5000",
        "cvss_range": "7.0-8.1",
    },
    "missing-hsts-on-auth": {
        "function": test_missing_hsts,
        "description": "Missing HSTS on authentication endpoints",
        "typical_bounty": "$100-$500",
        "cvss_range": "4.0-5.0",
    },
    "open-redirect": {
        "function": test_open_redirect,
        "description": "Unvalidated redirect on auth/login URLs",
        "typical_bounty": "$150-$1000",
        "cvss_range": "4.0-6.0",
    },
    "graphql-introspection": {
        "function": test_graphql_introspection,
        "description": "GraphQL introspection enabled in production",
        "typical_bounty": "$200-$1500",
        "cvss_range": "5.0-6.0",
    },
    "exposed-env": {
        "function": test_exposed_env,
        "description": "Exposed .env, .git, or config files",
        "typical_bounty": "$500-$5000",
        "cvss_range": "7.0-9.0",
    },
    "missing-csp-on-user-content": {
        "function": test_missing_csp,
        "description": "Missing CSP on pages rendering user content",
        "typical_bounty": "$200-$1000",
        "cvss_range": "4.0-6.0",
    },
    "cookie-no-secure": {
        "function": test_cookie_no_secure,
        "description": "Session cookies without Secure flag",
        "typical_bounty": "$100-$500",
        "cvss_range": "3.0-4.0",
    },
    "subdomain-takeover": {
        "function": test_subdomain_takeover,
        "description": "Dangling CNAME records vulnerable to takeover",
        "typical_bounty": "$500-$3000",
        "cvss_range": "7.0-8.0",
    },
}


# ============================================================
# REPORT GENERATOR
# ============================================================

def generate_report(result: ArbitrageResult) -> str:
    """Generate a draft bug bounty report for a finding."""
    templates = {
        "cors-wildcard": """## Title
CORS Misconfiguration Allows Cross-Origin Data Theft on {domain}

## Severity
{severity} (CVSS ~8.1)

## Description
The endpoint at `{domain}` reflects arbitrary Origin headers in the
`Access-Control-Allow-Origin` response header while also setting
`Access-Control-Allow-Credentials: true`. This allows an attacker to
read authenticated API responses from any origin.

## Steps to Reproduce
1. Authenticate to {domain} in your browser
2. Open the following HTML file in the same browser:

```html
<script>
fetch('{domain}', {{credentials: 'include'}})
  .then(r => r.text())
  .then(d => document.write('<pre>'+d+'</pre>'));
</script>
```

3. Observe that the authenticated response is readable by the attacker origin

## Evidence
{evidence}

## Impact
An attacker can steal any authenticated user's data by tricking them into
visiting a malicious website. This includes personal information, session
tokens, and any data accessible via the affected API endpoint.

## Remediation
- Implement a strict allowlist of trusted origins
- Do not reflect the Origin header directly
- Consider if `Access-Control-Allow-Credentials: true` is necessary
""",
        "missing-hsts-on-auth": """## Title
Missing HSTS Header on Authentication Endpoint at {domain}

## Severity
{severity}

## Description
The authentication endpoint at `{domain}` does not set the
`Strict-Transport-Security` header, making it vulnerable to
SSL stripping attacks.

## Evidence
{evidence}

## Impact
An attacker performing a man-in-the-middle attack can downgrade
the connection to HTTP and intercept credentials.

## Remediation
Add `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`
""",
        "open-redirect": """## Title
Open Redirect on {domain}

## Severity
{severity}

## Description
The login/authentication flow at `{domain}` contains an open redirect
vulnerability that can be used for phishing or OAuth token theft.

## Evidence
{evidence}

## Impact
An attacker can craft a link that appears to be from {domain} but
redirects the victim to a malicious site after authentication.
This can be chained with OAuth flows to steal access tokens.

## Remediation
- Validate redirect URLs against a strict allowlist
- Only allow relative redirects
- Use a redirect allowlist or signing mechanism
""",
    }

    template = templates.get(result.pattern, """## Title
{pattern} vulnerability on {domain}

## Severity
{severity}

## Evidence
{evidence}

## Impact
Security misconfiguration that may lead to data exposure or account compromise.
""")

    return template.format(
        domain=result.domain,
        severity=result.severity.upper(),
        evidence=result.evidence,
        pattern=result.pattern,
    )


# ============================================================
# MAIN ORCHESTRATOR
# ============================================================

def load_programs(programs_file: str) -> List[Program]:
    """Load programs from file."""
    programs = []
    with open(programs_file) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 3:
                bounty_range = parts[3] if len(parts) > 3 else "0-0"
                bounty_parts = bounty_range.split("-")
                program = Program(
                    handle=parts[0],
                    platform=parts[1],
                    domain_pattern=parts[2],
                    bounty_min=float(bounty_parts[0]) if len(bounty_parts) > 0 else 0,
                    bounty_max=float(bounty_parts[1]) if len(bounty_parts) > 1 else 0,
                )
                # Convert wildcard pattern to actual target
                domain = program.domain_pattern.replace("*.", "www.")
                program.targets = [domain]
                programs.append(program)
    return programs


def run_arbitrage(pattern_name: str, programs: List[Program],
                  workers: int = 20, min_bounty: float = 0,
                  output_file: str = None, report_dir: str = None):
    """Run a vuln pattern against all programs."""

    if pattern_name not in PATTERNS:
        print(f"[!] Unknown pattern: {pattern_name}")
        print(f"    Available: {', '.join(PATTERNS.keys())}")
        return

    pattern = PATTERNS[pattern_name]
    test_func = pattern["function"]

    # Filter by minimum bounty
    if min_bounty > 0:
        programs = [p for p in programs if p.bounty_max >= min_bounty]

    # Build target list
    targets = []
    for program in programs:
        for target in program.targets:
            targets.append((program, target))

    print(f"\n{'='*60}")
    print(f"  Bounty Arbitrage")
    print(f"  Pattern: {pattern_name} - {pattern['description']}")
    print(f"  Programs: {len(programs)} | Targets: {len(targets)} | Workers: {workers}")
    print(f"  Typical bounty: {pattern['typical_bounty']}")
    print(f"{'='*60}\n")

    results = []
    vulnerable_count = 0
    total_estimated = 0
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {}
        for program, target in targets:
            future = executor.submit(test_func, target)
            futures[future] = (program, target)

        for future in as_completed(futures):
            program, target = futures[future]
            try:
                result = future.result()
                result.program = program.handle
                result.domain = target

                # Adjust bounty estimates based on program's range
                if result.vulnerable and program.bounty_max > 0:
                    severity_multiplier = {
                        "critical": 0.8, "high": 0.5,
                        "medium": 0.2, "low": 0.05,
                    }.get(result.severity, 0.1)
                    result.estimated_bounty_min = max(
                        result.estimated_bounty_min,
                        program.bounty_min * severity_multiplier,
                    )
                    result.estimated_bounty_max = min(
                        result.estimated_bounty_max,
                        program.bounty_max * severity_multiplier,
                    )

                # Generate report
                if result.vulnerable:
                    result.draft_report = generate_report(result)
                    vulnerable_count += 1
                    total_estimated += result.estimated_bounty_max
                    print(f"  \033[91m[VULN]\033[0m {program.handle:20s} | {target:40s} | "
                          f"${result.estimated_bounty_min:.0f}-${result.estimated_bounty_max:.0f} | "
                          f"{result.severity}")
                else:
                    print(f"  [OK]   {program.handle:20s} | {target:40s}")

                results.append(result)
            except Exception as e:
                print(f"  [ERR]  {program.handle:20s} | {target}: {e}")

    elapsed = round(time.time() - start_time, 1)

    # Sort: vulnerable first, then by estimated bounty
    results.sort(key=lambda r: (not r.vulnerable, -r.estimated_bounty_max))

    # Summary
    print(f"\n{'='*60}")
    print(f"  ARBITRAGE RESULTS")
    print(f"{'='*60}")
    print(f"  Pattern:           {pattern_name}")
    print(f"  Tested:            {len(results)} targets in {elapsed}s")
    print(f"  Vulnerable:        {vulnerable_count}/{len(results)}")
    print(f"  Est. total bounty: ${total_estimated:.0f}")
    print(f"{'='*60}\n")

    if vulnerable_count > 0:
        print(f"  Vulnerable Programs (sorted by estimated bounty):\n")
        for r in results:
            if r.vulnerable:
                print(f"    {r.program:20s} ${r.estimated_bounty_min:.0f}-${r.estimated_bounty_max:.0f} "
                      f"[{r.severity}] {r.confidence} confidence")
                print(f"      Evidence: {r.evidence[:100]}")
                print()

    # Save results
    if output_file:
        output = {
            "pattern": pattern_name,
            "total_tested": len(results),
            "vulnerable": vulnerable_count,
            "estimated_total_bounty": total_estimated,
            "elapsed_seconds": elapsed,
            "results": [asdict(r) for r in results],
        }
        with open(output_file, "w") as f:
            json.dump(output, f, indent=2)
        print(f"[+] Results saved to {output_file}")

    # Save individual reports
    if report_dir and vulnerable_count > 0:
        os.makedirs(report_dir, exist_ok=True)
        for r in results:
            if r.vulnerable and r.draft_report:
                fname = f"{r.program}_{pattern_name}.md"
                with open(os.path.join(report_dir, fname), "w") as f:
                    f.write(r.draft_report)
        print(f"[+] Draft reports saved to {report_dir}/")

    return results


def main():
    parser = argparse.ArgumentParser(description="Bounty Arbitrage - Cross-Program Vuln Testing")
    parser.add_argument("pattern", nargs="?", help="Vulnerability pattern to test")
    parser.add_argument("programs", nargs="?", help="Programs file")
    parser.add_argument("--workers", type=int, default=20, help="Parallel workers")
    parser.add_argument("--output", help="Output JSON file")
    parser.add_argument("--min-bounty", type=float, default=0, help="Minimum bounty threshold")
    parser.add_argument("--generate-reports", help="Directory for draft reports")
    parser.add_argument("--list-patterns", action="store_true", help="List available patterns")
    args = parser.parse_args()

    if args.list_patterns:
        print(f"\n  Available Vulnerability Patterns:\n")
        for name, info in PATTERNS.items():
            print(f"    {name:30s} {info['description']}")
            print(f"    {'':30s} Bounty: {info['typical_bounty']} | CVSS: {info['cvss_range']}")
            print()
        return

    if not args.pattern or not args.programs:
        parser.print_help()
        return

    programs = load_programs(args.programs)
    run_arbitrage(
        args.pattern, programs,
        workers=args.workers,
        min_bounty=args.min_bounty,
        output_file=args.output,
        report_dir=args.generate_reports,
    )


if __name__ == "__main__":
    main()
```

## Quick Commands

### Test CORS across 50 programs (the CLEAR pattern)
```bash
python3 bounty_arbitrage.py cors-wildcard programs.txt --workers 30 --output cors_arbitrage.json --generate-reports ./reports/
```

### Test multiple patterns across all programs
```bash
for pattern in cors-wildcard missing-hsts-on-auth open-redirect graphql-introspection exposed-env; do
  echo "=== Testing: $pattern ==="
  python3 bounty_arbitrage.py "$pattern" programs.txt --output "${pattern}_results.json" --generate-reports "./reports/${pattern}/"
done
```

### Focus on high-bounty programs only
```bash
python3 bounty_arbitrage.py cors-wildcard programs.txt --min-bounty 1000 --output high_value_cors.json
```

### Generate the programs file from scope-parser
```bash
for prog in uber shopify github gitlab; do
  domain=$(python3 ../scope-parser/scope_parser.py "$prog" --platform h1 --domains-only 2>/dev/null | head -1)
  bounty=$(python3 ../scope-parser/scope_parser.py "$prog" --platform h1 --output /dev/stdout 2>/dev/null | jq -r '"$(.bounty_range.low)-$(.bounty_range.critical)"')
  echo "$prog h1 *.${domain} ${bounty}"
done > programs.txt
```

## Integration Pipeline

### Full arbitrage workflow
```bash
# 1. Parse scopes from multiple programs
python3 ../scope-parser/scope_parser.py --bulk programs_list.txt --output-dir ./scopes/

# 2. Build targets file from scopes
for f in ./scopes/*.json; do
  handle=$(jq -r '.program.handle' "$f")
  domain=$(jq -r '.scope.domains[0]' "$f")
  bounty=$(jq -r '"\\(.bounty_range.low // 0)-\\(.bounty_range.critical // 0)"' "$f")
  echo "$handle h1 *.$domain $bounty"
done > programs.txt

# 3. Run arbitrage
python3 bounty_arbitrage.py cors-wildcard programs.txt --output results.json --generate-reports ./reports/

# 4. Deep test hits with cors-chain
jq -r '.results[] | select(.vulnerable) | .domain' results.json | while read domain; do
  python3 ../cors-chain/cors_chain.py "https://${domain}" --output "cors_deep_${domain}.json"
done

# 5. Build attack chains from all findings
python3 ../finding-chain-builder/chain_builder.py --from-cors cors_deep_*.json --output chains.json
```
