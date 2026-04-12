# Spray Scanner Agent
# Parallel Multi-Target Scanning with Ranked Output
# Test multiple domains simultaneously with configurable concurrency

## Purpose
Take a list of target domains and run a comprehensive quickscan on each in parallel.
Consolidate all results into a single ranked output with the most promising targets first.
Designed for wide-scope programs where you need to triage 50-500 domains quickly.

## Usage
```
spray-scanner <domains_file> [--workers 20] [--timeout 30] [--output results.json] [--scan-type quick|full|cors|headers]
spray-scanner --generate-targets <program_name> | spray-scanner --stdin
```

## Environment Requirements
- Python 3.10+ with requests, concurrent.futures
- Optional: httpx CLI, nuclei, subfinder
- GNU parallel (for bash-mode scanning)

## Input Format
```
# domains.txt - one target per line
# Lines starting with # are comments
https://api.target1.com
https://app.target2.com
https://target3.com
# Can also be bare domains (https:// is prepended)
target4.com
api.target5.com
```

## Core Implementation

```python
#!/usr/bin/env python3
"""
spray_scanner.py - Parallel Multi-Target Scanner
Usage: python3 spray_scanner.py domains.txt [--workers 20] [--output results.json]
"""

import argparse
import json
import sys
import time
import hashlib
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict
from urllib.parse import urlparse
from datetime import datetime

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("[!] pip install requests")
    sys.exit(1)


@dataclass
class Finding:
    category: str
    severity: str  # critical, high, medium, low, info
    title: str
    detail: str
    evidence: str = ""


@dataclass
class ScanResult:
    target: str
    status: str  # scanned, error, timeout, filtered
    http_status: int = 0
    response_time: float = 0.0
    technologies: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    score: float = 0.0  # Composite interest score
    headers: Dict[str, str] = field(default_factory=dict)
    error: str = ""
    timestamp: str = ""

    def calculate_score(self):
        """Calculate composite score for ranking."""
        severity_weights = {"critical": 100, "high": 50, "medium": 20, "low": 5, "info": 1}
        self.score = sum(
            severity_weights.get(f.severity, 0)
            for f in self.findings
        )
        # Bonus for fast response (likely active target)
        if 0 < self.response_time < 2:
            self.score += 10
        # Bonus for interesting technologies
        interesting_techs = {"graphql", "wordpress", "laravel", "django", "next.js"}
        for tech in self.technologies:
            if tech.lower() in interesting_techs:
                self.score += 15
        return self.score


def normalize_target(target: str) -> str:
    """Ensure target has a scheme."""
    target = target.strip()
    if not target:
        return ""
    if not target.startswith("http"):
        target = f"https://{target}"
    return target


def detect_technologies(response) -> List[str]:
    """Quick tech detection from response."""
    techs = []
    headers = {k.lower(): v.lower() for k, v in response.headers.items()}
    body = response.text[:30000].lower() if len(response.text) > 0 else ""
    powered = headers.get("x-powered-by", "")
    server = headers.get("server", "")
    cookies = headers.get("set-cookie", "")

    detections = {
        "nginx": "nginx" in server,
        "apache": "apache" in server,
        "cloudflare": "cloudflare" in server or "cf-ray" in str(headers),
        "next.js": "/_next/" in body or "__next" in body,
        "react": "data-reactroot" in body or "react" in body,
        "wordpress": "wp-content" in body or "wp-json" in body,
        "laravel": "laravel_session" in cookies,
        "express": "express" in powered,
        "django": "csrftoken" in cookies,
        "graphql": "graphql" in body,
        "shopify": "cdn.shopify.com" in body,
        "php": "phpsessid" in cookies.lower() or "php" in powered,
        "asp.net": "asp.net" in powered or "__viewstate" in body,
        "java": "jsessionid" in cookies.lower(),
    }

    for tech, detected in detections.items():
        if detected:
            techs.append(tech)

    return techs


def check_security_headers(response) -> List[Finding]:
    """Check for missing or misconfigured security headers."""
    findings = []
    headers = {k.lower(): v for k, v in response.headers.items()}

    # Critical missing headers
    header_checks = [
        ("content-security-policy", "Missing Content-Security-Policy", "medium",
         "No CSP header - potential XSS chain target"),
        ("strict-transport-security", "Missing HSTS", "medium",
         "No HSTS header - vulnerable to SSL stripping"),
        ("x-frame-options", "Missing X-Frame-Options", "low",
         "No clickjacking protection (check CSP frame-ancestors too)"),
        ("x-content-type-options", "Missing X-Content-Type-Options", "low",
         "No MIME sniffing protection"),
    ]

    for header, title, severity, detail in header_checks:
        if header not in headers:
            findings.append(Finding("headers", severity, title, detail))

    # Check for overly permissive CORS
    acao = headers.get("access-control-allow-origin", "")
    if acao == "*":
        findings.append(Finding("cors", "medium", "CORS Wildcard (*)",
                                "Access-Control-Allow-Origin: * - check if credentials are also allowed"))

    # Check for information disclosure headers
    server = headers.get("server", "")
    powered = headers.get("x-powered-by", "")
    if server and any(v in server.lower() for v in ["apache/", "nginx/", "iis/"]):
        findings.append(Finding("info-disclosure", "info", "Server Version Exposed",
                                f"Server: {server}"))
    if powered:
        findings.append(Finding("info-disclosure", "info", "X-Powered-By Exposed",
                                f"X-Powered-By: {powered}"))

    # Check cookies
    for cookie_header in response.headers.getlist("Set-Cookie") if hasattr(response.headers, 'getlist') else [headers.get("set-cookie", "")]:
        if cookie_header:
            if "secure" not in cookie_header.lower():
                findings.append(Finding("cookies", "medium", "Cookie Missing Secure Flag",
                                        f"Cookie without Secure: {cookie_header[:80]}"))
            if "httponly" not in cookie_header.lower():
                findings.append(Finding("cookies", "low", "Cookie Missing HttpOnly Flag",
                                        f"Cookie without HttpOnly: {cookie_header[:80]}"))

    return findings


def check_cors_quick(target: str, timeout: int = 10) -> List[Finding]:
    """Quick CORS check with common bypasses."""
    findings = []
    parsed = urlparse(target)

    origins = [
        ("evil.com", "arbitrary_origin"),
        (f"evil.{parsed.hostname}", "subdomain_wildcard"),
        ("null", "null_origin"),
    ]

    for origin, bypass_type in origins:
        origin_header = origin if origin == "null" else f"https://{origin}"
        try:
            resp = requests.get(
                target,
                headers={"Origin": origin_header},
                timeout=timeout,
                verify=False,
                allow_redirects=False,
            )
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")
            if acao == origin_header:
                severity = "critical" if acac.lower() == "true" else "high"
                findings.append(Finding(
                    "cors", severity,
                    f"CORS {bypass_type}: Origin reflected",
                    f"Origin: {origin_header} -> ACAO: {acao}, ACAC: {acac}",
                    evidence=f"curl -H 'Origin: {origin_header}' '{target}'",
                ))
        except Exception:
            pass

    return findings


def check_common_endpoints(target: str, timeout: int = 10) -> List[Finding]:
    """Check for common interesting/vulnerable endpoints."""
    findings = []
    parsed = urlparse(target)
    base = f"{parsed.scheme}://{parsed.hostname}"
    if parsed.port and parsed.port not in (80, 443):
        base += f":{parsed.port}"

    endpoints = [
        ("/.env", "critical", "Exposed .env file"),
        ("/.git/HEAD", "critical", "Exposed .git directory"),
        ("/wp-json/wp/v2/users", "medium", "WordPress user enumeration"),
        ("/graphql", "medium", "GraphQL endpoint"),
        ("/api/graphql", "medium", "GraphQL API endpoint"),
        ("/swagger.json", "medium", "Swagger/OpenAPI spec exposed"),
        ("/api/swagger.json", "medium", "Swagger/OpenAPI spec exposed"),
        ("/openapi.json", "medium", "OpenAPI spec exposed"),
        ("/.well-known/openid-configuration", "info", "OpenID configuration"),
        ("/robots.txt", "info", "Robots.txt"),
        ("/sitemap.xml", "info", "Sitemap"),
        ("/server-status", "medium", "Apache server-status"),
        ("/debug", "high", "Debug endpoint"),
        ("/_debug", "high", "Debug endpoint"),
        ("/actuator", "high", "Spring Actuator"),
        ("/actuator/health", "medium", "Spring Actuator health"),
        ("/actuator/env", "critical", "Spring Actuator env - secrets exposed"),
        ("/wp-content/debug.log", "high", "WordPress debug log"),
        ("/.DS_Store", "low", "macOS directory listing"),
        ("/crossdomain.xml", "low", "Flash crossdomain policy"),
        ("/elmah.axd", "high", "ELMAH error log (.NET)"),
        ("/trace", "high", "Spring trace endpoint"),
        ("/info", "low", "Info endpoint"),
        ("/health", "info", "Health check endpoint"),
        ("/_next/static/chunks/app/layout.js", "info", "Next.js app router"),
    ]

    for path, severity, title in endpoints:
        try:
            resp = requests.get(
                f"{base}{path}",
                timeout=timeout,
                verify=False,
                allow_redirects=False,
                headers={"User-Agent": "Mozilla/5.0"},
            )
            if resp.status_code == 200:
                content = resp.text[:500].lower()
                # Validate it's actually the thing we're looking for
                if path == "/.env" and any(k in content for k in ["app_key", "db_", "password", "secret"]):
                    findings.append(Finding("exposure", severity, title, f"{base}{path} returned 200 with env data"))
                elif path == "/.git/HEAD" and "ref:" in content:
                    findings.append(Finding("exposure", severity, title, f"{base}{path} - git repo exposed"))
                elif path in ("/graphql", "/api/graphql"):
                    findings.append(Finding("endpoint", severity, title, f"{base}{path} accessible"))
                elif path.endswith(".json") and ("{" in content or "[" in content):
                    findings.append(Finding("exposure", severity, title, f"{base}{path} returns JSON"))
                elif path == "/actuator/env" and ("spring" in content or "jdbc" in content):
                    findings.append(Finding("exposure", severity, title, f"{base}{path} - Spring secrets"))
                elif severity in ("info", "low"):
                    findings.append(Finding("endpoint", severity, title, f"{base}{path} accessible"))
                elif resp.status_code == 200 and len(resp.text) > 50:
                    findings.append(Finding("endpoint", "info", title, f"{base}{path} returned 200"))
        except Exception:
            pass

    return findings


def scan_target(target: str, timeout: int = 15, scan_type: str = "quick") -> ScanResult:
    """Scan a single target."""
    target = normalize_target(target)
    if not target:
        return ScanResult(target="", status="error", error="Empty target")

    result = ScanResult(
        target=target,
        timestamp=datetime.utcnow().isoformat(),
    )

    try:
        start = time.time()
        resp = requests.get(
            target,
            timeout=timeout,
            verify=False,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
        )
        result.response_time = round(time.time() - start, 3)
        result.http_status = resp.status_code
        result.headers = dict(resp.headers)
        result.status = "scanned"

        # Tech detection
        result.technologies = detect_technologies(resp)

        # Security header checks
        result.findings.extend(check_security_headers(resp))

        # CORS checks
        if scan_type in ("quick", "full", "cors"):
            result.findings.extend(check_cors_quick(target, timeout))

        # Endpoint discovery
        if scan_type in ("quick", "full"):
            result.findings.extend(check_common_endpoints(target, timeout))

    except requests.Timeout:
        result.status = "timeout"
        result.error = "Connection timed out"
    except requests.ConnectionError as e:
        result.status = "error"
        result.error = f"Connection error: {str(e)[:100]}"
    except Exception as e:
        result.status = "error"
        result.error = str(e)[:200]

    result.calculate_score()
    return result


def spray_scan(domains_file: str, workers: int = 20, timeout: int = 15,
               scan_type: str = "quick", output_file: str = None) -> List[ScanResult]:
    """Run parallel scans against all targets."""

    # Load targets
    if domains_file == "-":
        targets = [line.strip() for line in sys.stdin if line.strip() and not line.startswith("#")]
    else:
        with open(domains_file) as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    print(f"\n{'='*60}")
    print(f"  Spray Scanner")
    print(f"  Targets: {len(targets)} | Workers: {workers} | Timeout: {timeout}s")
    print(f"  Scan type: {scan_type}")
    print(f"{'='*60}\n")

    results = []
    completed = 0
    total = len(targets)
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(scan_target, target, timeout, scan_type): target
            for target in targets
        }

        for future in as_completed(futures):
            completed += 1
            target = futures[future]
            try:
                result = future.result()
                results.append(result)
                finding_count = len(result.findings)
                critical_count = sum(1 for f in result.findings if f.severity == "critical")

                status_icon = {
                    "scanned": "+",
                    "error": "!",
                    "timeout": "~",
                }.get(result.status, "?")

                if critical_count > 0:
                    print(f"  [{status_icon}] ({completed}/{total}) {target} "
                          f"[{result.http_status}] {finding_count} findings "
                          f"\033[91m({critical_count} CRITICAL)\033[0m")
                elif finding_count > 5:
                    print(f"  [{status_icon}] ({completed}/{total}) {target} "
                          f"[{result.http_status}] \033[93m{finding_count} findings\033[0m")
                else:
                    print(f"  [{status_icon}] ({completed}/{total}) {target} "
                          f"[{result.http_status}] {finding_count} findings")

            except Exception as e:
                print(f"  [!] ({completed}/{total}) {target} - Exception: {e}")

    elapsed = round(time.time() - start_time, 1)

    # Sort by score (most promising first)
    results.sort(key=lambda r: r.score, reverse=True)

    # Print ranked summary
    print(f"\n{'='*60}")
    print(f"  RANKED RESULTS (Most Promising First)")
    print(f"  Scanned {len(results)} targets in {elapsed}s")
    print(f"{'='*60}\n")

    for i, r in enumerate(results[:30], 1):
        if r.score == 0:
            break
        criticals = sum(1 for f in r.findings if f.severity == "critical")
        highs = sum(1 for f in r.findings if f.severity == "high")
        techs = ", ".join(r.technologies[:3]) if r.technologies else "unknown"
        print(f"  #{i:2d} [Score: {r.score:6.1f}] {r.target}")
        print(f"      Tech: {techs} | C:{criticals} H:{highs} | {r.response_time}s")
        for f in r.findings:
            if f.severity in ("critical", "high"):
                print(f"      -> [{f.severity.upper()}] {f.title}")
        print()

    # Save results
    if output_file:
        output = {
            "scan_metadata": {
                "total_targets": total,
                "scanned": sum(1 for r in results if r.status == "scanned"),
                "errors": sum(1 for r in results if r.status == "error"),
                "timeouts": sum(1 for r in results if r.status == "timeout"),
                "elapsed_seconds": elapsed,
                "workers": workers,
                "scan_type": scan_type,
                "timestamp": datetime.utcnow().isoformat(),
            },
            "results": [
                {**asdict(r), "findings": [asdict(f) for f in r.findings]}
                for r in results
            ],
        }
        with open(output_file, "w") as f:
            json.dump(output, f, indent=2, default=str)
        print(f"[+] Results saved to {output_file}")

    return results


def main():
    parser = argparse.ArgumentParser(description="Spray Scanner - Parallel Target Scanner")
    parser.add_argument("domains", nargs="?", help="File with target domains (use - for stdin)")
    parser.add_argument("--workers", type=int, default=20, help="Parallel workers (default: 20)")
    parser.add_argument("--timeout", type=int, default=15, help="Request timeout in seconds")
    parser.add_argument("--scan-type", choices=["quick", "full", "cors", "headers"], default="quick")
    parser.add_argument("--output", help="Output JSON file")
    parser.add_argument("--min-score", type=float, default=0, help="Only show targets above this score")
    args = parser.parse_args()

    if not args.domains:
        parser.print_help()
        return

    results = spray_scan(
        args.domains,
        workers=args.workers,
        timeout=args.timeout,
        scan_type=args.scan_type,
        output_file=args.output,
    )

    if args.min_score > 0:
        filtered = [r for r in results if r.score >= args.min_score]
        print(f"\n[+] {len(filtered)} targets above score threshold {args.min_score}")


if __name__ == "__main__":
    main()
```

## GNU Parallel Alternative (Bash-mode)

### Quick header scan with parallel
```bash
# Parallel security header check
cat domains.txt | parallel -j 20 --timeout 15 '
  url="https://{}"
  headers=$(curl -s -D- -o /dev/null --max-time 10 "$url" 2>/dev/null)
  missing=""
  echo "$headers" | grep -qi "content-security-policy" || missing="${missing}CSP,"
  echo "$headers" | grep -qi "strict-transport-security" || missing="${missing}HSTS,"
  echo "$headers" | grep -qi "x-frame-options" || missing="${missing}XFO,"
  cors=$(echo "$headers" | grep -i "access-control-allow-origin" | tr -d "\r\n")
  [ -n "$missing" ] && echo "{}: MISSING=[${missing%,}] CORS=[$cors]"
' 2>/dev/null | tee header_scan_results.txt
```

### Parallel CORS spray
```bash
# Test CORS on all domains with evil.com origin
cat domains.txt | parallel -j 30 --timeout 10 '
  url="https://{}"
  resp=$(curl -s -D- -H "Origin: https://evil.com" -o /dev/null --max-time 8 "$url" 2>/dev/null)
  acao=$(echo "$resp" | grep -i "access-control-allow-origin" | tr -d "\r\n")
  acac=$(echo "$resp" | grep -i "access-control-allow-credentials" | tr -d "\r\n")
  if echo "$acao" | grep -qi "evil.com"; then
    echo "[VULN] {}: $acao | $acac"
  fi
' 2>/dev/null | tee cors_spray_results.txt
```

### Parallel endpoint discovery
```bash
# Check common endpoints across all domains
ENDPOINTS=(".env" ".git/HEAD" "graphql" "swagger.json" "actuator" "debug" "wp-json/wp/v2/users")
cat domains.txt | parallel -j 20 --timeout 10 '
  domain={}
  for ep in .env .git/HEAD graphql swagger.json actuator debug; do
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "https://${domain}/${ep}" 2>/dev/null)
    [ "$code" = "200" ] && echo "[200] https://${domain}/${ep}"
  done
' 2>/dev/null | tee endpoint_scan_results.txt
```

## Integration with Other Agents

### Generate target list from ghost-recon
```bash
python3 ../ghost-recon/ghost_recon.py target.com --output-dir ./recon
cat ./recon/target.com_subdomains.txt > domains.txt
python3 spray_scanner.py domains.txt --workers 30 --output spray_results.json
```

### Feed high-scoring targets to cors-chain
```bash
python3 spray_scanner.py domains.txt --output results.json
jq -r '.results[] | select(.score > 50) | .target' results.json | while read target; do
  python3 ../cors-chain/cors_chain.py "$target" --output "cors_$(echo $target | md5sum | cut -c1-8).json"
done
```

### Feed to vuln-predictor
```bash
jq -r '.results[] | select(.score > 20) | "\(.target) \(.technologies | join(","))"' results.json | \
while read target techs; do
  python3 ../vuln-predictor/predict.py "$target" --tech "$techs"
done
```

## Scan Type Reference

| Type | What It Tests | Speed | Use Case |
|------|--------------|-------|----------|
| quick | Headers + CORS + common endpoints | ~5s/target | Initial triage |
| full | Everything + deep endpoint checks | ~15s/target | Focused testing |
| cors | Only CORS misconfigurations | ~3s/target | CORS-specific hunt |
| headers | Only security headers | ~1s/target | Header compliance check |

## Rate Limiting and Safety
```bash
# Respect rate limits with --workers flag
# For sensitive programs, use lower concurrency
python3 spray_scanner.py domains.txt --workers 5 --timeout 30

# Add delay between requests per target (modify in code)
# Default: no delay (targets are different hosts)
```
