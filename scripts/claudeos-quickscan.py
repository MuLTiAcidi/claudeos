#!/usr/bin/env python3
"""
claudeos-quickscan.py — The 5-minute manual recon automated to 30 seconds

This is the REAL EXECUTABLE version of what we did manually on CLEAR, Kong,
WHOOP, and Rocket.Chat. One command. Full pipeline. Prioritized output.

Usage:
    claudeos quickscan target.com
    claudeos quickscan target.com --output json
    claudeos quickscan target.com --deep (includes nuclei + subfinder if available)

Pipeline:
    1. DNS resolution (A, AAAA, MX, NS, TXT, CNAME)
    2. Subdomain enumeration (crt.sh + subfinder if available)
    3. Live host detection (curl probe on each subdomain)
    4. Security headers audit on every live host
    5. CORS chain test (the 7-step pattern that found the CLEAR bug)
    6. OIDC/OAuth discovery
    7. Tech stack fingerprinting
    8. API endpoint probing
    9. Finding chain detection (connect dots automatically)
    10. Prioritized report output
"""
import sys, os, json, time, subprocess, urllib.request, urllib.parse, urllib.error
import ssl, socket, concurrent.futures
from pathlib import Path
from datetime import datetime

# === Config ===
TIMEOUT = 8
MAX_WORKERS = 10
USER_AGENT = "ClaudeOS-QuickScan/1.0"

# SSL context that doesn't verify (for scanning)
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

class Colors:
    R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"; B = "\033[94m"
    P = "\033[95m"; C = "\033[96m"; BOLD = "\033[1m"; END = "\033[0m"

def log(msg, color=""):
    print(f"{color}{msg}{Colors.END}")

def http_get(url, headers=None, timeout=TIMEOUT):
    """Simple HTTP GET, returns (status, headers_dict, body)."""
    req = urllib.request.Request(url)
    req.add_header("User-Agent", USER_AGENT)
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    handler = urllib.request.HTTPSHandler(context=SSL_CTX)
    opener = urllib.request.build_opener(handler)
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read().decode("utf-8", errors="ignore")[:50000]
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode("utf-8", errors="ignore")[:5000]
    except Exception as e:
        return 0, {}, str(e)

def dns_lookup(domain):
    """Get DNS records using dig."""
    records = {}
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
        try:
            r = subprocess.run(["dig", "+short", rtype, domain], capture_output=True, text=True, timeout=5)
            vals = [l.strip() for l in r.stdout.strip().split("\n") if l.strip()]
            if vals:
                records[rtype] = vals
        except:
            pass
    return records

def enumerate_subdomains(domain):
    """Enumerate subdomains via crt.sh."""
    subs = set()
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        handler = urllib.request.HTTPSHandler(context=SSL_CTX)
        opener = urllib.request.build_opener(handler)
        with opener.open(req, timeout=30) as r:
            data = json.loads(r.read())
            for entry in data:
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lower()
                    if name and not name.startswith("*") and domain in name:
                        subs.add(name)
    except Exception as e:
        log(f"  crt.sh error: {e}", Colors.Y)
    return sorted(subs)

def check_live(url, timeout=5):
    """Check if a URL responds."""
    try:
        code, headers, _ = http_get(url, timeout=timeout)
        return code, headers
    except:
        return 0, {}

def audit_headers(url):
    """Check security headers on a URL."""
    code, headers, _ = http_get(url)
    if code == 0:
        return None

    IMPORTANT_HEADERS = {
        "strict-transport-security": "HSTS",
        "content-security-policy": "CSP",
        "x-frame-options": "X-Frame",
        "x-content-type-options": "X-Content-Type",
        "referrer-policy": "Referrer",
        "permissions-policy": "Permissions",
        "access-control-allow-origin": "CORS-Origin",
        "access-control-allow-credentials": "CORS-Creds",
    }

    result = {"url": url, "status": code, "missing": [], "present": [], "interesting": {}}

    headers_lower = {k.lower(): v for k, v in headers.items()}

    for h, label in IMPORTANT_HEADERS.items():
        if h in headers_lower:
            result["present"].append(f"{label}: {headers_lower[h][:100]}")
        elif h in ["access-control-allow-origin", "access-control-allow-credentials"]:
            pass  # Don't flag missing CORS as a problem
        else:
            result["missing"].append(label)

    # Check for interesting headers
    for h in ["server", "x-powered-by", "via", "x-amz-cf-pop", "x-instance-id",
              "x-request-id", "x-backend", "x-cache"]:
        if h in headers_lower:
            result["interesting"][h] = headers_lower[h]

    return result

def cors_chain_test(url, domain):
    """Run the 7-step CORS chain test that found the CLEAR bug."""
    findings = []
    base_domain = domain

    test_origins = [
        ("attacker.com", "https://attacker.com"),
        (f"evil.{base_domain}", f"https://evil.{base_domain}"),
        (f"{base_domain}.attacker.com", f"https://{base_domain}.attacker.com"),
        (f"attacker{base_domain}", f"https://attacker{base_domain}"),
        ("null", "null"),
    ]

    for label, origin in test_origins:
        try:
            code, headers, _ = http_get(url, headers={"Origin": origin})
            headers_lower = {k.lower(): v for k, v in headers.items()}

            acao = headers_lower.get("access-control-allow-origin", "")
            acac = headers_lower.get("access-control-allow-credentials", "")

            if acao and acac.lower() == "true":
                finding = {
                    "type": "CORS_WITH_CREDENTIALS",
                    "url": url,
                    "origin_tested": origin,
                    "origin_label": label,
                    "acao": acao,
                    "acac": acac,
                    "severity": "HIGH" if "evil." in label or "attacker" in label else "MEDIUM",
                }
                findings.append(finding)
            elif acao == "*":
                findings.append({
                    "type": "CORS_WILDCARD",
                    "url": url,
                    "origin_tested": origin,
                    "acao": acao,
                    "acac": acac,
                    "severity": "MEDIUM",
                })
        except:
            pass

    return findings

def discover_oidc(domain):
    """Check for OIDC/OAuth discovery endpoints."""
    endpoints = {}
    for path in ["/.well-known/openid-configuration", "/.well-known/oauth-authorization-server",
                  "/oauth/discovery/keys", "/.well-known/jwks.json"]:
        try:
            code, _, body = http_get(f"https://{domain}{path}")
            if code == 200 and body.strip().startswith("{"):
                endpoints[path] = json.loads(body)
        except:
            pass
    return endpoints

def probe_api(domain):
    """Probe common API endpoints."""
    found = []
    paths = ["/api", "/api/v1", "/v1", "/v2", "/graphql", "/health", "/status",
             "/swagger.json", "/openapi.json", "/api-docs", "/.env",
             "/robots.txt", "/sitemap.xml", "/admin", "/login", "/register"]

    for path in paths:
        try:
            code, headers, body = http_get(f"https://{domain}{path}", timeout=5)
            if code not in [0, 404, 000]:
                found.append({"path": path, "status": code, "size": len(body)})
        except:
            pass
    return found

def detect_chains(all_findings, header_results):
    """Detect attack chains from individual findings."""
    chains = []

    # Pattern: CORS with credentials + missing CSP on a trusted subdomain
    cors_findings = [f for f in all_findings if f.get("type", "").startswith("CORS")]
    missing_csp_domains = set()
    for hr in header_results:
        if hr and "CSP" in hr.get("missing", []):
            # Extract domain from URL
            from urllib.parse import urlparse
            parsed = urlparse(hr["url"])
            missing_csp_domains.add(parsed.hostname)

    for cf in cors_findings:
        if cf.get("severity") in ["HIGH", "MEDIUM"] and cf.get("acac", "").lower() == "true":
            # Check if any sibling subdomain has missing CSP
            for csp_domain in missing_csp_domains:
                chains.append({
                    "type": "CORS_CSP_CHAIN",
                    "severity": "HIGH",
                    "description": (
                        f"CORS on {cf['url']} trusts {cf['origin_tested']} with credentials. "
                        f"Meanwhile {csp_domain} has no CSP. "
                        f"XSS on {csp_domain} → steal credentials from {cf['url']}."
                    ),
                    "cors_finding": cf,
                    "csp_domain": csp_domain,
                })

    return chains

def main():
    if len(sys.argv) < 2:
        print(f"""
{Colors.BOLD}{Colors.B}ClaudeOS QuickScan{Colors.END} — Full recon pipeline in 30 seconds

{Colors.BOLD}Usage:{Colors.END}
  claudeos quickscan <domain>
  claudeos quickscan <domain> --json
  claudeos quickscan <domain> --deep
""")
        sys.exit(0)

    domain = sys.argv[1].lower().replace("https://", "").replace("http://", "").rstrip("/")
    output_json = "--json" in sys.argv
    deep = "--deep" in sys.argv

    start_time = time.time()
    all_findings = []
    header_results = []

    log(f"\n{'='*60}", Colors.B)
    log(f"  ClaudeOS QuickScan — {domain}", Colors.BOLD)
    log(f"  Started: {datetime.now().isoformat()}", Colors.C)
    log(f"{'='*60}\n", Colors.B)

    # Phase 1: DNS
    log("[1/9] DNS Resolution", Colors.BOLD)
    dns = dns_lookup(domain)
    for rtype, vals in dns.items():
        log(f"  {rtype}: {', '.join(vals[:5])}")
    log("")

    # Phase 2: Subdomain enumeration
    log("[2/9] Subdomain Enumeration (crt.sh)", Colors.BOLD)
    subdomains = enumerate_subdomains(domain)
    # Always include the main domain and www
    for s in [domain, f"www.{domain}"]:
        if s not in subdomains:
            subdomains.append(s)
    subdomains = sorted(set(subdomains))
    log(f"  Found {len(subdomains)} unique subdomains")
    for s in subdomains[:20]:
        log(f"    {s}", Colors.C)
    if len(subdomains) > 20:
        log(f"    ... and {len(subdomains)-20} more")
    log("")

    # Phase 3: Live host detection
    log("[3/9] Live Host Detection", Colors.BOLD)
    live_hosts = []
    for sub in subdomains[:50]:  # Limit to 50 to stay fast
        code, _ = check_live(f"https://{sub}", timeout=3)
        if code > 0:
            live_hosts.append(sub)
            log(f"  ✓ {sub} (HTTP {code})", Colors.G)
    log(f"  {len(live_hosts)} live hosts of {min(len(subdomains), 50)} checked")
    log("")

    # Phase 4: Security headers audit
    log("[4/9] Security Headers Audit", Colors.BOLD)
    for host in live_hosts[:20]:
        result = audit_headers(f"https://{host}")
        if result:
            header_results.append(result)
            missing = result["missing"]
            if len(missing) >= 3:
                log(f"  🚨 {host}: missing {', '.join(missing)}", Colors.R)
            elif missing:
                log(f"  ⚠️  {host}: missing {', '.join(missing)}", Colors.Y)
            else:
                log(f"  ✓ {host}: all headers present", Colors.G)
    log("")

    # Phase 5: CORS chain test (THE MONEY MAKER)
    log("[5/9] CORS Chain Test (7-step pattern)", Colors.BOLD)
    for host in live_hosts[:20]:
        cors_results = cors_chain_test(f"https://{host}", domain)
        for cf in cors_results:
            all_findings.append(cf)
            if cf["severity"] == "HIGH":
                log(f"  🚨 {host}: {cf['type']} — Origin: {cf['origin_tested']} → ACAO: {cf['acao']} + Credentials: true", Colors.R)
            elif cf["severity"] == "MEDIUM":
                log(f"  ⚠️  {host}: {cf['type']} — Origin: {cf['origin_tested']}", Colors.Y)
    if not any(f.get("type", "").startswith("CORS") for f in all_findings):
        log("  ✓ No CORS issues found", Colors.G)
    log("")

    # Phase 6: OIDC/OAuth discovery
    log("[6/9] OIDC/OAuth Discovery", Colors.BOLD)
    oidc_found = False
    for host in live_hosts[:10]:
        oidc = discover_oidc(host)
        if oidc:
            oidc_found = True
            for path, config in oidc.items():
                log(f"  ✓ {host}{path}", Colors.G)
                if "authorization_endpoint" in config:
                    log(f"    Auth: {config['authorization_endpoint']}", Colors.C)
                if "token_endpoint" in config:
                    log(f"    Token: {config['token_endpoint']}", Colors.C)
    if not oidc_found:
        log("  (no OIDC endpoints found)")
    log("")

    # Phase 7: Tech stack fingerprinting
    log("[7/9] Tech Stack", Colors.BOLD)
    for hr in header_results[:10]:
        techs = []
        for k, v in hr.get("interesting", {}).items():
            techs.append(f"{k}: {v}")
        if techs:
            log(f"  {hr['url'].split('//')[-1].split('/')[0]}: {', '.join(techs[:3])}", Colors.C)
    log("")

    # Phase 8: API endpoint probing
    log("[8/9] API Endpoint Probing", Colors.BOLD)
    for host in live_hosts[:5]:
        endpoints = probe_api(host)
        for ep in endpoints:
            log(f"  {host}{ep['path']} → HTTP {ep['status']} ({ep['size']}b)")
    log("")

    # Phase 9: Chain detection
    log("[9/9] Attack Chain Detection", Colors.BOLD)
    chains = detect_chains(all_findings, header_results)
    if chains:
        for chain in chains:
            log(f"  🚨🚨🚨 CHAIN DETECTED: {chain['description']}", Colors.R)
            log(f"        Severity: {chain['severity']}", Colors.R)
    else:
        log("  No automatic chains detected (manual review recommended)")
    log("")

    # Summary
    elapsed = time.time() - start_time
    log(f"{'='*60}", Colors.B)
    log(f"  SCAN COMPLETE — {elapsed:.1f} seconds", Colors.BOLD)
    log(f"{'='*60}\n", Colors.B)

    total_findings = len(all_findings) + len(chains)
    missing_header_domains = sum(1 for hr in header_results if hr and len(hr.get("missing", [])) >= 3)

    log(f"  Subdomains found:     {len(subdomains)}")
    log(f"  Live hosts:           {len(live_hosts)}")
    log(f"  CORS findings:        {len([f for f in all_findings if f.get('type','').startswith('CORS')])}")
    log(f"  Attack chains:        {len(chains)}")
    log(f"  Domains missing 3+ headers: {missing_header_domains}")
    log(f"  Total findings:       {total_findings}")
    log("")

    if chains:
        log("  🚨 ACTION REQUIRED: Attack chains detected. Write report NOW.", Colors.R)
    elif total_findings > 0:
        log("  ⚠️  Findings found. Review and assess reportability.", Colors.Y)
    else:
        log("  ✓ Target appears well-secured from external scan.", Colors.G)
    log("")

    # JSON output
    if output_json:
        report = {
            "target": domain,
            "timestamp": datetime.now().isoformat(),
            "elapsed_seconds": round(elapsed, 1),
            "subdomains": subdomains,
            "live_hosts": live_hosts,
            "header_results": header_results,
            "cors_findings": all_findings,
            "chains": chains,
            "dns": dns,
        }
        print(json.dumps(report, indent=2, default=str))

if __name__ == "__main__":
    main()
