"""
Wolf Alpha — ClaudeOS Command Center
The Alpha's throne. See every wolf. Command every hunt. Lead the pack.
"""

import os
import json
import glob
from pathlib import Path
from flask import Flask, render_template, jsonify, request

BASE_DIR = Path(__file__).resolve().parent
AGENTS_DIR = BASE_DIR.parent / "agents"

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
)
app.secret_key = "wolfden-claudeos-2026"


def scan_agents():
    """Scan the agents directory and build the pack registry."""
    agents = []
    agent_dirs = sorted(AGENTS_DIR.iterdir()) if AGENTS_DIR.exists() else []

    # Define sectors and their agents
    sectors = {
        "Elite Wolves": {
            "color": "#ff0040",
            "agents": ["shadow-recon", "phantom-auth", "code-weaponizer", "chain-builder", "time-traveler", "wallet-breaker"]
        },
        "Intelligence": {
            "color": "#00d4ff",
            "agents": ["incident-responder", "performance-tuner", "cost-optimizer", "migration", "threat-intel"]
        },
        "Scouts": {
            "color": "#00ff88",
            "agents": ["subdomain-bruteforcer", "tech-stack-detector", "dns-manager", "osint-gatherer",
                       "github-recon", "shodan-pivoter", "s3-bucket-finder", "cloud-recon", "recon-master",
                       "recon-orchestrator", "screenshot-hunter"]
        },
        "Infiltrators": {
            "color": "#ffaa00",
            "agents": ["js-endpoint-extractor", "js-analyzer", "sourcemap-extractor", "config-extractor",
                       "swagger-extractor", "git-extractor", "metadata-extractor", "apk-extractor",
                       "error-extractor", "headless-browser"]
        },
        "Analysts": {
            "color": "#aa44ff",
            "agents": ["waf-fingerprinter", "waf-rule-analyzer", "waf-bypass-scanner", "waf-cloudflare-bypass",
                       "waf-akamai-bypass", "waf-aws-bypass", "waf-modsecurity-bypass", "waf-imperva-bypass",
                       "waf-custom-bypass", "waf-payload-encoder", "waf-protocol-bypass",
                       "token-analyzer", "cookie-security-auditor", "csp-analyzer"]
        },
        "Strikers": {
            "color": "#ff4444",
            "agents": ["xss-hunter", "sqli-hunter", "ssrf-hunter", "idor-hunter", "cors-tester",
                       "cors-chain-analyzer", "graphql-hunter", "jwt-hunter", "xxe-hunter",
                       "ssti-hunter", "lfi-hunter", "csrf-hunter", "request-smuggler",
                       "race-hunter", "cache-poisoner", "prototype-pollution-hunter",
                       "oauth-tester", "saml-tester", "deserialization-hunter",
                       "blind-injection-tester", "param-finder", "websocket-tester",
                       "postmessage-abuser", "account-takeover-hunter", "password-reset-tester",
                       "ecommerce-hunter", "business-logic-hunter"]
        },
        "Infrastructure": {
            "color": "#44aaff",
            "agents": ["network-mapper", "ssl-tester", "vulnerability-scanner", "cdn-bypass",
                       "origin-finder", "docker-manager", "kubernetes-tester", "container-escape",
                       "aws-tester"]
        },
        "Stealth & Support": {
            "color": "#888888",
            "agents": ["evasion-engine", "proxy-rotator", "poc-recorder", "bounty-report-writer",
                       "nuclei-template-builder", "nuclei-master", "response-differ",
                       "collaborator", "payload-crafter", "tool-forge"]
        },
        "Red Team": {
            "color": "#ff2200",
            "agents": ["red-commander", "attack-planner", "defense-breaker", "persistence-agent",
                       "lateral-mover", "exfil-operator", "implant-builder", "vuln-weaponizer",
                       "phishing-operator", "arsenal-manager", "blue-team-tester",
                       "attack-chain", "c2-operator", "apt-operator"]
        },
        "Platform Hunters": {
            "color": "#ff8800",
            "agents": ["wordpress-hunter", "drupal-hunter", "magento-hunter", "laravel-hunter",
                       "django-hunter", "shopify-hunter", "okta-tester", "m365-attacker",
                       "stripe-webhook-tester"]
        },
        "Core System": {
            "color": "#66bb6a",
            "agents": ["package-manager", "service-manager", "security", "network", "monitoring",
                       "backup", "cron-tasks", "user-manager", "auto-pilot", "web-server",
                       "database", "mail-server"]
        },
        "Builders": {
            "color": "#42a5f5",
            "agents": ["code-generator", "api-builder", "api-designer", "database-designer",
                       "test-writer", "documentation", "git-deploy", "pipeline-builder",
                       "agent-architect", "technique-inventor", "capability-scanner"]
        },
        "Defense": {
            "color": "#26c6da",
            "agents": ["ddos-shield", "defense-monitor", "firewall-visualizer", "security-auditor",
                       "config-hardener", "access-auditor", "encryption-enforcer", "compliance",
                       "compliance-checker", "honeypot-manager", "log-forensics", "incident-logger"]
        }
    }

    # Build agent list from actual directories
    existing_dirs = {d.name for d in agent_dirs if d.is_dir()}
    agent_id = 0

    for sector_name, sector_info in sectors.items():
        for agent_name in sector_info["agents"]:
            has_file = agent_name in existing_dirs
            claude_md = AGENTS_DIR / agent_name / "CLAUDE.md"
            lines = 0
            description = ""
            if claude_md.exists():
                content = claude_md.read_text()
                lines = len(content.split("\n"))
                # Extract first meaningful line as description
                for line in content.split("\n"):
                    if line.startswith(">") and len(line) > 10:
                        description = line.strip("> ").strip('"').strip()
                        break

            agents.append({
                "id": agent_id,
                "name": agent_name,
                "display_name": agent_name.replace("-", " ").title(),
                "sector": sector_name,
                "color": sector_info["color"],
                "exists": has_file,
                "lines": lines,
                "description": description,
                "status": "idle",
            })
            agent_id += 1

    # Add remaining agents not in sectors
    categorized = set()
    for sector_info in sectors.values():
        categorized.update(sector_info["agents"])

    for d in agent_dirs:
        if d.is_dir() and d.name not in categorized and not d.name.startswith("."):
            claude_md = d / "CLAUDE.md"
            lines = 0
            if claude_md.exists():
                lines = len(claude_md.read_text().split("\n"))
            agents.append({
                "id": agent_id,
                "name": d.name,
                "display_name": d.name.replace("-", " ").title(),
                "sector": "Other",
                "color": "#555555",
                "exists": True,
                "lines": lines,
                "description": "",
                "status": "idle",
            })
            agent_id += 1

    return agents


def get_pack_stats(agents):
    """Calculate pack statistics."""
    total = len(agents)
    existing = sum(1 for a in agents if a["exists"])
    total_lines = sum(a["lines"] for a in agents)
    sectors = {}
    for a in agents:
        s = a["sector"]
        if s not in sectors:
            sectors[s] = {"count": 0, "color": a["color"]}
        sectors[s]["count"] += 1

    elite = [a for a in agents if a["sector"] == "Elite Wolves"]

    return {
        "total_agents": total,
        "existing_agents": existing,
        "total_lines": total_lines,
        "sectors": sectors,
        "elite_count": len(elite),
        "elite_lines": sum(a["lines"] for a in elite),
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    agents = scan_agents()
    stats = get_pack_stats(agents)
    return render_template("index.html", stats=stats)


@app.route("/api/agents")
def api_agents():
    agents = scan_agents()
    return jsonify(agents)


@app.route("/api/stats")
def api_stats():
    agents = scan_agents()
    return jsonify(get_pack_stats(agents))


@app.route("/api/agent/<name>")
def api_agent_detail(name):
    claude_md = AGENTS_DIR / name / "CLAUDE.md"
    if not claude_md.exists():
        return jsonify({"error": "Agent not found"}), 404
    content = claude_md.read_text()
    return jsonify({
        "name": name,
        "display_name": name.replace("-", " ").title(),
        "content": content,
        "lines": len(content.split("\n")),
    })


@app.route("/api/sectors")
def api_sectors():
    agents = scan_agents()
    sectors = {}
    for a in agents:
        s = a["sector"]
        if s not in sectors:
            sectors[s] = {"color": a["color"], "agents": []}
        sectors[s]["agents"].append(a)
    return jsonify(sectors)


# ---------------------------------------------------------------------------
# Recon API — Wolves that actually hunt
# ---------------------------------------------------------------------------
import subprocess
import socket
import re
import threading

# Thread-safe findings storage
hunt_findings = []
hunt_lock = threading.Lock()
hunt_active = False
hunt_target = ""


def add_finding(wolf, category, data):
    with hunt_lock:
        hunt_findings.append({
            "wolf": wolf,
            "category": category,
            "data": data,
            "time": __import__('datetime').datetime.now().strftime("%H:%M:%S"),
        })


def wolf_dns_recon(target):
    """Shadow Recon — DNS records."""
    try:
        # A records
        result = subprocess.run(["dig", "+short", target, "A"], capture_output=True, text=True, timeout=10)
        for ip in result.stdout.strip().split("\n"):
            if ip.strip():
                add_finding("Shadow Recon", "DNS A Record", ip.strip())

        # MX records
        result = subprocess.run(["dig", "+short", target, "MX"], capture_output=True, text=True, timeout=10)
        for mx in result.stdout.strip().split("\n"):
            if mx.strip():
                add_finding("Shadow Recon", "Mail Server", mx.strip())

        # TXT records
        result = subprocess.run(["dig", "+short", target, "TXT"], capture_output=True, text=True, timeout=10)
        for txt in result.stdout.strip().split("\n"):
            if txt.strip() and len(txt) > 5:
                add_finding("Shadow Recon", "TXT Record", txt.strip()[:120])

        # NS records
        result = subprocess.run(["dig", "+short", target, "NS"], capture_output=True, text=True, timeout=10)
        for ns in result.stdout.strip().split("\n"):
            if ns.strip():
                add_finding("Shadow Recon", "Name Server", ns.strip())
    except Exception:
        pass


def wolf_http_recon(target):
    """Tech Stack Detector — HTTP headers and tech fingerprinting."""
    import urllib.request
    import ssl
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        url = f"https://{target}/"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        resp = urllib.request.urlopen(req, timeout=10, context=ctx)

        # Headers
        server = resp.headers.get("Server", "")
        if server:
            add_finding("Tech Stack Detector", "Server", server)

        powered = resp.headers.get("X-Powered-By", "")
        if powered:
            add_finding("Tech Stack Detector", "Powered By", powered)

        for h in ["X-Frame-Options", "Content-Security-Policy", "Strict-Transport-Security"]:
            val = resp.headers.get(h, "")
            if val:
                add_finding("Tech Stack Detector", f"Header: {h}", val[:100])
            else:
                add_finding("Tech Stack Detector", f"Missing Header", h)

        # Read body for tech detection
        body = resp.read(50000).decode("utf-8", errors="ignore")

        techs = {
            "React": "react" in body.lower() or "_next/" in body,
            "Vue.js": "vue" in body.lower() or "__vue" in body,
            "Angular": "ng-app" in body or "angular" in body.lower(),
            "jQuery": "jquery" in body.lower(),
            "WordPress": "wp-content" in body or "wp-json" in body,
            "Next.js": "_next/static" in body,
            "Laravel": "laravel" in body.lower(),
            "Django": "csrfmiddlewaretoken" in body,
            "Cloudflare": "cf-ray" in (resp.headers.get("cf-ray", "") or ""),
        }
        for tech, found in techs.items():
            if found:
                add_finding("Tech Stack Detector", "Technology", tech)

        # Title
        title_match = re.search(r"<title>([^<]{1,100})</title>", body, re.IGNORECASE)
        if title_match:
            add_finding("Tech Stack Detector", "Page Title", title_match.group(1).strip())

    except Exception as e:
        add_finding("Tech Stack Detector", "Error", str(e)[:80])


def wolf_subdomain_recon(target):
    """Recon Master — Certificate transparency subdomain discovery."""
    import urllib.request
    try:
        url = f"https://crt.sh/?q=%25.{target}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        resp = urllib.request.urlopen(req, timeout=15)
        data = json.loads(resp.read().decode())
        subs = set()
        for entry in data:
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lower()
                if name and "*" not in name and name != target:
                    subs.add(name)
        for sub in sorted(subs)[:30]:
            add_finding("Recon Master", "Subdomain", sub)
        if len(subs) > 30:
            add_finding("Recon Master", "Subdomains Total", f"{len(subs)} found (showing first 30)")
    except Exception:
        add_finding("Recon Master", "Info", "crt.sh unavailable or rate limited")


def wolf_port_scan(target):
    """Network Mapper — Quick port check on common ports."""
    common_ports = [21, 22, 25, 53, 80, 443, 3306, 5432, 8080, 8443, 8888, 9200]
    try:
        ip = socket.gethostbyname(target)
        add_finding("Network Mapper", "IP Address", ip)
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    service = {21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP",
                               443: "HTTPS", 3306: "MySQL", 5432: "PostgreSQL",
                               8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Alt2",
                               9200: "Elasticsearch"}.get(port, "Unknown")
                    add_finding("Network Mapper", f"Open Port", f"{port} ({service})")
                sock.close()
            except Exception:
                pass
    except Exception as e:
        add_finding("Network Mapper", "Error", str(e)[:80])


def run_hunt(target):
    """Run all wolves in sequence."""
    global hunt_active
    hunt_active = True
    add_finding("ALPHA", "Hunt Started", f"Target: {target}")

    add_finding("Shadow Recon", "Status", "Deploying... Ghost intelligence active")
    wolf_dns_recon(target)

    add_finding("Tech Stack Detector", "Status", "Deploying... Fingerprinting target")
    wolf_http_recon(target)

    add_finding("Recon Master", "Status", "Deploying... Searching certificate transparency")
    wolf_subdomain_recon(target)

    add_finding("Network Mapper", "Status", "Deploying... Scanning common ports")
    wolf_port_scan(target)

    add_finding("ALPHA", "Hunt Complete", f"{len(hunt_findings)} findings on {target}")
    hunt_active = False


@app.route("/api/hunt", methods=["POST"])
def api_hunt():
    global hunt_findings, hunt_target, hunt_active
    data = request.get_json() or {}
    target = data.get("target", "").strip()
    if not target:
        return jsonify({"error": "No target specified"}), 400
    if hunt_active:
        return jsonify({"error": "Hunt already in progress"}), 409

    # Clean domain
    target = target.replace("https://", "").replace("http://", "").split("/")[0]
    hunt_target = target

    with hunt_lock:
        hunt_findings = []

    # Run in background thread
    t = threading.Thread(target=run_hunt, args=(target,), daemon=True)
    t.start()

    return jsonify({"status": "Hunt started", "target": target})


@app.route("/api/findings")
def api_findings():
    with hunt_lock:
        return jsonify({
            "active": hunt_active,
            "target": hunt_target,
            "count": len(hunt_findings),
            "findings": list(hunt_findings),
        })


if __name__ == "__main__":
    print("\n" + "=" * 52)
    print("  WOLF ALPHA — ClaudeOS Command Center")
    print("=" * 52)
    print("  Open: http://localhost:5555")
    print("=" * 52 + "\n")
    app.run(host="0.0.0.0", port=5555, debug=True)
