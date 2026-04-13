<div align="center">

```
  ██████╗██╗      █████╗ ██╗   ██╗██████╗ ███████╗ ██████╗ ███████╗
 ██╔════╝██║     ██╔══██╗██║   ██║██╔══██╗██╔════╝██╔═══██╗██╔════╝
 ██║     ██║     ███████║██║   ██║██║  ██║█████╗  ██║   ██║███████╗
 ██║     ██║     ██╔══██║██║   ██║██║  ██║██╔══╝  ██║   ██║╚════██║
 ╚██████╗███████╗██║  ██║╚██████╔╝██████╔╝███████╗╚██████╔╝███████║
  ╚═════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝ ╚═════╝╚══════╝
```

### 300 AI Agents. One Command. Your Server, Your Rules.

**The largest AI-powered agent system ever built for Linux. Server management, bug bounty hunting, offensive security, and everything in between — all through natural language.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Agents](https://img.shields.io/badge/Agents-300-brightgreen.svg)]()
[![Ubuntu](https://img.shields.io/badge/Ubuntu-22.04+-orange.svg)]()
[![Debian](https://img.shields.io/badge/Debian-12+-red.svg)]()

**[Install](#install) | [What It Does](#what-can-it-do) | [All 300 Agents](#-300-specialist-agents) | [Bug Bounty](#-bug-bounty--proven-in-the-field) | [WAF Warfare](#-waf-warfare--11-agents) | [Pro Features](#-pro-features) | [Architecture](#architecture)**

</div>

---

## The Story

ClaudeOS started because memorizing Linux commands is stupid. You shouldn't need to remember `iptables -A INPUT -p tcp --dport 443 -j ACCEPT` when you can just say *"open port 443."*

Then it grew. Bug bounty hunters started using it. They said: *"What if it could also scan for vulnerabilities?"* So we built agents for that. Then pentesters wanted offensive tools. Gamers wanted Minecraft servers. DevOps wanted CI/CD pipelines.

Today ClaudeOS has **300 specialist AI agents** covering everything from setting up nginx to cracking WAFs to managing Minecraft servers. Every agent contains real, tested bash commands — not simulations, not theory. Real tools that work on real servers.

And it keeps getting better. ClaudeOS has a **self-improving engine** — when an agent fails, it detects why, fixes its own playbook, and commits the fix. The system literally learns from its mistakes.

---

## What Can It Do?

```bash
# Just talk to it
$ claudeos
> "harden this server"
> "why is the database slow?"
> "scan example.com for vulnerabilities"
> "set up a Minecraft server with 8GB RAM"
> "find XSS on this website"
> "deploy my app from GitHub with zero downtime"
> "alert me on Telegram if CPU hits 90%"
```

### Quick Examples

| You say... | ClaudeOS does... |
|---|---|
| *"update everything"* | Runs apt update, upgrades packages, checks for reboot |
| *"why is nginx throwing 502?"* | Reads logs, diagnoses upstream issue, suggests fix |
| *"scan my server for vulnerabilities"* | Runs full CVE scan, checks configs, reports findings |
| *"test this site for CORS bugs"* | Runs 7-origin CORS chain test, generates PoC if found |
| *"crack this WAF"* | Fingerprints WAF vendor, runs vendor-specific bypass techniques |
| *"decompile this APK and find secrets"* | jadx decompile, extracts API keys, Firebase URLs, endpoints |
| *"back up everything to S3"* | Configures rsnapshot, S3 sync, cron schedule, retention |
| *"set up CS2 server for 20 players"* | SteamCMD install, config, firewall rules, auto-restart |

---

## Install

### Quick Install (Ubuntu/Debian)
```bash
curl -fsSL https://raw.githubusercontent.com/MuLTiAcidi/claudeos/main/install.sh | sudo bash
```

### From Source
```bash
git clone https://github.com/MuLTiAcidi/claudeos.git
cd claudeos
sudo bash install.sh
```

### ISO Install (Bare Metal)
```bash
cd iso-builder && bash build-in-docker.sh
# Flash output/claudeos.iso to USB → boot → install
```

### Editions

| Edition | For | Install Flag |
|---|---|---|
| Server | VPS, cloud, headless | `--server` (default) |
| Dashboard | Remote management via browser | `--dashboard` |
| Desktop | Workstations with monitors | `--desktop` |
| Kiosk | Monitoring screens | `--kiosk` |
| Multi-Node | Managing server fleets | `--multi-node` |
| Raspberry Pi | ARM boards, home servers | `--pi` |

**Requirements:** Ubuntu 22.04+ or Debian 12+, 512MB RAM, 5GB disk, Node.js 20+

---

## Architecture

ClaudeOS has **4 layers**. No daemons. No message buses. Everything is Markdown files and bash.

```
┌───────────────────────────────────────────────────────┐
│  YOU        "scan this server for vulns"              │
└──────────────────────┬────────────────────────────────┘
                       ▼
┌───────────────────────────────────────────────────────┐
│  ORCHESTRATOR  (CLAUDE.md)                            │
│  Reads your request → picks the right agent(s) →     │
│  coordinates multi-agent workflows                   │
└──────────────────────┬────────────────────────────────┘
                       ▼
┌───────────────────────────────────────────────────────┐
│  300 SPECIALIST AGENTS  (agents/{name}/CLAUDE.md)     │
│  Each one is a Markdown playbook with real commands   │
│  Loaded on demand. Nothing runs in the background.   │
└──────────────────────┬────────────────────────────────┘
                       ▼
┌───────────────────────────────────────────────────────┐
│  BASH EXECUTOR  (Claude Code's terminal)              │
│  Runs commands, confirms destructive ops, logs all   │
└───────────────────────────────────────────────────────┘
```

**Key insight:** Agents are knowledge, not processes. Each agent is a Markdown file full of expert knowledge and real commands. You can read any agent to see exactly what it will do. No black boxes.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full technical breakdown.

---

## Bug Bounty — Proven in the Field

ClaudeOS isn't theoretical. It's been used on **real HackerOne programs** and found **real vulnerabilities**:

- **CORS data exfiltration** on an adult platform — user favorites and viewing history exposed cross-origin (submitted to H1)
- **Unauthenticated admin config center** on OPPO's e-commerce platform — H1 pre-check rated it **CRITICAL (CVSS 9.9)** (submitted to H1)
- **CORS vulnerability (CVSS 8.1)** on a major identity verification platform (submitted to H1, report #3668556)
- **7 security findings** on a major chat platform (disclosed via responsible disclosure)
- **HTML injection** on a major European e-commerce platform (browser-verified)

The tools we use to hunt are the tools we ship. Every agent in the Bug Bounty, WAF Warfare, and Extractor categories was born from real hunting sessions where we needed a tool that didn't exist — so we built it.

---

## 300 Specialist Agents

The largest agent collection ever built for a Linux system. Every agent contains **real working commands** — no simulations. Organized into sectors:

### System Management (52 agents)

<details>
<summary><b>Core System (9)</b> — Package, service, network, monitoring, backup, cron, user, security, auto-pilot</summary>

- **Package Manager** — Install, update, remove software
- **Service Manager** — Manage systemd services
- **Security Agent** — Firewall, fail2ban, SSH hardening, audits
- **Network Agent** — IP, DNS, ports, SSL certificates
- **Monitoring Agent** — CPU, RAM, disk, processes, logs
- **Backup Agent** — Scheduled backups, restore, remote sync
- **Cron/Task Agent** — Scheduled jobs, automation
- **User Manager** — Users, groups, SSH keys, permissions
- **Auto-Pilot** — Autonomous self-monitoring and self-healing
</details>

<details>
<summary><b>Infrastructure (6)</b> — Docker, database, web server, DNS, mail, WHMCS</summary>

- **Docker Manager** — Containers, compose, images, volumes
- **Database Agent** — MySQL/PostgreSQL tuning, queries, replication
- **Web Server Agent** — Nginx/Apache vhosts, SSL, performance
- **DNS Manager** — DNS zones, records, Cloudflare/Route53
- **Mail Server** — Postfix/Dovecot, spam, DKIM/SPF/DMARC
- **WHMCS Doctor** — WHMCS incident response: stuck crons, metadata locks, log table pruning
</details>

<details>
<summary><b>Intelligence (4)</b> — Incident response, performance, cost, migration</summary>

- **Incident Responder** — Root cause analysis, playbooks, post-mortems
- **Performance Tuner** — Sysctl, MySQL, Nginx, PHP-FPM optimization
- **Cost Optimizer** — Cloud right-sizing, waste detection
- **Migration Agent** — Move sites/apps between servers
</details>

<details>
<summary><b>DevOps (3)</b> — Git deploy, environment, multi-server</summary>

- **Git Deploy** — CI/CD, zero-downtime deploys, rollback
- **Environment Manager** — .env files, secrets, variables
- **Multi-Server** — Fleet management, parallel commands
</details>

<details>
<summary><b>Monitoring & Alerts (5)</b> — Notifications, logs, SSL, snapshots, compliance</summary>

- **Notifications** — Telegram, email, Slack, Discord alerts
- **Log Aggregator** — Centralized log search and analysis
- **SSL Watchdog** — Cert expiry, domain health, uptime
- **Snapshot Manager** — Pre-change snapshots, rollback
- **Compliance** — CIS, GDPR, PCI-DSS, SOC 2 checks
</details>

<details>
<summary><b>Advanced Operations (6)</b> — Firewall viz, crontab audit, process forensics, capacity, API gateway, containers</summary>

- **Firewall Visualizer** — Map rules, detect conflicts
- **Crontab Auditor** — Find dead jobs, optimize scheduling
- **Process Forensics** — Deep process inspection, anomaly detection
- **Capacity Planner** — Predict resource exhaustion
- **API Gateway** — Rate limiting, API keys, reverse proxy
- **Container Orchestrator** — Docker Swarm clusters
</details>

<details>
<summary><b>Network & Infrastructure (9)</b> — VPN, proxy, bandwidth, k8s, cloud, firewall, files, profiler, updates</summary>

- **VPN Manager** — WireGuard, OpenVPN setup and management
- **Proxy Manager** — Nginx, HAProxy, SOCKS5, Tor, Privoxy
- **Bandwidth Monitor** — Real traffic monitoring and throttling
- **Cluster Manager** — Kubernetes (kubeadm, k3s), Docker Swarm
- **Cloud Deployer** — AWS, GCP, Azure, DigitalOcean, Terraform
- **Firewall Architect** — Complex iptables/nftables/UFW rulesets
- **File Manager** — Advanced file ops, search, bulk operations
- **System Profiler** — Hardware inventory and benchmarking
- **Update Manager** — OS updates with snapshots and rollback
</details>

<details>
<summary><b>Automation (15)</b> — Scripts, cron, webhooks, tasks, file watch, events, API, email, reports, deploy, notifications, retry, triggers, batch</summary>

- **Script Builder** — Generate bash/python automation scripts
- **Cron Master** — Advanced cron orchestration with dependencies
- **Webhook Listener** — Receive webhooks with HMAC validation
- **Task Automator** — Chain actions into workflows
- **File Watcher** — inotify-based file monitoring
- **Event Reactor** — React to system events automatically
- **API Automator** — REST/GraphQL pipelines with auth
- **Email Automator** — Postfix, procmail, sieve, IMAP automation
- **Report Generator** — Automated system/security reports
- **Cleanup Automator** — Scheduled temp/log/cache cleanup
- **Deploy Automator** — Full deployment pipelines with rollback
- **Notification Router** — Multi-channel routing with rules
- **Retry Engine** — Exponential backoff, DLQ, circuit breaker
- **Trigger Builder** — Custom if-X-then-Y triggers
- **Batch Processor** — Parallel batch jobs across servers
</details>

### Development (8 agents)

<details>
<summary><b>Coder (8)</b> — Code gen, debug, refactor, API design, DB design, testing, deps, docs</summary>

- **Code Generator** — Scaffold projects (Node, Python, Go, Rust)
- **Debugger** — gdb, strace, valgrind, perf profiling
- **Refactorer** — Complexity analysis, dead code, AST refactoring
- **API Designer** — OpenAPI, GraphQL, REST design
- **Database Designer** — Schema design, migrations, optimization
- **Test Writer** — pytest, Jest, Go testing, coverage
- **Dependency Manager** — npm/pip/cargo audit, updates
- **Doc Generator** — Sphinx, JSDoc, godoc, MkDocs
</details>

### Auto-Repair (7 agents)

<details>
<summary><b>Fixer (7)</b> — Auto-heal, config fix, deps, logs, network, boot, database</summary>

- **Auto Healer** — Self-heal failing services
- **Config Fixer** — Detect and fix misconfigurations
- **Dependency Resolver** — Fix broken apt/pip/npm dependencies
- **Log Doctor** — Diagnose issues from log patterns
- **Network Healer** — Auto-fix DNS, routing, firewall, DHCP
- **Boot Fixer** — GRUB, initramfs, fstab repair
- **Database Repair** — MySQL/PostgreSQL/MongoDB recovery
</details>

### Uptime & Resilience (8 agents)

<details>
<summary><b>Always Up (8)</b> — Monitoring, failover, load balancing, chaos, DDoS, restart, redundancy, heartbeat</summary>

- **Uptime Guardian** — 24/7 monitoring with instant alerts
- **Failover Manager** — Keepalived/VRRP, HAProxy failover
- **Load Balancer** — Nginx/HAProxy load balancing
- **Chaos Tester** — Real chaos engineering with stress-ng, tc netem
- **DDoS Shield** — Detection and automatic mitigation
- **Auto Restarter** — Smart restart with backoff strategies
- **Redundancy Manager** — DRBD, GlusterFS, Pacemaker, replicas
- **Heartbeat Monitor** — Lightweight ICMP/TCP/HTTP checks
</details>

### Game Servers (8 agents)

<details>
<summary><b>Gamer (8)</b> — Universal game server, Minecraft, Steam/CS2, performance, players, mods, backups, Discord</summary>

- **Game Server Manager** — Universal game server lifecycle
- **Minecraft Server** — Paper/Spigot/Fabric, plugins, JVM tuning
- **Steam Server** — SteamCMD games (CS2, Valheim, Rust, ARK)
- **Game Performance** — Tick rate, FPS, Aikar's flags
- **Player Manager** — Bans, whitelists, RCON, LuckPerms
- **Mod Manager** — Workshop downloads, conflict resolution
- **Game Backup** — Hot world backups, rsnapshot, S3 sync
- **Discord Bot Manager** — Game-Discord bridge bots
</details>

---

### Security — Defensive (13 agents)

<details>
<summary><b>White Hat (13)</b> — Vulnerability scanning, auditing, hardening, compliance</summary>

- **Vulnerability Scanner** — Automated CVE scanning
- **Security Auditor** — CIS benchmarks, Lynis, OpenSCAP
- **Password Auditor** — Test password strength
- **Web App Scanner** — OWASP Top 10 testing
- **SSL Tester** — Deep TLS analysis, cipher suites
- **Network Mapper** — nmap, masscan, topology discovery
- **Patch Validator** — Verify security patches
- **Log Forensics** — Detect suspicious patterns
- **Config Hardener** — Auto-harden SSH, kernel, services
- **Access Auditor** — Users, sudo, SUID, ACLs
- **Encryption Enforcer** — LUKS, TLS, GPG enforcement
- **Compliance Checker** — PCI-DSS, HIPAA, SOC2, GDPR
- **Incident Logger** — Real-time logging with chain of custody
</details>

### Security — Offensive (41 agents)

> All offensive agents require authorization. See [Safety & Authorization](#safety--authorization).

<details>
<summary><b>Grey Hat — Security Research (11)</b></summary>

- **Zero Day Hunter** — AFL++, libFuzzer, Boofuzz fuzzing
- **Reverse Engineer** — radare2, Ghidra binary analysis
- **Traffic Analyzer** — tcpdump, tshark deep packet inspection
- **Exploit Researcher** — Searchsploit, Metasploit, CVE research
- **Bug Bounty Hunter** — Subfinder, amass, httpx, nuclei pipelines
- **Credential Tester** — Hydra, medusa, CrackMapExec
- **WiFi Breaker** — Aircrack-ng, hashcat WPA cracking
- **DNS Poisoner** — DNS spoofing, cache poisoning
- **Session Hijacker** — Bettercap, mitmproxy, token analysis
- **API Fuzzer** — ffuf, wfuzz, GraphQL/REST fuzzing
- **OSINT Gatherer** — theHarvester, Shodan, recon-ng
</details>

<details>
<summary><b>Black Hat — Offensive Security (12)</b></summary>

- **Attack Chain** — Multi-stage attack workflows
- **Malware Analyst** — Reverse engineer malware
- **Data Exfiltrator** — DNS/ICMP/stego exfil testing
- **Ransomware Tester** — Backup recovery validation
- **APT Operator** — Persistent access campaigns
- **Social Engineer** — GoPhish, SET, phishing tests
- **Backdoor Hunter** — Find and plant test backdoors
- **Keylogger Deployer** — Logkeys, PAM tty_audit
- **Rootkit Builder** — LKM/userspace rootkits
- **C2 Operator** — Sliver, Mythic, custom C2
- **Cryptojacker** — Mining injection/detection
- **Supply Chain Attacker** — Dependency confusion
</details>

<details>
<summary><b>Red Team (15)</b> — Full red team operations</summary>

- **Red Commander** — Orchestrate full operations
- **Attack Planner** — Multi-vector strategy
- **Defense Breaker** — Bypass firewalls, IDS, WAF, EDR
- **Tool Forge** — Build custom exploits
- **Recon Master** — Deep OSINT, fingerprinting
- **Persistence Agent** — Maintain access
- **Lateral Mover** — SSH/network pivoting
- **Exfil Operator** — Multi-channel extraction
- **Evasion Engine** — AV/IDS/WAF/EDR bypass
- **Implant Builder** — Custom RATs
- **Vuln Weaponizer** — CVEs to exploits
- **Phishing Operator** — GoPhish campaigns
- **Report Writer** — Pro pentest reports
- **Blue Team Tester** — Purple team exercises
- **Arsenal Manager** — MITRE ATT&CK mapping
</details>

<details>
<summary><b>Stealth (3)</b> — Authorized red team only</summary>

- **Trace Cleaner** — Clean logs, history
- **Tunnel Builder** — SSH/socat/chisel tunnels
- **Identity Rotator** — MAC/IP/DNS rotation
</details>

---

### Bug Bounty (47 agents)

<details>
<summary><b>Pro Toolkit (19)</b> — The core bug bounty arsenal</summary>

- **Subdomain Takeover** — Subjack, Subzy, nuclei templates
- **JS Analyzer** — LinkFinder, SecretFinder, JSluice
- **XSS Hunter** — dalfox, XSStrike, blind XSS callbacks
- **SQLi Hunter** — sqlmap, ghauri, NoSQL, WAF bypass
- **SSRF Hunter** — interactsh, cloud metadata
- **IDOR Hunter** — Parameter tampering, ID enumeration
- **GraphQL Hunter** — Introspection, batching, depth attacks
- **JWT Hunter** — jwt_tool, alg none, key confusion
- **CORS Tester** — CORStest, Corsy
- **Request Smuggler** — CL.TE, TE.CL, h2c
- **Race Hunter** — Single-packet attacks
- **Cache Poisoner** — Param Miner methodology
- **Param Finder** — Arjun, ParamSpider, x8
- **GitHub Recon** — trufflehog, gitleaks
- **Cloud Recon** — S3, IAM, GCP, Azure misconfigs
- **Collaborator** — interactsh-server
- **Nuclei Master** — Template management
- **Screenshot Hunter** — gowitness, aquatone
- **Payload Crafter** — Custom payloads, shellcode
</details>

<details>
<summary><b>Advanced Vuln Classes (8)</b> — XXE, SSTI, LFI, deser, OAuth, SAML, prototype pollution, CSRF</summary>

- **XXE Hunter** — XML External Entity (file read, blind, OOB)
- **SSTI Hunter** — Jinja, Twig, Velocity, Freemarker
- **LFI Hunter** — File inclusion + log poisoning
- **Deserialization Hunter** — Java/PHP/Python/.NET
- **OAuth Tester** — redirect_uri, state, PKCE, scope
- **SAML Tester** — XSW1-XSW8, signature wrapping
- **Prototype Pollution Hunter** — Server + client side
- **CSRF Hunter** — Token validation, SameSite bypass
</details>

<details>
<summary><b>CMS & Framework Hunters (5)</b> — WordPress, Drupal, Magento, Laravel, Django</summary>

- **WordPress Hunter** — wpscan, plugin CVEs, xmlrpc
- **Drupal Hunter** — Drupalgeddon, droopescan
- **Magento Hunter** — Trojan Order, Cosmic Sting, Magecart
- **Laravel Hunter** — .env, Ignition RCE, APP_KEY
- **Django Hunter** — DEBUG=True, SECRET_KEY RCE
</details>

<details>
<summary><b>Platform Specialists (6)</b> — Shopify, M365, Okta, ATO, e-commerce, JS extraction</summary>

- **Shopify Hunter** — Theme XSS, OAuth, checkout bypass
- **M365 Attacker** — Azure AD, password spray, FOCI
- **Okta Tester** — SSO fingerprinting, MFA bypass
- **Account Takeover Hunter** — Password reset, OTP bypass, OAuth hijack, 2FA bypass
- **E-Commerce Hunter** — Price manipulation, payment bypass, coupon abuse
- **JS Endpoint Extractor** — Extract hidden APIs from compiled JS bundles in SPAs
</details>

<details>
<summary><b>Web Vuln Specialists (4)</b> — WebSocket, postMessage, webhooks, CSP</summary>

- **WebSocket Tester** — Auth bypass, CSWSH, message injection
- **postMessage Abuser** — Origin validation flaws, eval sinks
- **Stripe Webhook Tester** — Payment signature validation
- **CSP Analyzer** — unsafe-inline, wildcard, JSONP bypass
</details>

<details>
<summary><b>Workflow (5)</b> — Tracking, monitoring, dedup, recon orchestration, report writing</summary>

- **Vuln Tracker** — SQLite finding tracker with payouts
- **Program Monitor** — Watch platforms for scope changes
- **Dupe Checker** — Pre-report duplicate screening
- **Recon Orchestrator** — Master recon pipeline
- **Bounty Report Writer** — Auto-format for H1/Bugcrowd templates
</details>

---

### Extractor Suite (8 agents)

> **Born from real hunting.** When standard scanning hits a wall, extractors crack open what's hidden.

<details>
<summary><b>Extractors (8)</b> — The tools that find what scanning can't</summary>

- **JS Endpoint Extractor** — Download compiled JS bundles from SPAs, extract every API endpoint, secret, internal domain. **This agent cracked open OPPO's Nuxt.js app to reveal 66 hidden API endpoints and an unauthenticated admin config center.**
- **Source Map Extractor** — Find .js.map files, reconstruct original unminified source code
- **APK Extractor** — Decompile Android APKs with jadx, extract API keys, Firebase URLs, endpoints
- **Config Extractor** — Hunt for .env, config.js, application.yml, phpinfo, debug endpoints
- **Swagger Extractor** — Find hidden Swagger/OpenAPI/GraphQL docs even behind WAFs
- **Error Extractor** — Trigger errors to harvest stack traces, internal paths, DB versions
- **Git Extractor** — Exploit exposed .git directories, reconstruct repos, find secrets in history
- **Metadata Extractor** — EXIF, PDF, Office metadata: usernames, GPS, internal paths
</details>

---

### WAF Warfare (11 agents)

> **The first comprehensive WAF bypass toolkit in any AI agent system.** Every major WAF gets its own specialist.

<details>
<summary><b>WAF Warfare (11)</b> — Break through any Web Application Firewall</summary>

| Agent | Target | What It Does |
|---|---|---|
| **WAF Fingerprinter** | Any | Identifies which WAF + outputs known bypass techniques |
| **WAF Bypass Scanner** | Any | General bypass: method switching, encoding, path confusion |
| **Cloudflare Bypass** | Cloudflare | Origin IP discovery, challenge bypass, Unicode normalization |
| **Akamai Bypass** | Akamai/Kona | Bot Manager evasion, sensor data, client reputation |
| **AWS WAF Bypass** | AWS WAF/Shield | Managed rule evasion, body limit overflow, rate-based bypass |
| **ModSecurity Bypass** | ModSecurity/CRS | Paranoia level detection, anomaly scoring, rule ID evasion |
| **Imperva Bypass** | Imperva/Incapsula | Client classification, cookie analysis, smuggling |
| **Custom WAF Bypass** | Unknown WAFs | 8-step methodology to reverse-engineer any WAF's rules |
| **Payload Encoder** | Any | 15+ encoding types: Unicode, hex, double-encode, chunked, SQL comments |
| **Rule Analyzer** | Any | Binary search probing to map exactly what triggers the WAF |
| **Protocol Bypass** | Any | HTTP/2, h2c smuggling, WebSocket upgrade, QUIC, chunked abuse |
</details>

---

### Hunter Suite (8 agents)

> Specialized hunters for specific attack patterns.

<details>
<summary><b>Hunters (8)</b> — Each one hunts a specific vulnerability class</summary>

- **Token Analyzer** — JWT cracking (alg:none, RS256→HS256, weak secrets), session entropy, cookie flags
- **CORS Chain Analyzer** — Automated 7-origin CORS test matrix with auto-PoC generation. **The pattern that found CORS bugs on two major platforms.**
- **Password Reset Tester** — Host header injection, token prediction, email pollution, IDOR
- **SSO Analyzer** — Map SSO domain scope, test cross-domain session attacks
- **API Parameter Bruter** — Brute force hidden API parameter names from error messages
- **CDN Bypass** — Find origin IP behind Cloudflare/Akamai via DNS history, certs, email headers
- **Rate Limit Tester** — Test rate limits on login, OTP, reset, with bypass techniques
- **Bounty Report Writer** — Auto-format findings into H1/Bugcrowd templates with CVSS
</details>

---

### Offensive Tooling (6 agents)

> The tools that fill the gaps between scanning and exploitation.

<details>
<summary><b>Offensive Tools (6)</b> — Browser automation, auth breaking, response diffing, blind testing, proxy rotation, template building</summary>

- **Headless Browser** — Playwright SPA renderer, intercepts all API calls at runtime, verifies XSS in real browser, tests CORS PoCs
- **Auth Flow Breaker** — Handles RSA-encrypted login, multi-step auth, CAPTCHA detection, OAuth automation
- **Response Differ** — JSON-aware response comparison for IDOR detection, highlights meaningful differences
- **Blind Injection Tester** — OOB testing with interactsh for blind XSS/SSRF/SQLi/XXE
- **Proxy Rotator** — IP rotation via Tor, free proxies, Lambda, header spoofing
- **Nuclei Template Builder** — Convert any finding into a nuclei template for mass scanning
</details>

---

### Recon & Utility (5 agents)

<details>
<summary><b>Recon (5)</b> — Subdomain brute-force, tech detection, cookie audit, redirect tracing, bucket finding</summary>

- **Subdomain Bruteforcer** — Active DNS brute-force + permutations + vhost discovery
- **Tech Stack Detector** — Wappalyzer-style fingerprinting from headers, JS, HTML, cookies
- **Cookie Security Auditor** — Audit all cookies for Secure/HttpOnly/SameSite/domain scope
- **Redirect Chain Tracer** — Follow every redirect, test for open redirect at each hop
- **S3 Bucket Finder** — Enumerate S3/GCS/Azure buckets from domain names
</details>

---

### Specialized (22 agents)

<details>
<summary><b>Active Directory (4)</b> — BloodHound, Kerberoasting, LDAP, SMB</summary>

- **AD Attacker** — Full AD chain: BloodHound, Kerberoasting, DCSync
- **SMB Tester** — EternalBlue, SMBGhost, ntlmrelayx
- **Kerberos Attacker** — Golden/Silver tickets, S4U2, RBCD
- **LDAP Tester** — Anonymous bind, LDAP injection, RID brute
</details>

<details>
<summary><b>Cloud Native (3)</b> — AWS, Kubernetes, container escape</summary>

- **AWS Tester** — Pacu, IAM, S3, IMDSv2, AssumeRole
- **Kubernetes Tester** — kube-hunter, RBAC, pod escape
- **Container Escape** — Docker socket, runc CVEs, cgroups
</details>

<details>
<summary><b>Mobile / IoT (4)</b> — Android, iOS, firmware, Bluetooth</summary>

- **Android Tester** — apktool, jadx, frida, drozer, MobSF
- **iOS Tester** — frida-ios-dump, objection, keychain
- **Firmware Extractor** — binwalk, unblob, firmware analysis
- **Bluetooth Tester** — BLE, GATT, btlejack, gattacker
</details>

<details>
<summary><b>AI/ML Security (3)</b> — Prompt injection, model extraction, jailbreaking</summary>

- **Prompt Injection Tester** — Direct/indirect injection
- **Model Extractor** — Exposed models, shadow extraction
- **AI Jailbreaker** — DAN, garak, PAIR, GCG
</details>

<details>
<summary><b>Recon & Bypass (4)</b> — WAF fingerprint, origin find, Shodan pivot, H2 smuggle</summary>

- **WAF Fingerprinter** — Identifies which WAF + bypass techniques
- **Origin Finder** — Real IP behind CDN via 10 techniques
- **Shodan Pivoter** — Pivot through Shodan/Censys/ZoomEye
- **HTTP/2 Smuggler** — h2c upgrade, downgrade desync
</details>

<details>
<summary><b>Defense & Workflow (4)</b> — GTFOBins, LOLBAS, drift detection, payout prediction</summary>

- **GTFOBins Lookup** — SUID/sudo/caps scanner
- **LOLBAS Finder** — Living-Off-The-Land + payload generator
- **Drift Detector** — System state snapshots + drift alerts
- **Bug Payout Predictor** — Predict bounty payouts from hacktivity
</details>

---

## Pro Features

| Command | What It Does |
|---|---|
| `claudeos wizard` | First-run setup wizard |
| `claudeos agents` | Browse and search all 300 agents by category |
| `claudeos workflow` | Pre-built multi-agent workflows (bug-bounty, recon, wordpress, etc.) |
| `claudeos engagement` | Manage bug bounty/pentest workspaces |
| `claudeos findings` | SQLite findings tracker with CVSS and payouts |
| `claudeos quickscan` | Full recon pipeline in 30 seconds (DNS, subdomains, headers, CORS, APIs) |
| `claudeos undo` | Roll back agent changes |
| `claudeos diff` | Compare scan results |
| `claudeos screenshot` | Auto-screenshot URLs for PoCs |
| `claudeos cheatsheet` | One-page reference cards for any agent |
| `claudeos telegram` | Telegram bot: control ClaudeOS from your phone |

### Self-Improving Engine

ClaudeOS gets smarter over time. When an agent's command fails:

1. **Detects** the failure (exit code, stderr)
2. **Classifies** it (missing tool, syntax error, OS mismatch, false positive)
3. **Fixes** the agent's CLAUDE.md playbook
4. **Retries** the command
5. **Commits** the fix: `auto-fix(agent): what was fixed`

Every failure makes the system stronger. See `agents/self-improver/CLAUDE.md` for the full protocol.

---

## Safety & Authorization

ClaudeOS is built for **defenders, learners, and ethical hackers.**

### One-Time Confirmation (Default)

The first time you use an offensive agent, ClaudeOS asks once:

```
> Are you authorized to test [target]?
> 1) bug-bounty   2) ctf   3) own   4) client   5) research   no) cancel
```

No forms. No PDFs. No lawyers. You're a professional — ClaudeOS trusts you.

### What ClaudeOS Always Does

- Logs every action to `/var/log/claudeos/actions.log`
- Confirms destructive operations before executing
- Refuses to attack targets you didn't authorize

### What ClaudeOS Will NOT Do

- Run offensive agents without your confirmation
- Help with malware distribution or unauthorized access
- Hide its actions from logs
- Pretend you have authorization when you don't

### Pro Mode (Optional)

For paid pentest engagements with legal requirements, enable Pro Mode for per-engagement scope files and audit trails. See [ARCHITECTURE.md](ARCHITECTURE.md).

---

## CLI Commands

```bash
claudeos              # Open AI assistant
claudeos status       # System health dashboard
claudeos agents       # Browse all 300 agents
claudeos quickscan    # Full recon pipeline
claudeos workflow     # Multi-agent workflows
claudeos engagement   # Manage workspaces
claudeos findings     # Track vulnerabilities
claudeos telegram     # Telegram bot control
claudeos help         # Show all commands
```

---

## Contributing

We welcome contributions:
- Add new agents (just create `agents/{name}/CLAUDE.md`)
- Improve existing agent playbooks
- Add support for more Linux distros
- Report bugs or suggest features
- Share your real-world stories

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

MIT License — use it, modify it, share it.

---

<div align="center">

**300 agents. Battle-tested. Self-improving. Open source.**

**Built by hunters, for hunters.**

[Report Bug](https://github.com/MuLTiAcidi/claudeos/issues) | [Request Feature](https://github.com/MuLTiAcidi/claudeos/issues) | [Join the Community](https://github.com/MuLTiAcidi/claudeos/discussions)

</div>
