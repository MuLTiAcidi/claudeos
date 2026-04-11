<div align="center">

```
  ██████╗██╗      █████╗ ██╗   ██╗██████╗ ███████╗ ██████╗ ███████╗
 ██╔════╝██║     ██╔══██╗██║   ██║██╔══██╗██╔════╝██╔═══██╗██╔════╝
 ██║     ██║     ███████║██║   ██║██║  ██║█████╗  ██║   ██║███████╗
 ██║     ██║     ██╔══██║██║   ██║██║  ██║██╔══╝  ██║   ██║╚════██║
 ╚██████╗███████╗██║  ██║╚██████╔╝██████╔╝███████╗╚██████╔╝███████║
  ╚═════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝ ╚═════╝╚══════╝
```

### AI-Powered Server Management OS

**Manage your Linux servers with natural language. No more memorizing commands.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-22.04+-orange.svg)]()
[![Debian](https://img.shields.io/badge/Debian-12+-red.svg)]()

</div>

---

## 🛡️ Our Mission

**ClaudeOS is built for defenders, learners, and ethical hackers.**

We built this for the people who want to make systems safer — sysadmins protecting their infrastructure, bug bounty hunters earning legit rewards, students learning in CTFs, pentesters running authorized engagements, and blue teams validating their defenses.

If you want to attack people, steal data, or harm others — **this is not the tool for you.** Unauthorized access is a crime. Real victims pay the price. Walk away.

For everyone else: welcome. Let's build something that makes the internet a little safer.

---

## What is ClaudeOS?

ClaudeOS turns your Linux server into an AI-managed system. Instead of memorizing hundreds of commands, just tell it what you want in plain English:

```
$ claudeos
> "install nginx and set up SSL for mysite.com"
> "why is the server slow right now?"
> "lock down this server"
> "migrate the database to the new server"
> "send me a Telegram alert if disk hits 90%"
```

It handles everything — from installing packages to security hardening, from backups to performance optimization.

## Install

### Option 1 — On existing Ubuntu/Debian (recommended)
```bash
curl -fsSL https://raw.githubusercontent.com/MuLTiAcidi/claudeos/main/install.sh | sudo bash
```

### Option 2 — Fresh install from ISO (bare metal)
Download the latest ISO from [Releases](https://github.com/MuLTiAcidi/claudeos/releases), or build it yourself:

```bash
# Build ISO (requires Docker on an amd64 Linux machine)
git clone https://github.com/MuLTiAcidi/claudeos.git
cd claudeos/iso-builder
bash build-in-docker.sh
# Output: output/claudeos.iso
```

```bash
# Flash to USB (replace /dev/sdX with your USB drive)
dd if=claudeos.iso of=/dev/sdX bs=4M status=progress
# Or use balenaEtcher (GUI tool)
```

Boot from USB → Install → On first boot, ClaudeOS setup wizard runs automatically.

That's it. ClaudeOS is ready. Type `claudeos` to start.

## Editions

| Edition | Best For | Install |
|---------|----------|---------|
| **Server** | VPS, cloud servers, headless machines | `sudo bash install.sh` |
| **Web Dashboard** | Remote management from any browser | `sudo bash install.sh --dashboard` |
| **Desktop** | Workstations with monitors | `sudo bash install.sh --desktop` |
| **Kiosk** | Office monitoring screens | `sudo bash install.sh --kiosk` |
| **Multi-Node** | Managing multiple servers | `sudo bash install.sh --multi-node` |
| **Raspberry Pi** | ARM boards, home servers | `sudo bash install.sh --pi` |

## Architecture — How It Works

ClaudeOS has **4 simple layers**. There are no daemons, no message buses, no hidden processes. Everything is Markdown files and bash.

```
┌─────────────────────────────────────────────────────────┐
│  LAYER 1: USER          "scan example.com for vulns"   │
└────────────────────┬────────────────────────────────────┘
                     ▼
┌─────────────────────────────────────────────────────────┐
│  LAYER 2: ORCHESTRATOR  (claudeos/CLAUDE.md)            │
│  • Reads your request                                   │
│  • Picks the right agent(s) from 231 specialists        │
│  • Coordinates multi-agent workflows                    │
│  • Verifies authorization for offensive agents          │
└────────────────────┬────────────────────────────────────┘
                     ▼
┌─────────────────────────────────────────────────────────┐
│  LAYER 3: SPECIALIST AGENTS  (agents/{name}/CLAUDE.md)  │
│  • 231 expert playbooks with real commands              │
│  • Each one is just a Markdown file                     │
│  • Loaded on demand by the orchestrator                 │
└────────────────────┬────────────────────────────────────┘
                     ▼
┌─────────────────────────────────────────────────────────┐
│  LAYER 4: COMMAND EXECUTOR  (Claude Code's bash tool)   │
│  • Actually runs the bash commands                      │
│  • Asks for confirmation on destructive ops             │
│  • Logs everything to /var/log/claudeos/actions.log     │
└─────────────────────────────────────────────────────────┘
```

**Key insight:** Agents are knowledge, not processes. Each agent is a Markdown playbook that the orchestrator loads when needed. Nothing runs in the background. You can read every agent's playbook to know exactly what it will do.

📖 **Full architecture details:** See [ARCHITECTURE.md](ARCHITECTURE.md) for the complete explanation, multi-agent workflow examples, security model, and how to add your own agents.

## How to Use Agents

ClaudeOS agents are smart specialists. You don't need to call them by name — just describe what you want and ClaudeOS picks the right agent automatically.

### The 3 Ways to Use Agents

**1. Natural language (easiest)** — Just talk to ClaudeOS:
```bash
$ claudeos
> "scan my server for vulnerabilities"          # → vulnerability-scanner
> "set up a Minecraft server with 8GB RAM"      # → minecraft-server
> "back up the database every 6 hours"          # → backup + cron-master
> "my nginx is throwing 502 errors, fix it"     # → log-doctor + config-fixer
> "harden this server against attacks"          # → config-hardener + security
```

**2. Call an agent directly** — When you know what you want:
```bash
$ claudeos
> "use the wifi-breaker agent to audit my office wifi"
> "ask the report-writer to generate a pentest report from today's findings"
> "have the chaos-tester run a network failure test on staging"
```

**3. Chain multiple agents** — For complex workflows:
```bash
$ claudeos
> "use recon-master to scan example.com, then vuln-weaponizer to find exploits,
   then report-writer to document everything"
```

### Agent Categories at a Glance

| Need to... | Use these agents |
|---|---|
| Manage daily server operations | Core System, Infrastructure, Monitoring |
| Audit security defensively | White Hat (vulnerability-scanner, security-auditor, ssl-tester) |
| Pentest your own systems | Grey Hat, Black Hat, Red Team (authorized only) |
| Write or fix code | Coder agents (code-generator, debugger, refactorer) |
| Auto-fix broken things | Fixer agents (auto-healer, log-doctor, network-healer) |
| Keep services online 24/7 | Always Up agents (uptime-guardian, failover-manager) |
| Run game servers | Gamer agents (minecraft-server, steam-server) |
| Automate repetitive tasks | Automation agents (cron-master, deploy-automator) |

### Agent Files

Every agent lives at `agents/{agent-name}/CLAUDE.md` and contains:
- **Safety rules** — what the agent will and won't do
- **Real commands** — every bash command is tested and ready to run
- **Workflows** — common task templates
- **Troubleshooting** — fix common issues

You can read any agent's CLAUDE.md to learn what it can do:
```bash
cat /opt/claudeos/agents/vulnerability-scanner/CLAUDE.md
```

### Safety First

Agents marked with ⚠️ (Black Hat, Red Team, Stealth, Bug Bounty) are powerful offensive tools. ClaudeOS uses a **simple, common-sense approach** to authorization — no PDFs, no contracts, no bureaucracy for the 95% of users who are bug bounty hunters, CTF players, or lab owners.

#### The Default: One-Time Confirmation

The first time you run an offensive agent, ClaudeOS asks you **once**:

```
> Are you authorized to test [target]?
> Type one of:
>   1) bug-bounty   (HackerOne, Bugcrowd, Intigriti, YesWeHack, etc.)
>   2) ctf          (HackTheBox, TryHackMe, VulnHub, lab platform)
>   3) own          (my own server/VPS/home lab)
>   4) client       (paid pentest engagement — see Pro Mode below)
>   5) research     (security research on systems I'm authorized to test)
>   no              (cancel)
```

Type 1, 2, 3, or 5 → ClaudeOS proceeds. Done. Logged to `/var/log/claudeos/actions.log`. No documents required.

That's it. No forms. No PDFs. No lawyers.

#### Why This Works

- **Bug bounty hunters** — your authorization is the program's scope page on HackerOne. ClaudeOS trusts you to read it.
- **CTF players** — the platform itself is your authorization. Just play.
- **Home lab owners** — you own it, you can break it.
- **Security researchers** — you know your scope.

ClaudeOS is a tool. **You** are responsible for being honest about your authorization. Lying to ClaudeOS to attack systems you don't own is illegal and on you, not the tool.

#### Pro Mode (Optional — for paid client engagements)

If you're a professional pentester running paid engagements where legal liability matters, you can opt into **Pro Mode**. This is for the ~5% of users who need a real audit trail.

Enable in `/etc/claudeos/config.toml`:
```toml
[mode]
pro_mode = true
```

In Pro Mode, ClaudeOS expects per-engagement scope files at:
```
/etc/claudeos/engagements/{name}/
├── scope.txt          # In-scope targets (one per line)
├── out-of-scope.txt   # Off-limits targets
├── start-date         # YYYY-MM-DD
└── end-date           # YYYY-MM-DD
```

Then ClaudeOS auto-validates every offensive action against the active engagement. Enterprise pentesters get the audit trail they need without making life harder for everyone else.

#### What ClaudeOS Always Does

- **Logs every action** to `/var/log/claudeos/actions.log` (regardless of mode)
- **Confirms destructive operations** (`rm -rf`, format, drop database, etc.)
- **Refuses to attack systems you didn't authorize** (no surprise targets)
- **Provides cleanup procedures** for stealth/red team agents

#### What ClaudeOS Will NOT Do

- ❌ Run offensive agents without your one-time confirmation
- ❌ Hide its actions from logs
- ❌ Help with malware distribution or unauthorized access
- ❌ Pretend you have authorization when you don't

#### Legal Reminder (the short version)

Testing systems without authorization is illegal almost everywhere. **You are responsible** for staying within scope. ClaudeOS is a tool — the ethics and legality are on the operator.

**If you're not sure you have permission, don't run the agent.** Ask the system owner. Read the bug bounty program rules. Use your judgment.

### Common Examples

```bash
# Daily operations
> "show me anything weird in today's logs"           # log-aggregator
> "what services are using too much memory?"         # monitoring + process-forensics
> "update everything but keep nginx pinned"          # update-manager

# Security
> "check my SSL certs and renew anything expiring"   # ssl-watchdog + ssl-tester
> "audit who has sudo access on this server"        # access-auditor
> "harden this fresh install"                        # config-hardener

# Recovery
> "the database crashed, recover it"                 # database-repair
> "fix my broken DNS"                                # network-healer
> "GRUB won't boot, help"                            # boot-fixer

# Automation
> "deploy the main branch from github every push"   # deploy-automator + webhook-listener
> "alert me on Telegram if disk hits 85%"           # event-reactor + notification-router
```

---

## 231 Specialist AI Agents

ClaudeOS ships with **231 specialized AI agents** across 17 categories. Every agent contains real working commands — no simulations. The largest agent ecosystem ever built for a Linux distribution.

<details>
<summary><b>Core System (9 agents)</b></summary>

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
<summary><b>Infrastructure (5 agents)</b></summary>

- **Docker Manager** — Containers, compose, images, volumes
- **Database Agent** — MySQL/PostgreSQL tuning, queries, replication
- **Web Server Agent** — Nginx/Apache vhosts, SSL, performance
- **DNS Manager** — DNS zones, records, Cloudflare/Route53
- **Mail Server** — Postfix/Dovecot, spam, DKIM/SPF/DMARC
</details>

<details>
<summary><b>Intelligence (4 agents)</b></summary>

- **Incident Responder** — Root cause analysis, playbooks, post-mortems
- **Performance Tuner** — Sysctl, MySQL, Nginx, PHP-FPM optimization
- **Cost Optimizer** — Cloud right-sizing, waste detection
- **Migration Agent** — Move sites/apps between servers
</details>

<details>
<summary><b>DevOps (3 agents)</b></summary>

- **Git Deploy** — CI/CD, zero-downtime deploys, rollback
- **Environment Manager** — .env files, secrets, variables
- **Multi-Server** — Fleet management, parallel commands
</details>

<details>
<summary><b>Monitoring & Alerts (5 agents)</b></summary>

- **Notifications** — Telegram, email, Slack, Discord alerts
- **Log Aggregator** — Centralized log search and analysis
- **SSL Watchdog** — Cert expiry, domain health, uptime
- **Snapshot Manager** — Pre-change snapshots, rollback
- **Compliance** — CIS, GDPR, PCI-DSS, SOC 2 checks
</details>

<details>
<summary><b>Advanced Operations (6 agents)</b></summary>

- **Firewall Visualizer** — Map rules, detect conflicts
- **Crontab Auditor** — Find dead jobs, optimize scheduling
- **Process Forensics** — Deep process inspection, anomaly detection
- **Capacity Planner** — Predict resource exhaustion
- **API Gateway** — Rate limiting, API keys, reverse proxy
- **Container Orchestrator** — Docker Swarm clusters
</details>

<details>
<summary><b>White Hat — Ethical Security (13 agents)</b></summary>

- **Vulnerability Scanner** — Automated CVE scanning across packages
- **Security Auditor** — CIS benchmarks, Lynis, OpenSCAP audits
- **Password Auditor** — Test password strength across accounts
- **Web App Scanner** — OWASP Top 10 testing (Nikto, sqlmap, gobuster)
- **SSL Tester** — Deep TLS analysis, cipher suites, vulnerabilities
- **Network Mapper** — Topology discovery, port inventory (nmap, masscan)
- **Patch Validator** — Verify security patches are applied
- **Log Forensics** — Detect suspicious patterns in system logs
- **Config Hardener** — Auto-harden SSH, kernel, services
- **Access Auditor** — Audit users, sudo, SUID, ACLs
- **Encryption Enforcer** — LUKS, TLS, GPG enforcement
- **Compliance Checker** — PCI-DSS, HIPAA, SOC2, GDPR validation
- **Incident Logger** — Real-time incident logging with chain of custody
</details>

<details>
<summary><b>Grey Hat — Security Research (11 agents)</b></summary>

- **Zero Day Hunter** — Fuzz with AFL++, libFuzzer, Boofuzz
- **Reverse Engineer** — Binary analysis with radare2, Ghidra, strings
- **Traffic Analyzer** — Deep packet inspection (tcpdump, tshark)
- **Exploit Researcher** — Searchsploit, Metasploit, CVE research
- **Bug Bounty Hunter** — Subfinder, amass, httpx, nuclei pipelines
- **Credential Tester** — Hydra, medusa, CrackMapExec
- **WiFi Breaker** — Aircrack-ng suite, hashcat WPA cracking
- **DNS Poisoner** — DNS spoofing, cache poisoning testing
- **Session Hijacker** — Bettercap, mitmproxy, token analysis
- **API Fuzzer** — ffuf, wfuzz, GraphQL/REST fuzzing
- **OSINT Gatherer** — theHarvester, Shodan, recon-ng, SpiderFoot
</details>

<details>
<summary><b>Black Hat — Offensive Security (12 agents)</b></summary>

> ⚠️ **For authorized penetration testing engagements only.**

- **Attack Chain** — Multi-stage real attack workflows
- **Malware Analyst** — Reverse engineer and dissect malware
- **Data Exfiltrator** — DNS/ICMP/steganography exfil testing
- **Ransomware Tester** — Real backup recovery validation
- **APT Operator** — Long-term persistent access campaigns
- **Social Engineer** — GoPhish, SET, real phishing tests
- **Backdoor Hunter** — Find and plant test backdoors
- **Keylogger Deployer** — Logkeys, PAM tty_audit, evdev
- **Rootkit Builder** — LKM/userspace rootkits, detection testing
- **C2 Operator** — Sliver, Mythic, custom C2 frameworks
- **Cryptojacker** — Mining injection and detection testing
- **Supply Chain Attacker** — Dependency confusion, typosquatting
</details>

<details>
<summary><b>Red Team — Combined Operations (15 agents)</b></summary>

- **Red Commander** — Orchestrate full red team operations
- **Attack Planner** — Multi-vector attack strategy planning
- **Defense Breaker** — Bypass firewalls, IDS, WAF, EDR
- **Tool Forge** — Build custom exploit tools and payloads
- **Recon Master** — Deep recon, OSINT, fingerprinting
- **Persistence Agent** — Maintain access (cron, systemd, PAM, kernel)
- **Lateral Mover** — SSH pivoting, proxychains, network pivoting
- **Exfil Operator** — Multi-channel data extraction
- **Evasion Engine** — Real-time AV/IDS/WAF/EDR bypass
- **Implant Builder** — Custom RATs and implants in C/Python/Go
- **Vuln Weaponizer** — Turn CVEs into working exploits
- **Phishing Operator** — Real phishing campaigns with GoPhish
- **Report Writer** — Pro pentest reports with CVSS scoring
- **Blue Team Tester** — Purple team exercises with Atomic Red Team
- **Arsenal Manager** — Tool inventory mapped to MITRE ATT&CK
</details>

<details>
<summary><b>Coder — Development (8 agents)</b></summary>

- **Code Generator** — Scaffold projects (Node, Python, Go, Rust)
- **Debugger** — gdb, strace, valgrind, perf profiling
- **Refactorer** — Complexity analysis, dead code, AST refactoring
- **API Designer** — OpenAPI, GraphQL, REST design
- **Database Designer** — Schema design, migrations, optimization
- **Test Writer** — pytest, Jest, Go testing, coverage
- **Dependency Manager** — npm/pip/cargo audit, updates
- **Doc Generator** — Sphinx, JSDoc, godoc, MkDocs
</details>

<details>
<summary><b>Fixer — Auto-Repair (7 agents)</b></summary>

- **Auto Healer** — Self-heal failing services
- **Config Fixer** — Detect and fix misconfigurations
- **Dependency Resolver** — Fix broken apt/pip/npm dependencies
- **Log Doctor** — Diagnose issues from log patterns
- **Network Healer** — Auto-fix DNS, routing, firewall, DHCP
- **Boot Fixer** — GRUB, initramfs, fstab repair
- **Database Repair** — MySQL/PostgreSQL/MongoDB recovery
</details>

<details>
<summary><b>Always Up — Uptime & Resilience (8 agents)</b></summary>

- **Uptime Guardian** — 24/7 monitoring with instant alerts
- **Failover Manager** — Keepalived/VRRP, HAProxy failover
- **Load Balancer** — Nginx/HAProxy load balancing
- **Chaos Tester** — Real chaos engineering with stress-ng, tc netem
- **DDoS Shield** — Detection and automatic mitigation
- **Auto Restarter** — Smart restart with backoff strategies
- **Redundancy Manager** — DRBD, GlusterFS, Pacemaker, replicas
- **Heartbeat Monitor** — Lightweight ICMP/TCP/HTTP checks
</details>

<details>
<summary><b>Gamer — Game Server Management (8 agents)</b></summary>

- **Game Server Manager** — Universal game server lifecycle
- **Minecraft Server** — Paper/Spigot/Fabric, plugins, JVM tuning
- **Steam Server** — SteamCMD games (CS2, Valheim, Rust, ARK)
- **Game Performance** — Tick rate, FPS, Aikar's flags
- **Player Manager** — Bans, whitelists, RCON, LuckPerms
- **Mod Manager** — Workshop downloads, conflict resolution
- **Game Backup** — Hot world backups, rsnapshot, S3 sync
- **Discord Bot Manager** — Game ↔ Discord bridge bots
</details>

<details>
<summary><b>Automation (15 agents)</b></summary>

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

<details>
<summary><b>Network & Infrastructure (9 agents)</b></summary>

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
<summary><b>Stealth — Authorized Red Team (3 agents)</b></summary>

> ⚠️ **For authorized red team engagements only.**

- **Trace Cleaner** — Clean logs, history, utmp/wtmp
- **Tunnel Builder** — SSH/socat/stunnel/chisel tunnels
- **Identity Rotator** — MAC/IP/DNS/hostname rotation
</details>

<details>
<summary><b>🏆 Bug Bounty Hunter — Pro Toolkit (18 agents)</b></summary>

> Built by a bug bounty hunter, for bug bounty hunters. Authorized programs only (HackerOne, Bugcrowd, Intigriti, etc.).

- **Subdomain Takeover** — Detect takeover-able subdomains (Subjack, Subzy, dnsReaper, nuclei templates)
- **JS Analyzer** — Parse JavaScript for endpoints, secrets, API keys (LinkFinder, SecretFinder, JSluice)
- **XSS Hunter** — XSS testing + blind XSS callback server (dalfox, XSStrike, XSS Hunter Express)
- **SQLi Hunter** — Deep SQL injection (sqlmap, ghauri, NoSQL injection, WAF bypass)
- **SSRF Hunter** — SSRF with out-of-band confirmation (interactsh, cloud metadata)
- **IDOR Hunter** — IDOR/BOLA testing, parameter tampering, ID enumeration
- **GraphQL Hunter** — Introspection, batching, depth attacks (graphql-cop, InQL, clairvoyance)
- **JWT Hunter** — JWT vulnerabilities (jwt_tool, none alg, key confusion, kid injection)
- **CORS Tester** — CORS misconfiguration detection (CORStest, Corsy)
- **Request Smuggler** — HTTP request smuggling (smuggler, http2smugl, h2cSmuggler)
- **Race Hunter** — Race condition testing (single-packet attacks, parallel requests)
- **Cache Poisoner** — Web cache poisoning (Param Miner methodology)
- **Param Finder** — Find hidden HTTP parameters (Arjun, ParamSpider, x8)
- **GitHub Recon** — GitHub dorking + secret scanning (trufflehog, gitleaks)
- **Cloud Recon** — Cloud misconfigs (S3 buckets, IAM, GCP, Azure)
- **Collaborator** — Self-hosted out-of-band interaction server (interactsh-server)
- **Nuclei Master** — Manage nuclei templates, custom template creation
- **Screenshot Hunter** — Mass visual recon (gowitness, aquatone, eyewitness)
- **Payload Crafter** — Custom exploit payloads, shellcode, webshells
</details>

<details>
<summary><b>🎯 Advanced Bug Bounty (8 agents)</b></summary>

> The vuln class specialists every BB hunter needs.

- **XXE Hunter** — XML External Entity attacks (file read, blind, OOB, SSRF)
- **SSTI Hunter** — Server-Side Template Injection (Jinja, Twig, Velocity, Freemarker)
- **LFI Hunter** — Local File Inclusion + log poisoning + PHP filter chains
- **Deserialization Hunter** — Java/PHP/Python/.NET/Ruby deserialization (ysoserial, phpggc)
- **OAuth Tester** — OAuth flow vulns (redirect_uri, state, PKCE, scope)
- **SAML Tester** — XSW1-XSW8, signature wrapping, NameID injection
- **Prototype Pollution Hunter** — Server-side + client-side prototype pollution
- **CSRF Hunter** — Token validation, SameSite, content-type bypass
</details>

<details>
<summary><b>🌐 CMS & Framework Hunters (5 agents)</b></summary>

- **WordPress Hunter** — Full wpscan integration, plugin/theme CVEs, xmlrpc abuse
- **Drupal Hunter** — Drupalgeddon, droopescan, version fingerprinting
- **Magento Hunter** — Trojan Order, Cosmic Sting, Shoplift, Magecart detection
- **Laravel Hunter** — .env exposure, Ignition RCE (CVE-2021-3129), APP_KEY abuse
- **Django Hunter** — DEBUG=True, SECRET_KEY → RCE, admin enum, DRF testing
</details>

<details>
<summary><b>🏢 Active Directory (4 agents)</b></summary>

> ⚠️ For authorized AD pentests only.

- **AD Attacker** — Full AD attack chain: BloodHound, Kerberoasting, AS-REP, ACL abuse, DCSync
- **SMB Tester** — Enum, EternalBlue, SMBGhost, PrintNightmare, ntlmrelayx
- **Kerberos Attacker** — Golden/Silver tickets, S4U2Self/Proxy, RBCD, delegation abuse
- **LDAP Tester** — Anonymous bind, AD enum, LDAP injection, RID brute
</details>

<details>
<summary><b>☁️ Cloud Native (3 agents)</b></summary>

- **AWS Tester** — Pacu, ScoutSuite, Prowler, IAM enum, S3, IMDSv1/v2, AssumeRole
- **Kubernetes Tester** — kube-hunter, RBAC, pod escape, kubelet abuse, etcd
- **Container Escape** — Docker socket, CAP_SYS_ADMIN, runc CVEs, cgroups, LKM
</details>

<details>
<summary><b>📱 Mobile / IoT / Hardware (4 agents)</b></summary>

- **Android Tester** — apktool, jadx, frida, drozer, MobSF, SSL pinning bypass
- **iOS Tester** — frida-ios-dump, class-dump, objection, keychain dumping
- **Firmware Extractor** — binwalk, unblob, jefferson, FAT, EMBA, secret hunting
- **Bluetooth Tester** — BLE scanning, GATT, btlejack hijacking, gattacker MITM
</details>

<details>
<summary><b>📊 Bug Bounty Workflow (4 agents)</b></summary>

- **Vuln Tracker** — SQLite finding tracker with payouts, CVSS, status, export
- **Program Monitor** — Watch H1/Bugcrowd/Intigriti/YesWeHack for scope changes
- **Dupe Checker** — Pre-report duplicate screening across hacktivity feeds
- **Recon Orchestrator** — Master pipeline: subfinder→httpx→nuclei→screenshots
</details>

<details>
<summary><b>🤖 AI/ML Security (3 agents)</b></summary>

> Emerging field — test LLM apps and ML models for security flaws.

- **Prompt Injection Tester** — Direct/indirect injection, system prompt extraction
- **Model Extractor** — Find exposed model files, shadow model extraction, MIA
- **AI Jailbreaker** — DAN, role-play, encoding, multi-step, garak, PAIR, GCG
</details>

## ⚡ Pro Features (v2.0)

ClaudeOS v2 adds 10 new pro features that make managing 231 agents actually pleasant:

| Command | What it does |
|---|---|
| `claudeos wizard` | First-run setup wizard — picks profile, mode, notifications in 60 seconds |
| `claudeos agents` | Browse, search, and read all 231 agents by category |
| `claudeos workflow` | Run pre-built multi-agent workflows (`bug-bounty`, `recon`, `wordpress`, etc.) |
| `claudeos engagement` | Manage bug bounty/pentest workspaces with auto-organized output |
| `claudeos findings` | SQLite-backed findings tracker with CVSS, status, payouts |
| `claudeos undo` | Roll back changes made by agents (config files, etc.) |
| `claudeos diff` | Compare scan results to find what changed |
| `claudeos screenshot` | Auto-screenshot URLs for PoCs (gowitness/aquatone/chromium) |
| `claudeos cheatsheet` | Generate one-page reference cards for any agent |
| `claudeos telegram` | Send alerts and receive commands via Telegram bot |

### Pro Workflow Example

```bash
# Start a new bug bounty engagement
claudeos engagement start hackerone-tesla

# Run the full bug bounty workflow against a target
claudeos workflow bug-bounty tesla.com

# Track findings as you discover them
claudeos findings add

# See your stats and earnings
claudeos findings stats

# Get notified on Telegram when scans complete
claudeos telegram alert success "Recon complete for tesla.com"

# Compare today's recon with yesterday's
claudeos diff engagement hackerone-tesla
```

## Autonomous Features

ClaudeOS runs in the background and takes care of your server:

| Feature | Interval | What It Does |
|---------|----------|-------------|
| Health Monitor | Every 5 min | Checks CPU/RAM/disk, restarts crashed services |
| Security Watchdog | Every 15 min | Detects brute force, bans attacking IPs |
| Auto Backup | Daily 2 AM | Full backup with 30-day rotation |
| Daily Report | Daily 7 AM | Summary report of everything that happened |
| Auto Optimize | Weekly | Tunes MySQL, Nginx, PHP-FPM for your hardware |
| Self Update | Weekly | Updates Claude Code CLI and security patches |

## CLI Commands

```bash
claudeos              # Open AI assistant
claudeos status       # System health dashboard
claudeos dashboard    # Full system overview
claudeos health       # Run health check
claudeos security     # Security audit
claudeos backup       # Run backup now
claudeos backup list  # Show backups
claudeos update       # Update packages
claudeos report       # Today's report
claudeos logs         # Recent events
claudeos services     # Running services
claudeos firewall     # Firewall rules
claudeos users        # System users
claudeos disk         # Disk usage
claudeos alerts       # Recent warnings
claudeos help         # Show all commands
```

## Requirements

- **OS**: Ubuntu 22.04+ or Debian 12+
- **RAM**: 512MB (Server), 1GB (Dashboard), 2GB (Desktop)
- **CPU**: 1+ cores
- **Disk**: 5GB+ free
- **Node.js**: 20+ (auto-installed)
- **Claude API key** (get at [claude.ai](https://claude.ai))

## Contributing

Contributions welcome! Feel free to:
- Add new agents
- Improve existing agents
- Add support for more Linux distros
- Improve the web dashboard
- Report bugs

## License

MIT License — use it, modify it, share it.

---

<div align="center">



[Report Bug](https://github.com/MuLTiAcidi/claudeos/issues) · [Request Feature](https://github.com/MuLTiAcidi/claudeos/issues)

</div>
