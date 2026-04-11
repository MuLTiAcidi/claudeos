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

Agents marked with ⚠️ (Black Hat, Red Team, Stealth) are powerful offensive tools. They are designed for **authorized security testing** — pentesting your own systems, CTF competitions, lab environments, and engagements where you have explicit written permission.

#### Legitimate Use Cases

| Use Case | Example |
|---|---|
| **Pentest your own infrastructure** | Find weaknesses before attackers do |
| **Bug bounty programs** | Test targets in scope (HackerOne, Bugcrowd, etc.) |
| **Authorized client engagements** | Run as a security consultant with signed contracts |
| **Internal red team exercises** | Validate your blue team's detection capabilities |
| **CTF competitions** | Practice on Hack The Box, TryHackMe, VulnHub |
| **Home lab learning** | Build a lab with intentionally vulnerable VMs |
| **Compliance testing** | PCI-DSS pentests, SOC 2 audits |

#### What You Need Before Running Offensive Agents

**1. Authorization (mandatory)**

You **must** have one or more of these before running offensive agents against any target:

| Permission Type | What It Looks Like | Where to Get It |
|---|---|---|
| **Signed Pentest Contract** | Written agreement from the system owner authorizing security testing, with scope, timeline, and signatures | Direct from client/employer |
| **Bug Bounty Program** | Public program with defined scope, rules, and safe harbor language | HackerOne, Bugcrowd, Intigriti, YesWeHack, Synack |
| **Letter of Authorization (LoA)** | Formal letter on company letterhead, signed by an authorized officer (CISO, CTO, IT Director), naming you and the systems in scope | Internal corporate request |
| **Statement of Work (SoW)** | Detailed contract describing testing services, deliverables, and authorization | Pentest client engagements |
| **CTF / Lab Permission** | Terms of service of the CTF platform, or you own the lab | TryHackMe, HackTheBox, your home lab |
| **Vendor Authorization** | Some cloud/SaaS providers require pre-notification before testing | AWS Penetration Testing form, Microsoft Cloud Pen Test rules |
| **Self-Owned Systems** | You personally own and control the target hardware and network | Your own servers, VPS, home lab |

#### What a Valid Authorization Document Must Contain

A proper pentest authorization (the gold standard) includes **all** of these:

- ✅ **Names of authorized testers** (you, by full legal name)
- ✅ **Scope** — exact IPs, domains, applications, networks in scope
- ✅ **Out of scope** — systems explicitly forbidden from testing
- ✅ **Time window** — start date/time and end date/time of testing
- ✅ **Allowed techniques** — what's permitted (recon, exploitation, social engineering, DoS testing, etc.)
- ✅ **Forbidden techniques** — what's not allowed (e.g., no actual DoS, no data exfiltration of real customer data)
- ✅ **Emergency contact** — name, phone, email of someone reachable 24/7
- ✅ **Authorizing party** — signature, title, date from someone with authority to grant permission
- ✅ **Indemnification clause** — protection for the tester acting in good faith within scope
- ✅ **Data handling** — what to do with sensitive data discovered during testing

#### Sample Authorization Templates

Use these as a starting point — get them reviewed by a lawyer for real engagements:

- **PTES** — [Penetration Testing Execution Standard](http://www.pentest-standard.org/)
- **SANS Sample LoA** — Search "SANS Letter of Authorization template"
- **OWASP Pre-engagement** — [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- **NIST SP 800-115** — Technical Guide to Information Security Testing
- **OSSTMM** — Open Source Security Testing Methodology Manual

#### Where to Store Your Authorization

ClaudeOS expects your authorization documents to live at:
```
/etc/claudeos/authorizations/{engagement-name}/
├── authorization.pdf       # Signed authorization document
├── scope.txt              # In-scope IPs/domains (one per line)
├── out-of-scope.txt       # Out-of-scope IPs/domains
├── contacts.txt           # Emergency contacts
├── start-date             # ISO date when authorized testing begins
└── end-date               # ISO date when authorization expires
```

When you launch an offensive agent, ClaudeOS will:
1. Ask which engagement you're working on
2. Verify the target is in your scope file
3. Verify the current date is within the authorized time window
4. Log the action with the engagement name attached
5. Refuse to act if any check fails

**2. Isolated environment (recommended)**
- Run from a dedicated pentest VM or jump box
- Use a separate network interface to avoid leaking traffic
- VPN or bastion host to keep your real IP off target logs
- Snapshot your testing machine before starting

**3. Required tools & resources**
- ClaudeOS installed with API key configured
- Sufficient disk space for captures, logs, evidence (10GB+ recommended)
- Network access to the target (or local lab network)
- Some agents need extra packages — they will tell you what to install
- For wifi-breaker: a wireless adapter that supports monitor mode

**4. Documentation discipline**
- Keep detailed notes of every command run
- Save all output to `/var/log/claudeos/engagements/{engagement-name}/`
- Use the `report-writer` agent to compile findings into a final report
- Preserve evidence with chain of custody (use `incident-logger`)

#### How ClaudeOS Protects You

- **Authorization gates** — Agents prompt for explicit confirmation: "Confirm you have authorization to test [target]"
- **Scope enforcement** — You can set allowed targets in `/etc/claudeos/scope.conf` and ClaudeOS refuses out-of-scope actions
- **Action logging** — Every command runs through `/var/log/claudeos/actions.log` with timestamps
- **Destructive command confirmation** — `rm -rf`, `dd`, `format`, dropping tables, etc. require manual confirmation
- **Dry-run mode** — Most agents support `--dry-run` to preview what they would do
- **Cleanup procedures** — Stealth agents include teardown steps to remove artifacts after engagement

#### What ClaudeOS Will NOT Do

- ❌ Attack systems you don't have authorization for
- ❌ Run against `*.gov`, `*.mil`, critical infrastructure, or known production targets without explicit override
- ❌ Bypass its own safety prompts
- ❌ Hide its actions from logs
- ❌ Provide capabilities for malware distribution or unauthorized access

#### Legal Reminder

Unauthorized access to computer systems is illegal in most jurisdictions (Computer Fraud and Abuse Act in the US, Computer Misuse Act in the UK, similar laws worldwide). **You are responsible for ensuring you have permission to test any target.** ClaudeOS is a tool — the operator is responsible for legal and ethical use.

If you're unsure whether you have authorization, **don't run the agent**. When in doubt, ask the system owner first.

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

## 182 Specialist AI Agents

ClaudeOS ships with **182 specialized AI agents** across 16 categories. Every agent contains real working commands — no simulations.

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
