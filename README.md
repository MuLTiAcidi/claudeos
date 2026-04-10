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
Download the latest ISO from [Releases](https://github.com/MuLTiAcidi/claudeos/releases), flash to USB, and boot your server from it. Ubuntu + ClaudeOS pre-installed.

```bash
# Flash to USB (replace /dev/sdX with your USB drive)
dd if=claudeos.iso of=/dev/sdX bs=4M status=progress
```

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

## 32 Specialist AI Agents

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
<summary><b>Advanced (6 agents)</b></summary>

- **Firewall Visualizer** — Map rules, detect conflicts
- **Crontab Auditor** — Find dead jobs, optimize scheduling
- **Process Forensics** — Deep process inspection, anomaly detection
- **Capacity Planner** — Predict resource exhaustion
- **API Gateway** — Rate limiting, API keys, reverse proxy
- **Container Orchestrator** — Docker Swarm clusters
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

**Made with Claude Code**

[Report Bug](https://github.com/MuLTiAcidi/claudeos/issues) · [Request Feature](https://github.com/MuLTiAcidi/claudeos/issues)

</div>
