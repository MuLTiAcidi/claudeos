# ClaudeOS Architecture

This document explains how ClaudeOS works under the hood — how user requests flow through the system, who orchestrates what, and who actually runs the commands.

---

## TL;DR

ClaudeOS has **4 layers**:

1. **You** — Talk in plain English
2. **Orchestrator** — One main "brain" (`claudeos/CLAUDE.md`) that picks the right specialist
3. **Specialists** — 200 expert playbooks (`agents/{name}/CLAUDE.md`) with real commands
4. **Executor** — Claude Code's bash tool that actually runs the commands on your server

There is **no daemon, no message bus, no IPC**. Every "agent" is a Markdown file containing a specialist's playbook. The orchestrator loads the right playbook on demand and executes commands directly through bash.

---

## The 4-Layer Model

```
┌──────────────────────────────────────────────────────────────────┐
│                       LAYER 1: USER                              │
│                                                                  │
│              "scan example.com for vulns"                        │
│              "fix my broken nginx config"                        │
│              "set up a Minecraft server"                         │
└────────────────────────────┬─────────────────────────────────────┘
                             │ natural language
                             ▼
┌──────────────────────────────────────────────────────────────────┐
│                  LAYER 2: ORCHESTRATOR                           │
│                                                                  │
│              ┌──────────────────────────┐                        │
│              │   claudeos/CLAUDE.md     │                        │
│              │   (the main "brain")     │                        │
│              └──────────────────────────┘                        │
│                                                                  │
│  • Reads your request                                            │
│  • Knows about all 253 specialist agents                         │
│  • Picks which agent(s) to invoke                                │
│  • Coordinates multi-agent workflows                             │
│  • Asks for confirmation before destructive actions              │
│  • Verifies authorization for offensive agents                   │
│  • Logs everything to /var/log/claudeos/actions.log              │
└────────────────────────────┬─────────────────────────────────────┘
                             │ loads agent playbook(s)
                             ▼
┌──────────────────────────────────────────────────────────────────┐
│                LAYER 3: SPECIALIST AGENTS                        │
│                                                                  │
│  ┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐  │
│  │  recon-master    │ │ vulnerability-   │ │  report-writer   │  │
│  │  CLAUDE.md       │ │  scanner         │ │  CLAUDE.md       │  │
│  │                  │ │  CLAUDE.md       │ │                  │  │
│  │  Specialist's    │ │  Specialist's    │ │  Specialist's    │  │
│  │  playbook for    │ │  playbook for    │ │  playbook for    │  │
│  │  recon work      │ │  CVE scanning    │ │  pro reports     │  │
│  └──────────────────┘ └──────────────────┘ └──────────────────┘  │
│                                                                  │
│            … 253 specialist playbooks total …                    │
│                                                                  │
│  Each playbook contains:                                         │
│  • Safety rules                                                  │
│  • Real bash commands (no simulations)                           │
│  • Configuration examples                                        │
│  • Workflows for common tasks                                    │
│  • Troubleshooting guides                                        │
└────────────────────────────┬─────────────────────────────────────┘
                             │ commands from playbook
                             ▼
┌──────────────────────────────────────────────────────────────────┐
│                  LAYER 4: COMMAND EXECUTOR                       │
│                                                                  │
│              ┌──────────────────────────┐                        │
│              │  Claude Code's bash tool │                        │
│              └──────────────────────────┘                        │
│                                                                  │
│  • Actually runs the bash commands on this Linux system          │
│  • Captures stdout, stderr, exit codes                           │
│  • Asks for permission before destructive operations             │
│  • Returns output back to the orchestrator                       │
└────────────────────────────┬─────────────────────────────────────┘
                             │ command output
                             ▼
                    Results back to user
```

---

## Layer-by-Layer Explanation

### Layer 1: User

You. The human typing requests in plain English. You don't need to know which agent does what — that's the orchestrator's job.

**Example inputs:**
- "what's eating my disk space?"
- "set up SSL for mysite.com"
- "the database crashed, fix it"
- "scan the bug bounty target acme-corp.com for subdomain takeovers"

---

### Layer 2: Orchestrator (`claudeos/CLAUDE.md`)

The "brain" of ClaudeOS. This is a single Markdown file at the root of the project that defines:
- Who ClaudeOS is and how it should behave
- The full directory of all 253 specialist agents
- How to pick agents for different tasks
- Multi-agent workflow patterns
- Safety rules and authorization checks
- Quick command shortcuts

**Critically:** the orchestrator does NOT execute commands itself. It picks specialists and delegates.

When you launch ClaudeOS, this file is loaded into Claude's context. Claude then plays the role described in it — the orchestrator.

#### How the orchestrator picks an agent

For each user request, the orchestrator asks itself:
1. **What domain is this?** (security, networking, database, code...)
2. **Defensive or offensive?** (offensive needs authorization check)
3. **One agent or chain?** (complex tasks need multiple agents)
4. **Destructive?** (if yes, confirm with user first)

Then it looks up the matching agent(s) from its directory and loads their playbooks.

---

### Layer 3: Specialist Agents

Each agent is a Markdown file at `agents/{name}/CLAUDE.md`. Think of each one as an expert's notebook containing:

- **Safety rules** — what the agent will and won't do
- **Tool installation** — how to install required packages
- **Real commands** — every bash command is tested and ready to run
- **Workflows** — common task templates (multi-step procedures)
- **Troubleshooting** — fix common issues
- **Quick reference** — cheat sheet at the bottom

**Key insight:** Agents are KNOWLEDGE, not PROCESSES. Nothing is running in the background. The agent file just sits there until the orchestrator decides to load it.

When the orchestrator "invokes" an agent, what actually happens is:
1. Claude reads the agent's CLAUDE.md file
2. The contents become part of Claude's working context
3. Claude now has expert-level knowledge in that domain
4. Claude uses that knowledge to construct bash commands
5. Commands are sent to Layer 4 for execution

#### Agent categories (200 total)

| Category | Agents | Purpose |
|---|---|---|
| Core System | 9 | Essential server management |
| Infrastructure | 5 | Docker, databases, web/DNS/mail servers |
| Intelligence | 4 | Incidents, performance, cost, migration |
| DevOps | 3 | Deploys, env vars, fleet management |
| Monitoring & Alerts | 5 | Notifications, logs, SSL, snapshots, compliance |
| Advanced Operations | 6 | Firewall viz, forensics, capacity, API gateway |
| Pre-existing Specialists | 41 | Various v1 carry-overs (audit, scheduler, etc.) |
| White Hat | 13 | Defensive security testing |
| Grey Hat | 11 | Security research |
| Black Hat | 12 | Authorized offensive security |
| Red Team | 15 | Combined attack/defense operations |
| Bug Bounty Hunter | 19 | Pro toolkit including payload-crafter |
| Coder | 8 | Development and code operations |
| Fixer | 7 | Auto-repair broken systems |
| Always Up | 8 | Uptime and resilience |
| Gamer | 8 | Game server management |
| Automation | 15 | Scheduled and event-driven workflows |
| Network & Infrastructure | 9 | VPN, proxy, cluster, cloud, firewall |
| Stealth | 3 | Authorized red team trace cleaning |

---

### Layer 4: Command Executor

This is Claude Code's built-in **bash tool**. It's the only thing in ClaudeOS that actually touches your operating system.

When the orchestrator (with a loaded specialist playbook) decides to run a command, it sends it to the bash tool. The bash tool:
1. Asks for permission if the command is risky
2. Runs the command on the local Linux system
3. Captures stdout, stderr, and exit code
4. Returns the output back to Claude

Every command goes through here. There is no other execution path. This means:
- All actions are visible
- All actions can be logged
- Nothing happens behind your back

---

## Multi-Agent Workflows

Many real tasks need multiple agents. The orchestrator chains them.

### Example 1: Bug Bounty Workflow

User: *"Scan acme-corp.com for vulnerabilities and write me a HackerOne report"*

```
[User]
   │
   ▼
[Orchestrator] — picks 5 agents
   │
   ├─→ [recon-master]              ── enumerate subdomains, ports, services
   │       │
   │       └─→ [bash tool] ── runs: nmap, subfinder, httpx, naabu
   │
   ├─→ [subdomain-takeover]        ── check for dangling CNAMEs
   │       │
   │       └─→ [bash tool] ── runs: nuclei, subjack, dnsReaper
   │
   ├─→ [web-app-scanner]           ── OWASP Top 10 testing
   │       │
   │       └─→ [bash tool] ── runs: nikto, sqlmap, gobuster
   │
   ├─→ [vuln-weaponizer]           ── confirm exploitable findings
   │       │
   │       └─→ [bash tool] ── runs: metasploit, custom exploits
   │
   └─→ [report-writer]             ── compile professional report
           │
           └─→ [bash tool] ── runs: pandoc, CVSS calculator
   │
   ▼
[Final report delivered to user]
```

### Example 2: Crash Recovery

User: *"My server is down, fix it"*

```
[User]
   │
   ▼
[Orchestrator] — picks agents based on diagnosis
   │
   ├─→ [monitoring]      ── check what's failing (services, disk, RAM)
   │
   ├─→ [log-doctor]      ── parse logs, identify root cause
   │
   ├─→ [auto-healer]     ── attempt restart of failed services
   │
   └─→ [database-repair] ── if DB is the issue
   │
   ▼
[Server back online + post-mortem]
```

---

## Where Things Live

```
/Users/.../claudeos/
├── CLAUDE.md                    # Layer 2: orchestrator
├── README.md                    # User-facing docs
├── ARCHITECTURE.md              # This file
│
├── agents/                      # Layer 3: 253 specialists
│   ├── vulnerability-scanner/
│   │   └── CLAUDE.md           # Specialist playbook
│   ├── jwt-hunter/
│   │   └── CLAUDE.md
│   └── ... (253 agents)
│
├── config/                      # Configuration
│   ├── defaults.json
│   ├── notifications.json
│   └── system-info.json
│
├── scripts/                     # Helper scripts
│   ├── claudeos-cli.sh         # Main CLI
│   ├── auto-backup.sh
│   └── ...
│
├── /var/log/claudeos/           # Action logs
│   ├── actions.log
│   ├── payloads.log
│   └── engagements/
│
└── /etc/claudeos/               # System config
    ├── scope.conf
    └── authorizations/
        └── {engagement-name}/
            ├── authorization.pdf
            ├── scope.txt
            ├── out-of-scope.txt
            └── contacts.txt
```

---

## Why This Design?

### Why not separate processes per agent?
- **Simplicity** — Markdown files are easy to read, write, audit, and version-control
- **No infrastructure overhead** — no IPC, no message bus, no service mesh, no background daemons
- **Composability** — the orchestrator can chain agents instantly without process startup time
- **Transparency** — you can read every agent's playbook to know exactly what it will do
- **Easy to extend** — adding a new agent = creating one Markdown file

### Why one orchestrator instead of agents calling each other?
- **Single source of truth** — one brain decides what runs and in what order
- **Clear authorization** — all auth checks happen in one place
- **Deterministic logging** — every action funnels through the orchestrator
- **No agent loops** — agents can't call each other recursively

### Why are commands real instead of simulated?
- **Real results** — pretending to run a command gives you nothing useful
- **No wasted tokens** — simulations burn API tokens for fake output
- **Trustworthy** — what you see is what happened on your server
- **Practical** — bug bounty hunters and admins need actual data, not hypothetical data

---

## Security Model

### Defense-in-depth at every layer

| Layer | Protection |
|---|---|
| **User** | You always see what's about to happen before it happens |
| **Orchestrator** | Verifies authorization, refuses out-of-scope actions, logs everything |
| **Specialists** | Each agent has explicit Safety Rules at the top |
| **Executor** | Asks for confirmation before destructive operations |

### Authorization for offensive agents

For White/Grey/Black Hat, Red Team, Bug Bounty, and Stealth agents, the orchestrator checks:

1. **Engagement exists** in `/etc/claudeos/authorizations/{engagement-name}/`
2. **Target is in scope** (`scope.txt` allowlist)
3. **Target is NOT out of scope** (`out-of-scope.txt` denylist)
4. **Current date is within window** (`start-date` to `end-date`)

If any check fails → orchestrator REFUSES to act.

### Action logging

Every action is logged to `/var/log/claudeos/actions.log`:
```
[2026-04-11 15:30:00] AGENT=vulnerability-scanner TARGET=10.0.0.5 ACTION="nmap -sV"
[2026-04-11 15:31:00] AGENT=jwt-hunter ENGAGEMENT=acme-corp FINDING="weak HMAC"
[2026-04-11 15:35:00] AGENT=auto-healer ACTION="restart nginx" REASON="health check failed"
```

---

## Adding a New Agent

To add a 201st agent:

1. **Create the directory:**
   ```bash
   mkdir -p agents/my-new-agent
   ```

2. **Write the playbook:**
   ```bash
   cat > agents/my-new-agent/CLAUDE.md <<'EOF'
   # My New Agent

   You are the My New Agent for ClaudeOS. You [what it does].

   ## Safety Rules
   - [rules]

   ## Tool Installation
   ```bash
   # install commands
   ```

   ## Workflows
   ```bash
   # real working commands
   ```
   EOF
   ```

3. **Register with the orchestrator:**
   Add a row to `claudeos/CLAUDE.md` under the appropriate category.

4. **Done.** No restart, no recompile, no service reload. The next time the orchestrator runs, it knows about your new agent.

---

## Frequently Asked Questions

**Q: Are agents running 24/7?**
A: No. Agents are just Markdown files. They are loaded on demand when the orchestrator needs them.

**Q: Can two agents run in parallel?**
A: Yes — the orchestrator can invoke multiple agents in sequence, and the bash tool can run commands in the background. But there's no agent process running independently.

**Q: How does ClaudeOS know which agent to pick?**
A: The orchestrator (`claudeos/CLAUDE.md`) has a directory of all 200 agents with their specialties. It matches your request to the right specialist using natural language understanding.

**Q: What if the orchestrator picks the wrong agent?**
A: You can call agents by name: *"use the jwt-hunter agent on this token"*. The orchestrator will load that specific playbook.

**Q: Can agents call other agents?**
A: Indirectly. An agent can suggest "next, run the report-writer agent on this output" — the orchestrator sees that and chains them.

**Q: Where do I see what commands actually ran?**
A: `/var/log/claudeos/actions.log` — every action is timestamped and tagged with agent + target.

**Q: Can I disable an agent I don't trust?**
A: Yes. Either delete its directory (`rm -rf agents/some-agent/`) or remove it from the orchestrator's directory in `claudeos/CLAUDE.md`. The orchestrator won't know to use it anymore.

---

## Summary

ClaudeOS is **just text and bash**. The orchestrator is a Markdown file. The agents are Markdown files. Commands run through Claude Code's bash tool. There's no magic, no daemons, no hidden complexity.

That simplicity is the design. It makes ClaudeOS:
- **Auditable** — read any file to know what it does
- **Hackable** — add or modify agents in seconds
- **Trustworthy** — nothing runs in the background without your knowledge
- **Powerful** — 253 specialists at your fingertips with one natural language interface

That's the whole architecture.
