#!/bin/bash
# ClaudeOS — Pre-built Workflows
# Run multi-agent workflows with one command
# Usage: claudeos workflow <name> <target>

WORKFLOWS_DIR="${WORKFLOWS_DIR:-$HOME/.claudeos/workflows}"
ENGAGEMENTS_DIR="${ENGAGEMENTS_DIR:-$HOME/.claudeos/engagements}"
ACTIVE_FILE="$HOME/.claudeos/active-engagement"

mkdir -p "$WORKFLOWS_DIR"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

active_engagement() {
    [ -f "$ACTIVE_FILE" ] && cat "$ACTIVE_FILE"
}

get_workdir() {
    local engagement=$(active_engagement)
    if [ -n "$engagement" ]; then
        echo "$ENGAGEMENTS_DIR/$engagement"
    else
        echo "$(pwd)/claudeos-output-$(date +%s)"
    fi
}

list_workflows() {
    cat <<EOF

${BOLD}${BLUE}Available Workflows${NC}

${BOLD}Bug Bounty:${NC}
  ${GREEN}bug-bounty${NC} <target>     Full BB recon → scan → report pipeline
  ${GREEN}recon${NC} <target>          Subdomain enum + port scan + screenshots
  ${GREEN}quick-scan${NC} <target>     Fast nuclei + nikto + dirb on a single host
  ${GREEN}deep-scan${NC} <target>      Full vulnerability scan (slow but thorough)
  ${GREEN}js-hunt${NC} <target>        Find JS files, extract endpoints + secrets
  ${GREEN}cloud-audit${NC} <target>    AWS/GCP/Azure misconfigurations
  ${GREEN}wordpress${NC} <target>      Full WordPress security check
  ${GREEN}api-audit${NC} <target>      REST/GraphQL API security audit
  ${GREEN}subtake${NC} <target>        Hunt subdomain takeovers

${BOLD}Pentest:${NC}
  ${GREEN}network-pentest${NC} <range> Network discovery + vuln scan + exploit
  ${GREEN}ad-pentest${NC} <dc-ip>      Active Directory full pentest
  ${GREEN}internal-recon${NC}          Recon from inside the network

${BOLD}Defensive:${NC}
  ${GREEN}harden${NC}                  Full system hardening sweep
  ${GREEN}vuln-assessment${NC}         Local vulnerability assessment
  ${GREEN}compliance${NC} <standard>   Run compliance checks (pci/hipaa/soc2/gdpr)

${BOLD}Operations:${NC}
  ${GREEN}health-check${NC}            Full system health diagnostic
  ${GREEN}post-incident${NC}           Post-incident analysis & log forensics
  ${GREEN}backup-verify${NC}           Verify all backups + restore test

${BOLD}Usage:${NC}
  claudeos workflow <name> [target]
  claudeos workflow list
  claudeos workflow show <name>

${BOLD}Tip:${NC} Start an engagement first to organize output:
  ${CYAN}claudeos engagement start <name>${NC}

EOF
}

run_bug_bounty() {
    local target="$1"
    [ -z "$target" ] && echo -e "${RED}Usage: claudeos workflow bug-bounty <target>${NC}" && return 1

    local workdir=$(get_workdir)
    mkdir -p "$workdir/recon" "$workdir/scans" "$workdir/screenshots"

    echo ""
    echo -e "${BOLD}${BLUE}Bug Bounty Workflow${NC}"
    echo -e "${CYAN}Target: $target${NC}"
    echo -e "${CYAN}Workdir: $workdir${NC}"
    echo ""
    echo -e "${BOLD}Pipeline:${NC}"
    echo -e "  1. recon-master       — subdomain enumeration"
    echo -e "  2. screenshot-hunter  — visual recon"
    echo -e "  3. js-analyzer        — extract endpoints + secrets from JS"
    echo -e "  4. subdomain-takeover — check for takeovers"
    echo -e "  5. nuclei-master      — vulnerability templates"
    echo -e "  6. web-app-scanner    — OWASP Top 10"
    echo -e "  7. report-writer      — compile findings"
    echo ""

    cat > "$workdir/workflow-prompt.txt" <<EOF
Run a full bug bounty workflow against $target. Save all output to $workdir/.

Pipeline:
1. Use recon-master to enumerate subdomains: subfinder, amass, assetfinder. Save to $workdir/recon/subdomains.txt
2. Probe live hosts with httpx. Save to $workdir/recon/live.txt
3. Use screenshot-hunter to screenshot all live hosts to $workdir/screenshots/
4. Use js-analyzer to crawl and extract endpoints from JS files. Save to $workdir/recon/js-endpoints.txt and js-secrets.txt
5. Use subdomain-takeover to check all subdomains for takeover-able CNAMEs
6. Use nuclei-master to scan all live hosts with critical/high templates
7. Use web-app-scanner for OWASP Top 10 testing on top targets
8. Use report-writer to compile findings into $workdir/findings-report.md

For each finding, add to the findings tracker:
  claudeos findings add

Stop and ask before any aggressive testing or large scope scans.
EOF

    echo -e "${GREEN}✓${NC} Workflow prepared. Open ClaudeOS to run it:"
    echo ""
    echo -e "  ${CYAN}claudeos${NC}"
    echo -e "  ${CYAN}> Run the workflow at $workdir/workflow-prompt.txt${NC}"
    echo ""
    echo -e "Or copy the prompt:"
    echo -e "  ${CYAN}cat $workdir/workflow-prompt.txt${NC}"
}

run_recon() {
    local target="$1"
    [ -z "$target" ] && echo -e "${RED}Usage: claudeos workflow recon <target>${NC}" && return 1

    local workdir=$(get_workdir)
    mkdir -p "$workdir/recon"

    cat > "$workdir/workflow-prompt.txt" <<EOF
Run a recon workflow against $target. Save output to $workdir/recon/.

1. recon-master: subfinder + amass + assetfinder for subdomains
2. naabu/nmap: port scan top ports on each subdomain
3. httpx: probe HTTP/HTTPS on discovered hosts
4. screenshot-hunter: visual recon of all live web hosts
5. nmap -sV: service version detection on open ports
6. tech detection (whatweb / wappalyzer)

Output structure:
  $workdir/recon/
  ├── subdomains.txt
  ├── live-hosts.txt
  ├── ports.txt
  ├── services.json
  └── screenshots/
EOF

    echo -e "${GREEN}✓${NC} Recon workflow ready: $workdir/workflow-prompt.txt"
    echo -e "Run: ${CYAN}claudeos${NC}"
}

run_quick_scan() {
    local target="$1"
    [ -z "$target" ] && echo -e "${RED}Usage: claudeos workflow quick-scan <target>${NC}" && return 1
    local workdir=$(get_workdir)

    cat > "$workdir/workflow-prompt.txt" <<EOF
Quick vulnerability scan on $target. Save to $workdir/quick-scan/.

1. nuclei -severity critical,high,medium $target
2. nikto -h $target
3. gobuster dir -u $target -w common.txt
4. nmap -sV --script vuln $target

Compile findings into $workdir/quick-scan/summary.md
EOF
    echo -e "${GREEN}✓${NC} Quick scan workflow ready"
}

run_wordpress() {
    local target="$1"
    [ -z "$target" ] && echo -e "${RED}Usage: claudeos workflow wordpress <target>${NC}" && return 1
    local workdir=$(get_workdir)

    cat > "$workdir/workflow-prompt.txt" <<EOF
Full WordPress security audit of $target.

1. wordpress-hunter: wpscan with --enumerate vp,vt,u,ap,at,cb,dbe
2. Check for exposed wp-config.php, debug.log, backup files
3. Test xmlrpc.php for amplification + brute force
4. Check REST API user enumeration: /wp-json/wp/v2/users
5. Test known plugin CVEs
6. Save all findings to $workdir/wordpress-audit.md
EOF
    echo -e "${GREEN}✓${NC} WordPress workflow ready"
}

run_subtake() {
    local target="$1"
    [ -z "$target" ] && echo -e "${RED}Usage: claudeos workflow subtake <target>${NC}" && return 1
    local workdir=$(get_workdir)

    cat > "$workdir/workflow-prompt.txt" <<EOF
Subdomain takeover hunt on $target.

1. recon-master: enumerate ALL subdomains (subfinder + amass + assetfinder + crt.sh)
2. Filter for CNAME records pointing to known takeover-able services
3. subdomain-takeover: validate each candidate with subjack, subzy, dnsReaper, nuclei takeovers
4. For confirmed takeovers, document with PoC
5. Save report to $workdir/takeovers.md
EOF
    echo -e "${GREEN}✓${NC} Subdomain takeover workflow ready"
}

run_harden() {
    local workdir=$(get_workdir)
    cat > "$workdir/workflow-prompt.txt" <<EOF
Full system hardening sweep on this server.

1. config-hardener: harden SSH, kernel sysctl, services
2. security-auditor: run lynis audit
3. access-auditor: audit users, sudoers, SUID binaries
4. encryption-enforcer: verify disk + transit encryption
5. firewall-architect: review and tighten firewall rules
6. compliance-checker: run CIS benchmark
7. Save full hardening report to $workdir/hardening-report.md

Ask before applying changes that could cause downtime.
EOF
    echo -e "${GREEN}✓${NC} Hardening workflow ready"
}

run_health_check() {
    local workdir=$(get_workdir)
    cat > "$workdir/workflow-prompt.txt" <<EOF
Full system health check.

1. monitoring: CPU, RAM, disk, processes, top consumers
2. log-doctor: parse logs for errors, OOM kills, segfaults, disk full
3. process-forensics: anomaly detection on running processes
4. crash-analyzer: check for recent crashes
5. service-healer: list any failing services
6. heartbeat-monitor: verify all critical services responding
7. Compile health report to $workdir/health-report.md
EOF
    echo -e "${GREEN}✓${NC} Health check workflow ready"
}

run_ad_pentest() {
    local dc="$1"
    [ -z "$dc" ] && echo -e "${RED}Usage: claudeos workflow ad-pentest <dc-ip>${NC}" && return 1
    local workdir=$(get_workdir)

    cat > "$workdir/workflow-prompt.txt" <<EOF
Active Directory pentest against DC $dc.

1. ldap-tester: anonymous bind enumeration
2. smb-tester: enum4linux-ng, smbmap, signing check
3. ad-attacker: BloodHound bloodhound-python
4. kerberos-attacker: kerbrute user enum, ASREPRoasting (GetNPUsers.py), Kerberoasting (GetUserSPNs.py)
5. credential-tester: password spraying with discovered users
6. lateral-mover: if creds found, attempt lateral movement
7. report-writer: compile pentest report

Save output to $workdir/ad-pentest/
EOF
    echo -e "${GREEN}✓${NC} AD pentest workflow ready"
}

show_workflow() {
    local name="$1"
    [ -z "$name" ] && list_workflows && return
    local workdir=$(get_workdir)
    if [ -f "$workdir/workflow-prompt.txt" ]; then
        echo -e "${CYAN}Last workflow:${NC}"
        cat "$workdir/workflow-prompt.txt"
    else
        echo -e "${YELLOW}No workflow generated yet. Run: claudeos workflow $name <target>${NC}"
    fi
}

case "${1:-list}" in
    bug-bounty|bb)
        run_bug_bounty "$2"
        ;;
    recon)
        run_recon "$2"
        ;;
    quick-scan|quick)
        run_quick_scan "$2"
        ;;
    wordpress|wp)
        run_wordpress "$2"
        ;;
    subtake|takeover)
        run_subtake "$2"
        ;;
    harden|hardening)
        run_harden
        ;;
    health-check|health)
        run_health_check
        ;;
    ad-pentest|ad)
        run_ad_pentest "$2"
        ;;
    list|ls|"")
        list_workflows
        ;;
    show)
        show_workflow "$2"
        ;;
    help|--help|-h)
        list_workflows
        ;;
    *)
        echo -e "${RED}Unknown workflow: $1${NC}"
        list_workflows
        ;;
esac
