# ClaudeOS Agent Discovery Guide

**Can't find the right wolf? This guide maps common tasks to the agents that handle them.**

---

## 🔍 "I want to scan for vulnerabilities"

| What you want | Agent to use | Directory |
|---|---|---|
| Port scanning / service detection | `network-mapper` | `agents/network-mapper/` |
| Web vulnerability scanning | `web-app-scanner` | `agents/web-app-scanner/` |
| CVE scanning | `vulnerability-scanner` | `agents/vulnerability-scanner/` |
| Full recon pipeline | `bug-bounty-hunter` | `agents/bug-bounty-hunter/` |
| Nuclei scanning | `nuclei-master` | `agents/nuclei-master/` |

## 🌐 "I want to find subdomains"

| What you want | Agent to use | Directory |
|---|---|---|
| Passive subdomain discovery | `subdomain-bruteforcer` | `agents/subdomain-bruteforcer/` |
| Full recon (subdomains + URLs + tech) | `recon-master` | `agents/recon-master/` |
| Subdomain takeover check | `subdomain-takeover` | `agents/subdomain-takeover/` |
| Certificate transparency search | `recon-master` | `agents/recon-master/` |

## 🔐 "I want to test authentication"

| What you want | Agent to use | Directory |
|---|---|---|
| OAuth vulnerabilities | `oauth-tester` | `agents/oauth-tester/` |
| SAML attacks | `saml-tester` | `agents/saml-tester/` |
| SSO domain mapping | `sso-analyzer` | `agents/sso-analyzer/` |
| JWT vulnerabilities | `jwt-hunter` | `agents/jwt-hunter/` |
| Password reset flaws | `password-reset-tester` | `agents/password-reset-tester/` |
| Account takeover | `account-takeover-hunter` | `agents/account-takeover-hunter/` |
| Credential testing | `credential-tester` | `agents/credential-tester/` |
| MFA bypass | `account-takeover-hunter` | `agents/account-takeover-hunter/` |

## 💉 "I want to test for injection"

| What you want | Agent to use | Directory |
|---|---|---|
| XSS | `xss-hunter` | `agents/xss-hunter/` |
| SQL Injection | `sqli-hunter` | `agents/sqli-hunter/` |
| SSRF | `ssrf-hunter` | `agents/ssrf-hunter/` |
| XXE | `xxe-hunter` | `agents/xxe-hunter/` |
| SSTI | `ssti-hunter` | `agents/ssti-hunter/` |
| Command injection | `exploit-researcher` | `agents/exploit-researcher/` |
| Prototype pollution | `prototype-pollution-hunter` | `agents/prototype-pollution-hunter/` |
| CSRF | `csrf-hunter` | `agents/csrf-hunter/` |
| LFI | `lfi-hunter` | `agents/lfi-hunter/` |

## 🔓 "I want to test access control"

| What you want | Agent to use | Directory |
|---|---|---|
| IDOR / BOLA | `idor-hunter` | `agents/idor-hunter/` |
| CORS misconfiguration | `cors-tester` | `agents/cors-tester/` |
| Business logic bugs | `business-logic-hunter` | `agents/business-logic-hunter/` |
| E-commerce bugs | `ecommerce-hunter` | `agents/ecommerce-hunter/` |
| Permission escalation | `privilege-escalator` | `agents/privilege-escalator/` |

## 📱 "I want to test APIs"

| What you want | Agent to use | Directory |
|---|---|---|
| GraphQL testing | `graphql-hunter` | `agents/graphql-hunter/` |
| REST API fuzzing | `api-fuzzer` | `agents/api-fuzzer/` |
| Hidden parameters | `param-finder` | `agents/param-finder/` |
| API parameter brute force | `api-parameter-bruter` | `agents/api-parameter-bruter/` |
| Swagger/OpenAPI discovery | `swagger-extractor` | `agents/swagger-extractor/` |
| Request smuggling | `request-smuggler` | `agents/request-smuggler/` |

## ☁️ "I want to test cloud"

| What you want | Agent to use | Directory |
|---|---|---|
| AWS testing | `aws-tester` | `agents/aws-tester/` |
| S3 bucket discovery | `s3-bucket-finder` | `agents/s3-bucket-finder/` |
| Cloud recon + misconfig | `cloud-recon` | `agents/cloud-recon/` |
| Kubernetes testing | `kubernetes-tester` | `agents/kubernetes-tester/` |
| Container escape | `container-escape` | `agents/container-escape/` |
| GitHub secret scanning | `github-recon` | `agents/github-recon/` |

## 🤖 "I want to test AI/LLM"

| What you want | Agent to use | Directory |
|---|---|---|
| Prompt injection | `prompt-injection-tester` | `agents/prompt-injection-tester/` |
| Jailbreaking | `ai-jailbreaker` | `agents/ai-jailbreaker/` |
| Model extraction | `model-extractor` | `agents/model-extractor/` |

## 🔗 "I want to test supply chain"

| What you want | Agent to use | Directory |
|---|---|---|
| Dependency confusion | `supply-chain-attacker` | `agents/supply-chain-attacker/` |
| Package analysis | `supply-chain-attacker` | `agents/supply-chain-attacker/` |
| CI/CD vulnerabilities | `supply-chain-attacker` | `agents/supply-chain-attacker/` |

## 🛡️ "I want to protect/defend"

| What you want | Agent to use | Directory |
|---|---|---|
| DDoS protection | `ddos-shield` | `agents/ddos-shield/` |
| Firewall management | `firewall-architect` | `agents/firewall-architect/` |
| Firewall visualization | `firewall-visualizer` | `agents/firewall-visualizer/` |
| Security hardening | `config-hardener` | `agents/config-hardener/` |
| Real-time monitoring | `defense-monitor` | `agents/defense-monitor/` |
| Intrusion detection | `security` | `agents/security/` |
| SSL/TLS management | `ssl-watchdog` | `agents/ssl-watchdog/` |
| Uptime monitoring | `uptime-guardian` | `agents/uptime-guardian/` |

## 🕵️ "I want to intercept traffic"

| What you want | Agent to use | Directory |
|---|---|---|
| HTTP proxy (Burp-style) | `web-proxy-agent` | `agents/web-proxy-agent/` |
| Network sniffing | `network-sniffer` | `agents/network-sniffer/` |
| Traffic analysis | `traffic-analyzer` | `agents/traffic-analyzer/` |
| WebSocket testing | `websocket-tester` | `agents/websocket-tester/` |

## 🏗️ "I want to extract/analyze"

| What you want | Agent to use | Directory |
|---|---|---|
| JavaScript analysis | `js-analyzer` + `js-endpoint-extractor` | `agents/js-analyzer/` |
| Source map extraction | `sourcemap-extractor` | `agents/sourcemap-extractor/` |
| Config file discovery | `config-extractor` | `agents/config-extractor/` |
| APK decompilation | `apk-extractor` | `agents/apk-extractor/` |
| Git repo extraction | `git-extractor` | `agents/git-extractor/` |
| Error harvesting | `error-extractor` | `agents/error-extractor/` |

## 🐺 "I want the pack to hunt autonomously"

| What you want | Agent to use | Directory |
|---|---|---|
| Full autonomous hunt | `multi-agent-bounty-hunter` | `agents/multi-agent-bounty-hunter/` |
| Recon pipeline | `recon-orchestrator` | `agents/recon-orchestrator/` |
| Red team operation | `red-commander` | `agents/red-commander/` |
| Target selection | `target-pipeline` | `agents/target-pipeline/` |

## 🎯 "I want to bypass WAF"

| What you want | Agent to use | Directory |
|---|---|---|
| WAF identification | `waf-fingerprinter` | `agents/waf-fingerprinter/` |
| Cloudflare bypass | `waf-cloudflare-bypass` | `agents/waf-cloudflare-bypass/` |
| Akamai bypass | `waf-akamai-bypass` | `agents/waf-akamai-bypass/` |
| AWS WAF bypass | `waf-aws-bypass` | `agents/waf-aws-bypass/` |
| Payload encoding | `waf-payload-encoder` | `agents/waf-payload-encoder/` |
| Origin IP discovery | `origin-finder` | `agents/origin-finder/` |

---

## How to Use an Agent

```
# Read the agent's playbook
cat agents/<agent-name>/CLAUDE.md

# The playbook contains:
# - Safety rules
# - Setup commands
# - Testing commands
# - Quick reference
```

## Total Pack Size: 340+ wolves

Every wolf has a purpose. No wolf sits idle. If you can't find what you need, ask the Alpha — or use the **Agent Architect** (`agents/agent-architect/`) to build a new one.
