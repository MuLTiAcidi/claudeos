# CDN Bypass Agent

Find the origin server IP behind CDN/WAF protection (Cloudflare, Akamai, Fastly, AWS CloudFront). Once found, direct requests to the origin bypass all WAF rules, rate limits, and geo-restrictions.

## Prerequisites

```bash
which curl || apt install -y curl
which dig || apt install -y dnsutils
which nmap || apt install -y nmap
which jq || apt install -y jq
pip3 install censys shodan
```

## Phase 1: DNS History Lookup

Old DNS records often reveal the origin IP from before CDN was added.

```bash
DOMAIN="$TARGET"

# SecurityTrails API (free tier: 50 req/month)
curl -s "https://api.securitytrails.com/v1/history/$DOMAIN/dns/a" \
  -H "APIKEY: $SECURITYTRAILS_KEY" | jq '.records[].values[].ip'

# ViewDNS.info
curl -s "https://viewdns.info/iphistory/?domain=$DOMAIN" | \
  grep -oP '\d+\.\d+\.\d+\.\d+' | sort -u

# Check if any historical IPs still serve the site
for IP in $(cat history_ips.txt); do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" -H "Host: $DOMAIN" "https://$IP/")
  echo "$IP -> $CODE"
done
```

## Phase 2: Certificate Transparency Search

Certificates are tied to IPs. Search Censys/crt.sh for certs issued to the domain.

```bash
# crt.sh — free, no API key
curl -s "https://crt.sh/?q=%.$DOMAIN&output=json" | \
  jq -r '.[].common_name' | sort -u

# Censys — search for certificates matching the domain
censys search "services.tls.certificates.leaf.names: $DOMAIN" \
  --index-type hosts -f ip | head -50

# Censys — search by organization name
censys search "services.tls.certificates.leaf.subject.organization: \"$ORG_NAME\"" \
  --index-type hosts -f ip

# Shodan — search for SSL cert
curl -s "https://api.shodan.io/shodan/host/search?key=$SHODAN_KEY&query=ssl.cert.subject.CN:$DOMAIN" | \
  jq '.matches[].ip_str' | sort -u
```

## Phase 3: Email Header Analysis

If the target sends emails (signup, password reset, notifications), the Received headers may leak the origin.

```bash
# Trigger an email from the target
# (register an account, request password reset, contact form, newsletter signup)

# Then inspect raw email headers — look for:
# Received: from mail.target.com (ORIGIN_IP)
# X-Originating-IP: [ORIGIN_IP]
# Return-Path: bounce@ORIGIN_IP

# Check MX records — sometimes MX points to origin
dig MX "$DOMAIN" +short
# If MX is mail.target.com (not a third-party), resolve it:
dig A "$(dig MX $DOMAIN +short | awk '{print $2}')" +short
```

## Phase 4: Subdomain IP Comparison

Subdomains often point directly to the origin while the main domain uses CDN.

```bash
# Enumerate subdomains
subfinder -d "$DOMAIN" -silent | tee subs.txt

# Resolve all subdomains
while read SUB; do
  IP=$(dig +short A "$SUB" | tail -1)
  echo "$SUB -> $IP"
done < subs.txt | tee sub_ips.txt

# Filter out known CDN ranges
# Cloudflare: 104.16.0.0/12, 172.64.0.0/13, 131.0.72.0/22, 173.245.48.0/20
# Akamai: check https://techdocs.akamai.com/property-mgr/docs/edge-ip-addresses
# Fastly: 151.101.0.0/16, 199.232.0.0/16

# IPs NOT in CDN ranges are likely the origin
grep -vE "104\.1[6-9]\.|104\.2[0-9]\.|172\.6[4-9]\.|131\.0\.7[2-5]\." sub_ips.txt

# Verify candidate IPs serve the main site
for IP in $(cat candidate_ips.txt); do
  curl -sk -H "Host: $DOMAIN" "https://$IP/" -o /dev/null -w "$IP: %{http_code}\n"
done
```

## Phase 5: Direct IP Scanning

Scan the target's ASN range for the origin server.

```bash
# Find the organization's ASN
curl -s "https://api.bgpview.io/search?query_term=$DOMAIN" | jq '.data.asns'
# Or:
whois -h whois.radb.net "!g$DOMAIN"

# Get IP prefixes for the ASN
curl -s "https://api.bgpview.io/asn/$ASN/prefixes" | jq -r '.data.ipv4_prefixes[].prefix'

# Scan prefixes for the target on port 443
nmap -sS -p 443 --open -iL asn_prefixes.txt -oG scan_results.txt

# Check each open 443 for the target's hostname
for IP in $(grep "443/open" scan_results.txt | awk '{print $2}'); do
  TITLE=$(curl -sk -H "Host: $DOMAIN" "https://$IP/" | grep -oP '(?<=<title>).*?(?=</title>)')
  echo "$IP: $TITLE"
done
```

## Phase 6: Favicon Hash Matching (Shodan)

The favicon hash is a fingerprint. Search Shodan for servers with the same favicon.

```bash
# Get the favicon hash
python3 -c "
import requests, hashlib, codecs, mmh3
r = requests.get('https://$DOMAIN/favicon.ico', verify=False)
favicon = codecs.encode(r.content, 'base64')
print(f'http.favicon.hash:{mmh3.hash(favicon)}')
"

# Search Shodan with the hash
FAVICON_HASH=$(python3 -c "import requests,codecs,mmh3; r=requests.get('https://$DOMAIN/favicon.ico',verify=False); print(mmh3.hash(codecs.encode(r.content,'base64')))")
curl -s "https://api.shodan.io/shodan/host/search?key=$SHODAN_KEY&query=http.favicon.hash:$FAVICON_HASH" | \
  jq '.matches[] | {ip: .ip_str, port: .port, org: .org}'
```

## Phase 7: Outbound Connection Triggers

Force the server to make an outbound connection that reveals its IP.

```bash
# If SSRF exists, point it at your server
# Use Burp Collaborator, interact.sh, or your own listener
CALLBACK="https://YOUR_CALLBACK_SERVER/cdn-check"

# Common SSRF vectors:
# - Webhook URLs in app settings
# - PDF generators (URL to PDF)
# - Image URL imports (avatar upload by URL)
# - Open redirect chains

# Listen for incoming connections
# On your server:
python3 -m http.server 8888 &
# Check access logs for the origin IP

# interact.sh (free OOB server)
curl -s "https://interact.sh/register" | jq '.data'
# Use the generated subdomain as callback, check results
```

## Phase 8: Virtual Host Enumeration

Try common vhost names against candidate IPs.

```bash
# For each candidate IP, try common vhost patterns
IP="$CANDIDATE_IP"
for VHOST in "$DOMAIN" "www.$DOMAIN" "api.$DOMAIN" "staging.$DOMAIN" "dev.$DOMAIN" "origin.$DOMAIN" "direct.$DOMAIN"; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" -H "Host: $VHOST" "https://$IP/")
  SIZE=$(curl -sk -H "Host: $VHOST" "https://$IP/" | wc -c)
  echo "$VHOST @ $IP -> $CODE ($SIZE bytes)"
done
```

## Phase 9: Verification

Once you have a candidate origin IP, confirm it.

```bash
ORIGIN_IP="$CANDIDATE"

# 1. Does it serve the same content?
diff <(curl -sk "https://$DOMAIN/" | md5sum) \
     <(curl -sk -H "Host: $DOMAIN" "https://$ORIGIN_IP/" | md5sum)

# 2. Does it respond to the domain's Host header?
curl -sk -D- -H "Host: $DOMAIN" "https://$ORIGIN_IP/" | head -20

# 3. Is the WAF bypassed? (send a blocked payload directly to origin)
curl -sk -H "Host: $DOMAIN" "https://$ORIGIN_IP/?q=<script>alert(1)</script>" \
  -o /dev/null -w "%{http_code}"

# 4. Check if origin restricts connections to CDN IPs only (proper config)
curl -sk --connect-timeout 5 -H "Host: $DOMAIN" "https://$ORIGIN_IP/" \
  -o /dev/null -w "%{http_code}"
# If 403 or timeout, origin is properly locked down
```

## Severity Classification

| Finding | Severity |
|---------|----------|
| Origin IP exposed, accepts direct connections, no WAF | High |
| Origin IP found but restricts to CDN source IPs | Low (info) |
| Origin IP found, WAF bypassed, sensitive endpoints reachable | Critical |
| Multiple origin IPs found across services | Medium |

## Output Format

For each finding:
1. **Origin IP**: The discovered IP address
2. **Discovery Method**: Which technique found it
3. **Verification**: Proof it serves the target's content
4. **WAF Bypass Confirmed**: Yes/No (can payloads reach origin unfiltered?)
5. **Remediation**: Restrict origin to CDN IP ranges only (Cloudflare authenticated origin pulls, AWS security groups, iptables)

## Rules

- Only test on authorized targets within scope
- Never exploit access to the origin for data exfiltration
- Report origin exposure as a finding, don't chain further without permission
- Include `X-HackerOne-Research` header on all requests
- Document every technique attempted, not just successes
