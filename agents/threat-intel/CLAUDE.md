# Threat Intel

Automated threat intelligence agent for monitoring threat feeds, matching indicators of compromise (IOCs), checking dark web exposure, and maintaining blocklists across your infrastructure.

## Safety Rules

- Only query and scan assets that you own or have explicit authorization to investigate
- Respect all API rate limits — implement backoff and caching to avoid bans
- Store API keys and credentials in environment variables or a secrets manager, never in plaintext files
- Never share raw IOC data, threat reports, or indicators publicly without sanitization
- Log all queries for auditability but redact sensitive values from logs
- Validate all input before passing to external APIs to prevent injection
- Do not attempt to access dark web resources directly — use authorized feed APIs only
- Always verify the provenance of threat intelligence before acting on it
- Quarantine suspicious artifacts in isolated environments only
- Follow responsible disclosure practices for any vulnerabilities discovered

---

## 1. Threat Feed Setup

### 1.1 MISP Instance Configuration

```bash
# Install MISP dependencies (Ubuntu/Debian)
sudo apt-get update && sudo apt-get install -y \
  python3-pip python3-venv git curl jq

# Install PyMISP client library
pip3 install pymisp

# Set MISP connection variables
export MISP_URL="https://misp.yourdomain.com"
export MISP_API_KEY="your-misp-api-key-here"

# Test MISP connectivity
curl -s -k \
  -H "Authorization: ${MISP_API_KEY}" \
  -H "Accept: application/json" \
  "${MISP_URL}/servers/getVersion" | jq .

# List available MISP feeds
curl -s -k \
  -H "Authorization: ${MISP_API_KEY}" \
  -H "Accept: application/json" \
  "${MISP_URL}/feeds/index" | jq '.[].Feed.name'

# Enable a specific MISP feed by ID
curl -s -k -X POST \
  -H "Authorization: ${MISP_API_KEY}" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{"enabled": true}' \
  "${MISP_URL}/feeds/enable/FEED_ID" | jq .

# Fetch latest events from MISP (last 24 hours)
curl -s -k -X POST \
  -H "Authorization: ${MISP_API_KEY}" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{"last":"1d","enforceWarninglist":true}' \
  "${MISP_URL}/events/restSearch" | jq '.response[].Event.info'

# Pull all attributes of type ip-dst from MISP
curl -s -k -X POST \
  -H "Authorization: ${MISP_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"type":"ip-dst","last":"7d","enforceWarninglist":true}' \
  "${MISP_URL}/attributes/restSearch" | jq '.response.Attribute[].value'
```

### 1.2 OTX AlienVault Feed

```bash
# Set OTX API key
export OTX_API_KEY="your-otx-api-key-here"

# Fetch subscribed pulses (last 7 days)
curl -s \
  -H "X-OTX-API-KEY: ${OTX_API_KEY}" \
  "https://otx.alienvault.com/api/v1/pulses/subscribed?modified_since=$(date -d '7 days ago' +%Y-%m-%dT%H:%M:%S)&limit=50" \
  | jq '.results[].name'

# Get indicators from a specific pulse
PULSE_ID="your-pulse-id"
curl -s \
  -H "X-OTX-API-KEY: ${OTX_API_KEY}" \
  "https://otx.alienvault.com/api/v1/pulses/${PULSE_ID}/indicators" \
  | jq '.results[] | {type: .type, indicator: .indicator}'

# Search OTX for a specific indicator
curl -s \
  -H "X-OTX-API-KEY: ${OTX_API_KEY}" \
  "https://otx.alienvault.com/api/v1/indicators/IPv4/8.8.8.8/general" \
  | jq '{reputation: .reputation, pulse_count: .pulse_info.count}'

# Export all IPv4 indicators from subscribed pulses
curl -s \
  -H "X-OTX-API-KEY: ${OTX_API_KEY}" \
  "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=100" \
  | jq -r '.results[].indicators[] | select(.type=="IPv4") | .indicator' \
  | sort -u > /tmp/otx_malicious_ips.txt

echo "Collected $(wc -l < /tmp/otx_malicious_ips.txt) unique malicious IPs from OTX"
```

### 1.3 abuse.ch Feeds

```bash
# Download URLhaus malicious URL feed
curl -s "https://urlhaus.abuse.ch/downloads/csv_recent/" \
  | grep -v "^#" | tail -n +2 \
  > /tmp/urlhaus_recent.csv

echo "URLhaus entries: $(wc -l < /tmp/urlhaus_recent.csv)"

# Download Feodo Tracker botnet C2 IPs
curl -s "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt" \
  | grep -v "^#" | grep -v "^$" \
  > /tmp/feodo_c2_ips.txt

echo "Feodo C2 IPs: $(wc -l < /tmp/feodo_c2_ips.txt)"

# Download MalBazaar recent malware hashes
curl -s "https://bazaar.abuse.ch/export/csv/recent/" \
  | grep -v "^#" | tail -n +2 \
  > /tmp/malbazaar_recent.csv

echo "MalBazaar recent samples: $(wc -l < /tmp/malbazaar_recent.csv)"

# Download SSL blacklist (malicious SSL certificates)
curl -s "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv" \
  | grep -v "^#" | tail -n +2 \
  > /tmp/ssl_blacklist.csv

echo "SSL blacklist entries: $(wc -l < /tmp/ssl_blacklist.csv)"

# Download ThreatFox IOCs (last 7 days)
curl -s -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"get_iocs","days":7}' \
  "https://threatfox-api.abuse.ch/api/v1/" \
  | jq '.data[:10][] | {ioc: .ioc, type: .ioc_type, threat: .threat_type}'
```

---

## 2. IOC Matching

### 2.1 Check IPs Against Feeds

```bash
# Build a consolidated malicious IP list
cat /tmp/feodo_c2_ips.txt /tmp/otx_malicious_ips.txt \
  | sort -u > /tmp/all_malicious_ips.txt

echo "Total unique malicious IPs: $(wc -l < /tmp/all_malicious_ips.txt)"

# Check your firewall logs for connections to known-bad IPs
# (assumes iptables/netfilter log format)
LOGFILE="/var/log/syslog"
while IFS= read -r ip; do
  HITS=$(grep -c "$ip" "$LOGFILE" 2>/dev/null || echo 0)
  if [ "$HITS" -gt 0 ]; then
    echo "[ALERT] Malicious IP $ip found $HITS times in $LOGFILE"
  fi
done < /tmp/all_malicious_ips.txt

# Check active network connections against malicious IPs
ss -tnp | awk '{print $5}' | cut -d: -f1 | sort -u | while read -r conn_ip; do
  if grep -qx "$conn_ip" /tmp/all_malicious_ips.txt; then
    echo "[CRITICAL] Active connection to malicious IP: $conn_ip"
    ss -tnp | grep "$conn_ip"
  fi
done

# Check DNS query logs for known malicious domains
MALICIOUS_DOMAINS="/tmp/malicious_domains.txt"
DNS_LOG="/var/log/named/queries.log"
if [ -f "$DNS_LOG" ] && [ -f "$MALICIOUS_DOMAINS" ]; then
  grep -Ff "$MALICIOUS_DOMAINS" "$DNS_LOG" \
    | awk '{print $1, $4, $5}' \
    | sort | uniq -c | sort -rn | head -20
fi
```

### 2.2 Check File Hashes

```bash
# Compute SHA256 hashes for files in a directory
TARGET_DIR="/opt/uploads"
find "$TARGET_DIR" -type f -exec sha256sum {} \; > /tmp/file_hashes.txt

echo "Hashed $(wc -l < /tmp/file_hashes.txt) files"

# Extract known malicious hashes from MalBazaar feed
awk -F',' '{print $2}' /tmp/malbazaar_recent.csv \
  | tr -d '"' | grep -E '^[a-f0-9]{64}$' \
  | sort -u > /tmp/malicious_hashes.txt

# Cross-reference local file hashes against malicious hashes
while IFS=' ' read -r hash filepath; do
  if grep -qx "$hash" /tmp/malicious_hashes.txt; then
    echo "[CRITICAL] Malicious file detected: $filepath (hash: $hash)"
  fi
done < /tmp/file_hashes.txt

# Check a single file hash against MalBazaar API
FILE_HASH="your-sha256-hash-here"
curl -s -X POST \
  -H "Content-Type: application/json" \
  -d "{\"query\":\"get_info\",\"hash\":\"${FILE_HASH}\"}" \
  "https://mb-api.abuse.ch/api/v1/" \
  | jq '{status: .query_status, signature: .data[0].signature, tags: .data[0].tags}'
```

---

## 3. Exposure Check

### 3.1 Shodan — Internet-Facing Asset Exposure

```bash
# Set Shodan API key
export SHODAN_API_KEY="your-shodan-api-key-here"

# Check your own public IP exposure
MY_IP=$(curl -s ifconfig.me)
curl -s "https://api.shodan.io/shodan/host/${MY_IP}?key=${SHODAN_API_KEY}" \
  | jq '{ip: .ip_str, org: .org, os: .os, ports: .ports, vulns: .vulns}'

# Search for all your organization's assets on Shodan
curl -s "https://api.shodan.io/shodan/host/search?key=${SHODAN_API_KEY}&query=org:\"Your+Org+Name\"" \
  | jq '.matches[] | {ip: .ip_str, port: .port, product: .product, version: .version}'

# Check a specific IP for open ports and vulnerabilities
TARGET_IP="203.0.113.10"
curl -s "https://api.shodan.io/shodan/host/${TARGET_IP}?key=${SHODAN_API_KEY}" \
  | jq '{
    ip: .ip_str,
    hostnames: .hostnames,
    ports: .ports,
    vulns: .vulns,
    services: [.data[] | {port: .port, transport: .transport, product: .product}]
  }'

# Check for exposed services across a CIDR range you own
curl -s "https://api.shodan.io/shodan/host/search?key=${SHODAN_API_KEY}&query=net:203.0.113.0/24" \
  | jq '.matches[] | {ip: .ip_str, port: .port, product: .product}' \
  | tee /tmp/shodan_exposure_report.json

# Monitor for new exposures (Shodan Alerts)
curl -s -X POST \
  -H "Content-Type: application/json" \
  -d '{"name":"My Network","filters":{"ip":["203.0.113.0/24"]}}' \
  "https://api.shodan.io/shodan/alert?key=${SHODAN_API_KEY}" | jq .
```

### 3.2 Have I Been Pwned — Email Exposure

```bash
# Set HIBP API key
export HIBP_API_KEY="your-hibp-api-key-here"

# Check a single email for breaches
EMAIL="user@yourdomain.com"
curl -s \
  -H "hibp-api-key: ${HIBP_API_KEY}" \
  -H "user-agent: ClaudeOS-ThreatIntel" \
  "https://haveibeenpwned.com/api/v3/breachedaccount/${EMAIL}?truncateResponse=false" \
  | jq '.[] | {name: .Name, date: .BreachDate, data_classes: .DataClasses}'

# Check a single email for pastes
curl -s \
  -H "hibp-api-key: ${HIBP_API_KEY}" \
  -H "user-agent: ClaudeOS-ThreatIntel" \
  "https://haveibeenpwned.com/api/v3/pasteaccount/${EMAIL}" \
  | jq '.[] | {source: .Source, title: .Title, date: .Date}'

# Batch-check a list of company emails (respect rate limit: 1 req per 1.5s)
EMAIL_LIST="/tmp/company_emails.txt"
while IFS= read -r email; do
  RESULT=$(curl -s -w "\n%{http_code}" \
    -H "hibp-api-key: ${HIBP_API_KEY}" \
    -H "user-agent: ClaudeOS-ThreatIntel" \
    "https://haveibeenpwned.com/api/v3/breachedaccount/${email}?truncateResponse=true")
  HTTP_CODE=$(echo "$RESULT" | tail -1)
  BODY=$(echo "$RESULT" | head -n -1)
  if [ "$HTTP_CODE" = "200" ]; then
    BREACH_COUNT=$(echo "$BODY" | jq length)
    echo "[EXPOSED] ${email} — found in ${BREACH_COUNT} breach(es)"
  elif [ "$HTTP_CODE" = "404" ]; then
    echo "[CLEAN] ${email} — no breaches found"
  else
    echo "[ERROR] ${email} — HTTP ${HTTP_CODE}"
  fi
  sleep 1.6  # Rate limit: 1 request per 1.5 seconds
done < "$EMAIL_LIST"

# Check if your domain has been involved in breaches
curl -s \
  -H "hibp-api-key: ${HIBP_API_KEY}" \
  -H "user-agent: ClaudeOS-ThreatIntel" \
  "https://haveibeenpwned.com/api/v3/breaches?domain=yourdomain.com" \
  | jq '.[] | {name: .Name, breach_date: .BreachDate, pwn_count: .PwnCount}'
```

---

## 4. IP Reputation Check

### 4.1 AbuseIPDB

```bash
# Set AbuseIPDB API key
export ABUSEIPDB_API_KEY="your-abuseipdb-api-key-here"

# Check a single IP reputation
CHECK_IP="203.0.113.50"
curl -s \
  -H "Key: ${ABUSEIPDB_API_KEY}" \
  -H "Accept: application/json" \
  "https://api.abuseipdb.com/api/v2/check?ipAddress=${CHECK_IP}&maxAgeInDays=90&verbose" \
  | jq '{
    ip: .data.ipAddress,
    abuse_score: .data.abuseConfidenceScore,
    country: .data.countryCode,
    isp: .data.isp,
    domain: .data.domain,
    total_reports: .data.totalReports,
    last_reported: .data.lastReportedAt
  }'

# Bulk check IPs from firewall deny logs
SUSPICIOUS_IPS="/tmp/suspicious_ips.txt"
while IFS= read -r ip; do
  SCORE=$(curl -s \
    -H "Key: ${ABUSEIPDB_API_KEY}" \
    -H "Accept: application/json" \
    "https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=30" \
    | jq -r '.data.abuseConfidenceScore')
  if [ "$SCORE" -ge 50 ] 2>/dev/null; then
    echo "[HIGH RISK] ${ip} — abuse score: ${SCORE}%"
  elif [ "$SCORE" -ge 25 ] 2>/dev/null; then
    echo "[MEDIUM RISK] ${ip} — abuse score: ${SCORE}%"
  else
    echo "[LOW RISK] ${ip} — abuse score: ${SCORE}%"
  fi
  sleep 1  # Respect rate limits
done < "$SUSPICIOUS_IPS"

# Report an abusive IP to AbuseIPDB
curl -s -X POST \
  -H "Key: ${ABUSEIPDB_API_KEY}" \
  -H "Accept: application/json" \
  --data-urlencode "ip=${CHECK_IP}" \
  --data-urlencode "categories=18,22" \
  --data-urlencode "comment=Port scanning and brute force attempts detected" \
  "https://api.abuseipdb.com/api/v2/report" | jq .
```

### 4.2 VirusTotal IP/Domain Check

```bash
# Set VirusTotal API key
export VT_API_KEY="your-virustotal-api-key-here"

# Check IP reputation on VirusTotal
CHECK_IP="203.0.113.50"
curl -s \
  -H "x-apikey: ${VT_API_KEY}" \
  "https://www.virustotal.com/api/v3/ip_addresses/${CHECK_IP}" \
  | jq '{
    ip: .data.id,
    country: .data.attributes.country,
    as_owner: .data.attributes.as_owner,
    malicious: .data.attributes.last_analysis_stats.malicious,
    suspicious: .data.attributes.last_analysis_stats.suspicious,
    reputation: .data.attributes.reputation
  }'

# Check domain reputation on VirusTotal
CHECK_DOMAIN="suspicious-domain.com"
curl -s \
  -H "x-apikey: ${VT_API_KEY}" \
  "https://www.virustotal.com/api/v3/domains/${CHECK_DOMAIN}" \
  | jq '{
    domain: .data.id,
    registrar: .data.attributes.registrar,
    creation_date: .data.attributes.creation_date,
    malicious: .data.attributes.last_analysis_stats.malicious,
    categories: .data.attributes.categories
  }'
```

---

## 5. Hash Analysis

```bash
# Submit a file hash to VirusTotal
FILE_HASH="d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
curl -s \
  -H "x-apikey: ${VT_API_KEY}" \
  "https://www.virustotal.com/api/v3/files/${FILE_HASH}" \
  | jq '{
    sha256: .data.attributes.sha256,
    name: .data.attributes.meaningful_name,
    type: .data.attributes.type_description,
    size: .data.attributes.size,
    malicious: .data.attributes.last_analysis_stats.malicious,
    undetected: .data.attributes.last_analysis_stats.undetected,
    first_seen: .data.attributes.first_submission_date,
    tags: .data.attributes.tags
  }'

# Batch check multiple hashes against VirusTotal
HASH_FILE="/tmp/hashes_to_check.txt"
while IFS= read -r hash; do
  [ -z "$hash" ] && continue
  RESULT=$(curl -s -H "x-apikey: ${VT_API_KEY}" \
    "https://www.virustotal.com/api/v3/files/${hash}" 2>/dev/null)
  MALICIOUS=$(echo "$RESULT" | jq -r '.data.attributes.last_analysis_stats.malicious // "unknown"')
  NAME=$(echo "$RESULT" | jq -r '.data.attributes.meaningful_name // "unknown"')
  [ "$MALICIOUS" != "unknown" ] && [ "$MALICIOUS" -gt 0 ] 2>/dev/null \
    && echo "[MALICIOUS] ${hash} — ${NAME} — ${MALICIOUS} detections" \
    || echo "[CLEAN] ${hash} — ${NAME}"
  sleep 15  # VirusTotal free tier: 4 requests per minute
done < "$HASH_FILE"

# Upload a file for scanning (max 32MB for this endpoint)
FILE_PATH="/tmp/suspicious_file.exe"
curl -s -X POST \
  -H "x-apikey: ${VT_API_KEY}" \
  -F "file=@${FILE_PATH}" \
  "https://www.virustotal.com/api/v3/files" \
  | jq '{id: .data.id, type: .data.type}'

# Get a rescan of an already-known hash
curl -s -X POST \
  -H "x-apikey: ${VT_API_KEY}" \
  "https://www.virustotal.com/api/v3/files/${FILE_HASH}/analyse" \
  | jq .
```

---

## 6. Blocklist Management

```bash
# Create a blocklist directory structure
BLOCKLIST_DIR="/etc/threat-intel/blocklists"
sudo mkdir -p "$BLOCKLIST_DIR"
sudo chown root:root "$BLOCKLIST_DIR"
sudo chmod 750 "$BLOCKLIST_DIR"

# Download and consolidate IP blocklists
download_blocklists() {
  echo "[$(date -Iseconds)] Updating blocklists..."

  # abuse.ch Feodo Tracker
  curl -s "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt" \
    | grep -v "^#" | grep -v "^$" > /tmp/bl_feodo.txt

  # Spamhaus DROP list
  curl -s "https://www.spamhaus.org/drop/drop.txt" \
    | grep -v "^;" | awk '{print $1}' | grep -v "^$" > /tmp/bl_spamhaus_drop.txt

  # Emerging Threats compromised IPs
  curl -s "https://rules.emergingthreats.net/blockrules/compromised-ips.txt" \
    | grep -v "^#" | grep -v "^$" > /tmp/bl_et_compromised.txt

  # Consolidate and deduplicate
  cat /tmp/bl_feodo.txt /tmp/bl_spamhaus_drop.txt /tmp/bl_et_compromised.txt \
    | sort -u > "${BLOCKLIST_DIR}/ip_blocklist.txt"

  echo "[$(date -Iseconds)] Total unique blocked IPs: $(wc -l < "${BLOCKLIST_DIR}/ip_blocklist.txt")"
}
download_blocklists

# Apply IP blocklist to iptables
apply_ip_blocklist() {
  BLOCKLIST="${BLOCKLIST_DIR}/ip_blocklist.txt"
  CHAIN="THREAT_INTEL_BLOCK"

  # Create or flush the chain
  sudo iptables -N "$CHAIN" 2>/dev/null || sudo iptables -F "$CHAIN"

  # Add blocked IPs
  while IFS= read -r ip; do
    [ -z "$ip" ] && continue
    sudo iptables -A "$CHAIN" -s "$ip" -j DROP
    sudo iptables -A "$CHAIN" -d "$ip" -j DROP
  done < "$BLOCKLIST"

  # Ensure chain is referenced from INPUT and OUTPUT
  sudo iptables -C INPUT -j "$CHAIN" 2>/dev/null \
    || sudo iptables -I INPUT 1 -j "$CHAIN"
  sudo iptables -C OUTPUT -j "$CHAIN" 2>/dev/null \
    || sudo iptables -I OUTPUT 1 -j "$CHAIN"

  echo "Applied $(wc -l < "$BLOCKLIST") IPs to iptables chain ${CHAIN}"
}

# Schedule automatic blocklist updates (cron)
CRON_ENTRY="0 */6 * * * /usr/local/bin/update-blocklists.sh >> /var/log/threat-intel/blocklist-update.log 2>&1"
(crontab -l 2>/dev/null | grep -v "update-blocklists"; echo "$CRON_ENTRY") | crontab -

# Download domain blocklist
curl -s "https://urlhaus.abuse.ch/downloads/hostfile/" \
  | grep -v "^#" | awk '{print $2}' | grep -v "^$" \
  | sort -u > "${BLOCKLIST_DIR}/domain_blocklist.txt"

echo "Domain blocklist entries: $(wc -l < "${BLOCKLIST_DIR}/domain_blocklist.txt")"

# Apply domain blocklist to DNS (dnsmasq example)
while IFS= read -r domain; do
  echo "address=/${domain}/" >> /tmp/dnsmasq_blocklist.conf
done < "${BLOCKLIST_DIR}/domain_blocklist.txt"

echo "Generated dnsmasq blocklist with $(wc -l < /tmp/dnsmasq_blocklist.conf) entries"
```

---

## 7. Report Generation

```bash
# Generate a daily threat intelligence summary report
REPORT_DIR="/var/log/threat-intel/reports"
mkdir -p "$REPORT_DIR"
REPORT_FILE="${REPORT_DIR}/threat-intel-report-$(date +%Y-%m-%d).txt"

{
  echo "=============================================="
  echo " THREAT INTELLIGENCE DAILY REPORT"
  echo " Generated: $(date -Iseconds)"
  echo " Hostname: $(hostname)"
  echo "=============================================="
  echo ""
  echo "--- Feed Statistics ---"
  echo "Total malicious IPs tracked: $(wc -l < /tmp/all_malicious_ips.txt 2>/dev/null || echo 0)"
  echo "Total malicious domains tracked: $(wc -l < "${BLOCKLIST_DIR}/domain_blocklist.txt" 2>/dev/null || echo 0)"
  echo "Total malicious hashes tracked: $(wc -l < /tmp/malicious_hashes.txt 2>/dev/null || echo 0)"
  echo ""
  echo "--- Active Connections to Malicious IPs ---"
  ss -tnp | awk '{print $5}' | cut -d: -f1 | sort -u | while read -r ip; do
    if grep -qx "$ip" /tmp/all_malicious_ips.txt 2>/dev/null; then
      echo "  [CRITICAL] Active connection to: $ip"
    fi
  done
  echo ""
  echo "--- Blocklist Summary ---"
  echo "IP blocklist entries: $(wc -l < "${BLOCKLIST_DIR}/ip_blocklist.txt" 2>/dev/null || echo 0)"
  echo "Domain blocklist entries: $(wc -l < "${BLOCKLIST_DIR}/domain_blocklist.txt" 2>/dev/null || echo 0)"
  echo "Last blocklist update: $(stat -c %y "${BLOCKLIST_DIR}/ip_blocklist.txt" 2>/dev/null || echo 'unknown')"
  echo ""
  echo "--- Shodan Exposure ---"
  if [ -f /tmp/shodan_exposure_report.json ]; then
    echo "Exposed services found: $(jq -s length /tmp/shodan_exposure_report.json)"
  else
    echo "No Shodan exposure report available"
  fi
  echo ""
  echo "=============================================="
  echo " END OF REPORT"
  echo "=============================================="
} > "$REPORT_FILE"

echo "Report saved to: $REPORT_FILE"
cat "$REPORT_FILE"

```

---

## Quick Reference

| Task | Tool | Command |
|------|------|---------|
| Test MISP connection | curl | `curl -s -k -H "Authorization: $MISP_API_KEY" "$MISP_URL/servers/getVersion"` |
| Fetch OTX pulses | curl | `curl -s -H "X-OTX-API-KEY: $OTX_API_KEY" "https://otx.alienvault.com/api/v1/pulses/subscribed"` |
| Download Feodo C2 IPs | curl | `curl -s "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"` |
| Check IP on AbuseIPDB | curl | `curl -s -H "Key: $ABUSEIPDB_API_KEY" "https://api.abuseipdb.com/api/v2/check?ipAddress=IP"` |
| Check IP on VirusTotal | curl | `curl -s -H "x-apikey: $VT_API_KEY" "https://www.virustotal.com/api/v3/ip_addresses/IP"` |
| Lookup hash on VT | curl | `curl -s -H "x-apikey: $VT_API_KEY" "https://www.virustotal.com/api/v3/files/HASH"` |
| Shodan host lookup | curl | `curl -s "https://api.shodan.io/shodan/host/IP?key=$SHODAN_API_KEY"` |
| HIBP email check | curl | `curl -s -H "hibp-api-key: $HIBP_API_KEY" "https://haveibeenpwned.com/api/v3/breachedaccount/EMAIL"` |
| Check active bad connections | ss + grep | `ss -tnp \| awk '{print $5}' \| cut -d: -f1 \| grep -Ff malicious_ips.txt` |
| Update blocklists | curl + sort | `curl feeds... \| sort -u > ip_blocklist.txt` |
| Apply iptables blocklist | iptables | `iptables -A CHAIN -s IP -j DROP` |
| Generate report | bash | `bash /usr/local/bin/generate-threat-report.sh` |
