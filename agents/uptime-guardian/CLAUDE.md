# Uptime Guardian

> 24/7 uptime monitoring agent with instant alerting. Continuously monitors services, endpoints, and infrastructure for availability, latency, and correctness — alerting immediately when something goes down.

## Safety Rules

- NEVER disable monitoring on production services without explicit confirmation
- NEVER send test alerts to production alert channels without confirmation
- NEVER modify firewall rules or network configuration
- NEVER store credentials in plain text — use environment variables or secret managers
- ALWAYS validate URLs and hostnames before probing
- ALWAYS respect rate limits when checking external services
- ALWAYS log all monitoring actions for audit trails

---

## 1. HTTP Health Checks

### Basic HTTP status check with curl

```bash
# Check if endpoint returns 2xx
curl -s -o /dev/null -w "%{http_code}" --max-time 10 https://example.com/health
```

### Full health check with response time

```bash
# Measure response time, status code, and size
curl -s -o /dev/null -w "status=%{http_code} time=%{time_total}s size=%{size_download} dns=%{time_namelookup}s connect=%{time_connect}s ttfb=%{time_starttransfer}s" --max-time 15 https://example.com/health
```

### Check with expected content validation

```bash
# Verify response body contains expected string
RESPONSE=$(curl -s --max-time 10 https://example.com/health)
if echo "$RESPONSE" | grep -q '"status":"ok"'; then
  echo "HEALTHY"
else
  echo "UNHEALTHY — unexpected response body"
fi
```

### Check multiple endpoints from a list

```bash
# /etc/uptime-guardian/endpoints.txt format:
# https://app.example.com/health
# https://api.example.com/ping
# https://cdn.example.com/status

while IFS= read -r url; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$url" 2>/dev/null)
  TIME=$(curl -s -o /dev/null -w "%{time_total}" --max-time 10 "$url" 2>/dev/null)
  TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  echo "$TIMESTAMP | $url | HTTP $STATUS | ${TIME}s"
done < /etc/uptime-guardian/endpoints.txt
```

### wget-based health check (alternative)

```bash
# wget with timeout and status check
wget --spider --timeout=10 --tries=1 -q https://example.com/health
if [ $? -eq 0 ]; then
  echo "UP"
else
  echo "DOWN"
fi
```

---

## 2. Port and TCP Checks

### Check if a TCP port is open with nc (netcat)

```bash
# Check single port
nc -z -w5 server.example.com 443
echo "Exit code: $? (0=open, 1=closed)"
```

### Check multiple ports on a host

```bash
PORTS=(22 80 443 3306 5432 6379 8080)
HOST="server.example.com"
for PORT in "${PORTS[@]}"; do
  if nc -z -w3 "$HOST" "$PORT" 2>/dev/null; then
    echo "Port $PORT: OPEN"
  else
    echo "Port $PORT: CLOSED"
  fi
done
```

### Port scanning with nmap

```bash
# Quick service scan
nmap -sT -T4 --open -p 22,80,443,3306,5432,6379,8080,9090 server.example.com

# Service version detection
nmap -sV -p 22,80,443 server.example.com
```

### UDP port check

```bash
# Check DNS port (UDP 53)
nc -zu -w3 dns.example.com 53
echo "DNS port: $?"
```

---

## 3. Systemd Service Monitoring

### Check if a service is active

```bash
systemctl is-active --quiet nginx && echo "nginx: RUNNING" || echo "nginx: DOWN"
```

### Monitor multiple services

```bash
SERVICES=(nginx postgresql redis-server docker ssh cron)
for SVC in "${SERVICES[@]}"; do
  STATUS=$(systemctl is-active "$SVC" 2>/dev/null)
  if [ "$STATUS" = "active" ]; then
    echo "$SVC: UP"
  else
    echo "$SVC: DOWN ($STATUS)"
  fi
done
```

### Get detailed service status

```bash
# Full status with recent logs
systemctl status nginx --no-pager -l

# Check if service is enabled at boot
systemctl is-enabled nginx

# Time since last restart
systemctl show nginx --property=ActiveEnterTimestamp
```

### List failed services

```bash
systemctl --failed --no-pager
```

### Monitor service resource usage

```bash
# CPU and memory for a service
systemctl show nginx --property=MemoryCurrent,CPUUsageNSec
```

---

## 4. Response Time Tracking

### Track response times to a log file

```bash
LOG_FILE="/var/log/uptime-guardian/response-times.log"
mkdir -p "$(dirname "$LOG_FILE")"

URL="https://example.com/health"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
METRICS=$(curl -s -o /dev/null -w "%{time_total},%{time_namelookup},%{time_connect},%{time_starttransfer},%{http_code}" --max-time 15 "$URL")
echo "$TIMESTAMP,$URL,$METRICS" >> "$LOG_FILE"
```

### Response time statistics

```bash
LOG_FILE="/var/log/uptime-guardian/response-times.log"

# Average response time from last 100 checks
tail -100 "$LOG_FILE" | awk -F',' '{sum+=$3; count++} END {printf "Average: %.3fs over %d checks\n", sum/count, count}'

# 95th percentile
tail -1000 "$LOG_FILE" | awk -F',' '{print $3}' | sort -n | awk '{a[NR]=$1} END {print "P95: " a[int(NR*0.95)] "s"}'

# Max response time
tail -1000 "$LOG_FILE" | awk -F',' '{print $3}' | sort -rn | head -1 | xargs -I{} echo "Max: {}s"
```

### Slow response alerting

```bash
THRESHOLD=2.0  # seconds
URL="https://example.com/health"
RESPONSE_TIME=$(curl -s -o /dev/null -w "%{time_total}" --max-time 15 "$URL")

SLOW=$(echo "$RESPONSE_TIME > $THRESHOLD" | bc -l)
if [ "$SLOW" -eq 1 ]; then
  echo "SLOW RESPONSE: ${RESPONSE_TIME}s exceeds threshold of ${THRESHOLD}s"
fi
```

---

## 5. Uptime Calculation

### Calculate uptime percentage from logs

```bash
LOG_FILE="/var/log/uptime-guardian/response-times.log"

TOTAL=$(wc -l < "$LOG_FILE")
FAILURES=$(awk -F',' '$7 !~ /^2/' "$LOG_FILE" | wc -l)
UPTIME=$(echo "scale=4; ($TOTAL - $FAILURES) / $TOTAL * 100" | bc)
echo "Uptime: ${UPTIME}% ($TOTAL checks, $FAILURES failures)"
```

### System uptime

```bash
# How long the server has been up
uptime -p

# Precise uptime in seconds
awk '{print $1}' /proc/uptime

# Last reboot time
who -b
```

### Calculate SLA compliance

```bash
# Monthly uptime target: 99.9% = max 43.2 minutes downtime
MONTH_MINUTES=43200  # 30 days in minutes
TARGET_UPTIME=99.9
MAX_DOWNTIME_MINUTES=$(echo "scale=1; $MONTH_MINUTES * (100 - $TARGET_UPTIME) / 100" | bc)
echo "SLA $TARGET_UPTIME% allows max ${MAX_DOWNTIME_MINUTES} minutes downtime per month"

# Calculate actual downtime from logs (assuming 1-minute check intervals)
DOWNTIME_MINUTES=$(awk -F',' '$7 !~ /^2/' /var/log/uptime-guardian/response-times.log | wc -l)
echo "Actual downtime this period: ${DOWNTIME_MINUTES} minutes"
```

---

## 6. Cron-Based Monitoring

### Set up monitoring cron jobs

```bash
# Edit crontab
crontab -e
```

### Example crontab entries

```cron
# Health check every minute
* * * * * /usr/local/bin/uptime-guardian-check.sh >> /var/log/uptime-guardian/cron.log 2>&1

# Response time logging every 5 minutes
*/5 * * * * /usr/local/bin/uptime-guardian-metrics.sh >> /var/log/uptime-guardian/metrics.log 2>&1

# Uptime report every hour
0 * * * * /usr/local/bin/uptime-guardian-report.sh >> /var/log/uptime-guardian/hourly.log 2>&1

# Daily SLA report at midnight
0 0 * * * /usr/local/bin/uptime-guardian-daily-report.sh | mail -s "Daily Uptime Report" ops@example.com

# Certificate expiry check daily at 6am
0 6 * * * /usr/local/bin/uptime-guardian-cert-check.sh >> /var/log/uptime-guardian/certs.log 2>&1
```

### Health check script (/usr/local/bin/uptime-guardian-check.sh)

```bash
#!/bin/bash
set -euo pipefail

ENDPOINTS_FILE="/etc/uptime-guardian/endpoints.txt"
LOG_DIR="/var/log/uptime-guardian"
ALERT_SCRIPT="/usr/local/bin/uptime-guardian-alert.sh"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

mkdir -p "$LOG_DIR"

while IFS= read -r url; do
  [[ -z "$url" || "$url" == \#* ]] && continue

  HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$url" 2>/dev/null || echo "000")
  RESPONSE_TIME=$(curl -s -o /dev/null -w "%{time_total}" --max-time 10 "$url" 2>/dev/null || echo "0")

  echo "$TIMESTAMP,$url,$HTTP_CODE,$RESPONSE_TIME" >> "$LOG_DIR/checks.csv"

  if [[ ! "$HTTP_CODE" =~ ^2 ]]; then
    echo "$TIMESTAMP ALERT: $url returned HTTP $HTTP_CODE" >> "$LOG_DIR/alerts.log"
    if [ -x "$ALERT_SCRIPT" ]; then
      "$ALERT_SCRIPT" "$url" "$HTTP_CODE" "$RESPONSE_TIME"
    fi
  fi
done < "$ENDPOINTS_FILE"
```

---

## 7. Alerting

### Webhook alert (Slack/Discord/Generic)

```bash
# Slack webhook alert
send_slack_alert() {
  local SERVICE="$1"
  local STATUS="$2"
  local DETAILS="$3"
  local WEBHOOK_URL="${SLACK_WEBHOOK_URL}"

  curl -s -X POST "$WEBHOOK_URL" \
    -H 'Content-Type: application/json' \
    -d "{
      \"text\": \":rotating_light: *Service Alert*\",
      \"blocks\": [
        {
          \"type\": \"section\",
          \"text\": {
            \"type\": \"mrkdwn\",
            \"text\": \"*Service:* $SERVICE\n*Status:* $STATUS\n*Details:* $DETAILS\n*Time:* $(date -u +%Y-%m-%dT%H:%M:%SZ)\"
          }
        }
      ]
    }"
}

# Usage
send_slack_alert "api.example.com" "DOWN" "HTTP 503 - Service Unavailable"
```

### Discord webhook alert

```bash
send_discord_alert() {
  local SERVICE="$1"
  local STATUS="$2"
  local WEBHOOK_URL="${DISCORD_WEBHOOK_URL}"

  curl -s -X POST "$WEBHOOK_URL" \
    -H 'Content-Type: application/json' \
    -d "{
      \"embeds\": [{
        \"title\": \"Service Alert\",
        \"description\": \"**$SERVICE** is **$STATUS**\",
        \"color\": 16711680,
        \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"
      }]
    }"
}
```

### Telegram alert

```bash
send_telegram_alert() {
  local MESSAGE="$1"
  local BOT_TOKEN="${TELEGRAM_BOT_TOKEN}"
  local CHAT_ID="${TELEGRAM_CHAT_ID}"

  curl -s -X POST "https://api.telegram.org/bot${BOT_TOKEN}/sendMessage" \
    -d "chat_id=${CHAT_ID}" \
    -d "text=${MESSAGE}" \
    -d "parse_mode=Markdown"
}

# Usage
send_telegram_alert "*ALERT*: api.example.com is DOWN (HTTP 503) at $(date -u)"
```

### Email alert via sendmail/mailx

```bash
send_email_alert() {
  local SUBJECT="$1"
  local BODY="$2"
  local RECIPIENT="${ALERT_EMAIL:-ops@example.com}"

  echo "$BODY" | mail -s "$SUBJECT" "$RECIPIENT"
}

# Usage
send_email_alert "[ALERT] api.example.com DOWN" "Service api.example.com returned HTTP 503 at $(date -u)"
```

### PagerDuty alert

```bash
send_pagerduty_alert() {
  local SERVICE="$1"
  local DETAILS="$2"
  local ROUTING_KEY="${PAGERDUTY_ROUTING_KEY}"

  curl -s -X POST "https://events.pagerduty.com/v2/enqueue" \
    -H 'Content-Type: application/json' \
    -d "{
      \"routing_key\": \"$ROUTING_KEY\",
      \"event_action\": \"trigger\",
      \"payload\": {
        \"summary\": \"$SERVICE is down\",
        \"severity\": \"critical\",
        \"source\": \"uptime-guardian\",
        \"custom_details\": {\"details\": \"$DETAILS\"}
      }
    }"
}
```

---

## 8. SSL Certificate Monitoring

### Check certificate expiry

```bash
# Days until certificate expires
check_cert_expiry() {
  local HOST="$1"
  local PORT="${2:-443}"

  EXPIRY=$(echo | openssl s_client -servername "$HOST" -connect "$HOST:$PORT" 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)

  if [ -n "$EXPIRY" ]; then
    EXPIRY_EPOCH=$(date -d "$EXPIRY" +%s 2>/dev/null || date -jf "%b %d %T %Y %Z" "$EXPIRY" +%s 2>/dev/null)
    NOW_EPOCH=$(date +%s)
    DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))
    echo "$HOST: $DAYS_LEFT days until cert expiry (expires $EXPIRY)"

    if [ "$DAYS_LEFT" -lt 14 ]; then
      echo "WARNING: Certificate for $HOST expires in $DAYS_LEFT days!"
    fi
  else
    echo "$HOST: Unable to retrieve certificate"
  fi
}

check_cert_expiry example.com
check_cert_expiry api.example.com
```

### Batch certificate check

```bash
DOMAINS=(example.com api.example.com cdn.example.com mail.example.com)
for DOMAIN in "${DOMAINS[@]}"; do
  check_cert_expiry "$DOMAIN"
done
```

---

## 9. DNS Monitoring

### Check DNS resolution

```bash
# Verify DNS resolves correctly
dig +short A example.com
dig +short AAAA example.com

# Check against specific DNS server
dig @8.8.8.8 +short A example.com

# Measure DNS resolution time
dig example.com | grep "Query time"
```

### Monitor DNS propagation

```bash
DNS_SERVERS=(8.8.8.8 1.1.1.1 208.67.222.222 9.9.9.9)
DOMAIN="example.com"
for DNS in "${DNS_SERVERS[@]}"; do
  RESULT=$(dig @"$DNS" +short A "$DOMAIN" 2>/dev/null | head -1)
  echo "DNS $DNS -> $DOMAIN = $RESULT"
done
```

---

## 10. Comprehensive Monitoring Script

### Full monitoring loop

```bash
#!/bin/bash
# /usr/local/bin/uptime-guardian-full.sh
set -euo pipefail

CONFIG_DIR="/etc/uptime-guardian"
LOG_DIR="/var/log/uptime-guardian"
STATE_DIR="/var/lib/uptime-guardian"
mkdir -p "$LOG_DIR" "$STATE_DIR"

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
ALERT_COOLDOWN=300  # seconds between repeated alerts for same service

should_alert() {
  local SERVICE_KEY="$1"
  local STATE_FILE="$STATE_DIR/alert_${SERVICE_KEY//[^a-zA-Z0-9]/_}"

  if [ -f "$STATE_FILE" ]; then
    LAST_ALERT=$(cat "$STATE_FILE")
    NOW=$(date +%s)
    DIFF=$((NOW - LAST_ALERT))
    if [ "$DIFF" -lt "$ALERT_COOLDOWN" ]; then
      return 1
    fi
  fi
  date +%s > "$STATE_FILE"
  return 0
}

mark_recovered() {
  local SERVICE_KEY="$1"
  local STATE_FILE="$STATE_DIR/alert_${SERVICE_KEY//[^a-zA-Z0-9]/_}"
  rm -f "$STATE_FILE"
}

# HTTP checks
if [ -f "$CONFIG_DIR/endpoints.txt" ]; then
  while IFS= read -r url; do
    [[ -z "$url" || "$url" == \#* ]] && continue
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$url" 2>/dev/null || echo "000")

    if [[ ! "$HTTP_CODE" =~ ^2 ]]; then
      echo "$TIMESTAMP FAIL $url HTTP_$HTTP_CODE" >> "$LOG_DIR/monitor.log"
      if should_alert "$url"; then
        echo "ALERT: $url is DOWN (HTTP $HTTP_CODE)"
      fi
    else
      mark_recovered "$url"
      echo "$TIMESTAMP OK $url HTTP_$HTTP_CODE" >> "$LOG_DIR/monitor.log"
    fi
  done < "$CONFIG_DIR/endpoints.txt"
fi

# Service checks
if [ -f "$CONFIG_DIR/services.txt" ]; then
  while IFS= read -r svc; do
    [[ -z "$svc" || "$svc" == \#* ]] && continue
    if ! systemctl is-active --quiet "$svc" 2>/dev/null; then
      echo "$TIMESTAMP FAIL service:$svc DOWN" >> "$LOG_DIR/monitor.log"
      if should_alert "svc_$svc"; then
        echo "ALERT: Service $svc is DOWN"
      fi
    else
      mark_recovered "svc_$svc"
      echo "$TIMESTAMP OK service:$svc ACTIVE" >> "$LOG_DIR/monitor.log"
    fi
  done < "$CONFIG_DIR/services.txt"
fi

# Port checks
if [ -f "$CONFIG_DIR/ports.txt" ]; then
  while IFS=',' read -r host port; do
    [[ -z "$host" || "$host" == \#* ]] && continue
    if ! nc -z -w3 "$host" "$port" 2>/dev/null; then
      echo "$TIMESTAMP FAIL port:${host}:${port} CLOSED" >> "$LOG_DIR/monitor.log"
      if should_alert "port_${host}_${port}"; then
        echo "ALERT: Port $port on $host is CLOSED"
      fi
    else
      mark_recovered "port_${host}_${port}"
      echo "$TIMESTAMP OK port:${host}:${port} OPEN" >> "$LOG_DIR/monitor.log"
    fi
  done < "$CONFIG_DIR/ports.txt"
fi

echo "$TIMESTAMP Monitoring cycle complete" >> "$LOG_DIR/monitor.log"
```

---

## 11. Configuration Files

### /etc/uptime-guardian/endpoints.txt

```text
# HTTP endpoints to monitor (one per line)
https://app.example.com/health
https://api.example.com/ping
https://cdn.example.com/status
http://internal-service:8080/healthz
```

### /etc/uptime-guardian/services.txt

```text
# Systemd services to monitor
nginx
postgresql
redis-server
docker
ssh
```

### /etc/uptime-guardian/ports.txt

```text
# host,port pairs to check
db.example.com,5432
redis.example.com,6379
mail.example.com,25
app.example.com,443
```

---

## 12. Log Rotation

### /etc/logrotate.d/uptime-guardian

```text
/var/log/uptime-guardian/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0644 root root
}
```

---

## 13. Status Dashboard Generation

### Generate plain-text status page

```bash
#!/bin/bash
# Generate a simple status report
echo "=== Uptime Guardian Status Report ==="
echo "Generated: $(date -u)"
echo ""

echo "--- Service Status ---"
for svc in nginx postgresql redis-server docker; do
  STATUS=$(systemctl is-active "$svc" 2>/dev/null || echo "unknown")
  printf "%-20s %s\n" "$svc" "$STATUS"
done

echo ""
echo "--- Recent Alerts (last 24h) ---"
if [ -f /var/log/uptime-guardian/alerts.log ]; then
  YESTERDAY=$(date -d "24 hours ago" -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date -v-24H -u +"%Y-%m-%dT%H:%M:%SZ")
  awk -v cutoff="$YESTERDAY" '$1 >= cutoff' /var/log/uptime-guardian/alerts.log | tail -20
else
  echo "No alert log found"
fi

echo ""
echo "--- Uptime Summary ---"
if [ -f /var/log/uptime-guardian/checks.csv ]; then
  TOTAL=$(wc -l < /var/log/uptime-guardian/checks.csv)
  OK=$(awk -F',' '$3 ~ /^2/' /var/log/uptime-guardian/checks.csv | wc -l)
  PCT=$(echo "scale=2; $OK * 100 / $TOTAL" | bc 2>/dev/null || echo "N/A")
  echo "Total checks: $TOTAL | Successful: $OK | Uptime: ${PCT}%"
fi
```
