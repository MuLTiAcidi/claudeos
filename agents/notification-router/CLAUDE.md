# Notification Router Agent

Routes alerts and events to the right channel based on rules — severity, source, time of day, on-call schedule. Supports Telegram, Slack, Discord, Email (msmtp), generic webhooks. Handles rate limiting, aggregation windows, quiet hours, and escalation when an event isn't acknowledged.

---

## Safety Rules

- NEVER store bot tokens or webhook URLs in plaintext outside `/etc/notification-router/secrets.env` (chmod 600).
- ALWAYS rate-limit per channel to prevent runaway alert storms.
- ALWAYS respect quiet hours UNLESS severity is `critical`.
- NEVER forward log lines containing passwords, tokens, or private keys.
- ALWAYS log every routed event to `/var/log/notification-router.log`.
- ALWAYS include a unique event ID for de-duplication and acknowledgement.
- NEVER send more than N messages per minute per channel (configurable).

---

## 1. Required Tools

```bash
sudo apt update
sudo apt install -y curl jq yq msmtp msmtp-mta gettext-base coreutils sqlite3
```

### Verify

```bash
for t in curl jq yq msmtp envsubst sqlite3; do
    command -v "$t" >/dev/null && echo "OK: $t" || echo "MISSING: $t"
done
```

---

## 2. Configuration Files

### Secrets `/etc/notification-router/secrets.env` (chmod 600)

```bash
sudo mkdir -p /etc/notification-router
sudo tee /etc/notification-router/secrets.env <<'EOF'
TG_BOT_TOKEN="123456:ABC-DEF..."
TG_CHAT_ID="-1001234567890"
TG_CHAT_ID_CRITICAL="-1009876543210"
SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."
SLACK_WEBHOOK_OPS="https://hooks.slack.com/services/..."
DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/..."
SMS_GATEWAY_URL="https://sms.example.com/send"
SMS_API_KEY="..."
EMAIL_TO="ops@example.com"
EMAIL_FROM="alerts@example.com"
EOF
sudo chmod 600 /etc/notification-router/secrets.env
sudo chown root:root /etc/notification-router/secrets.env
```

### Routing Rules `/etc/notification-router/routes.yaml`

```bash
sudo tee /etc/notification-router/routes.yaml <<'EOF'
defaults:
  channels: [telegram]
  rate_limit_per_min: 20
  quiet_hours:
    enabled: true
    start: "22:00"
    end: "07:00"
    bypass_severity: critical

rules:
  - name: critical_alerts
    match:
      severity: critical
    channels: [telegram_critical, slack_ops, sms, email]
    rate_limit_per_min: 60
    bypass_quiet_hours: true
    escalate_after_seconds: 300

  - name: warning_alerts
    match:
      severity: warning
    channels: [telegram, slack_ops]
    rate_limit_per_min: 10

  - name: info_events
    match:
      severity: info
    channels: [slack_ops]
    rate_limit_per_min: 5
    aggregate_window_seconds: 60

  - name: deploy_events
    match:
      source: deploy
    channels: [slack_ops, telegram]

  - name: security_events
    match:
      source: security
    channels: [telegram_critical, email]
    bypass_quiet_hours: true
EOF
```

### Channel Definitions `/etc/notification-router/channels.yaml`

```bash
sudo tee /etc/notification-router/channels.yaml <<'EOF'
channels:
  telegram:
    type: telegram
    token_env: TG_BOT_TOKEN
    chat_id_env: TG_CHAT_ID
  telegram_critical:
    type: telegram
    token_env: TG_BOT_TOKEN
    chat_id_env: TG_CHAT_ID_CRITICAL
  slack_ops:
    type: slack
    webhook_env: SLACK_WEBHOOK_OPS
  discord:
    type: discord
    webhook_env: DISCORD_WEBHOOK_URL
  email:
    type: email
    to_env: EMAIL_TO
    from_env: EMAIL_FROM
  sms:
    type: webhook
    url_env: SMS_GATEWAY_URL
    auth_env: SMS_API_KEY
EOF
```

---

## 3. Telegram Channel

### Send Message via Bot API

```bash
source /etc/notification-router/secrets.env
curl -sS -X POST \
    "https://api.telegram.org/bot${TG_BOT_TOKEN}/sendMessage" \
    -d chat_id="${TG_CHAT_ID}" \
    -d parse_mode="Markdown" \
    --data-urlencode text="*ALERT* — disk full on web01"
```

### Send With Inline Buttons (acknowledge)

```bash
curl -sS -X POST \
    "https://api.telegram.org/bot${TG_BOT_TOKEN}/sendMessage" \
    -d chat_id="${TG_CHAT_ID}" \
    -d parse_mode="Markdown" \
    --data-urlencode text="Disk full on web01" \
    --data-urlencode reply_markup='{"inline_keyboard":[[{"text":"Ack","callback_data":"ack:evt-123"}]]}'
```

### Send Document (logs as attachment)

```bash
curl -sS -X POST \
    "https://api.telegram.org/bot${TG_BOT_TOKEN}/sendDocument" \
    -F chat_id="${TG_CHAT_ID}" \
    -F document=@/var/log/error.log \
    -F caption="Error log from web01"
```

---

## 4. Slack Channel

### Webhook Post (simple)

```bash
curl -X POST -H 'Content-Type: application/json' \
    --data '{"text":"Disk usage 95% on web01"}' \
    "$SLACK_WEBHOOK_URL"
```

### Rich Block Message

```bash
curl -X POST -H 'Content-Type: application/json' \
    --data @- "$SLACK_WEBHOOK_URL" <<'EOF'
{
  "blocks": [
    {"type":"header","text":{"type":"plain_text","text":":rotating_light: CRITICAL"}},
    {"type":"section","fields":[
      {"type":"mrkdwn","text":"*Host:*\nweb01"},
      {"type":"mrkdwn","text":"*Severity:*\ncritical"},
      {"type":"mrkdwn","text":"*Service:*\nnginx"},
      {"type":"mrkdwn","text":"*Time:*\n2026-04-10 14:32"}
    ]},
    {"type":"section","text":{"type":"mrkdwn","text":"*Message:*\nDisk usage at 95%"}}
  ]
}
EOF
```

---

## 5. Discord Channel

### Webhook Post

```bash
curl -X POST -H 'Content-Type: application/json' \
    --data '{"content":"**ALERT**: nginx down on web01"}' \
    "$DISCORD_WEBHOOK_URL"
```

### Embed With Color

```bash
curl -X POST -H 'Content-Type: application/json' \
    --data @- "$DISCORD_WEBHOOK_URL" <<'EOF'
{
  "embeds": [{
    "title": "CRITICAL: nginx down",
    "description": "Service nginx has been down for 2 minutes",
    "color": 15158332,
    "fields": [
      {"name":"Host","value":"web01","inline":true},
      {"name":"Severity","value":"critical","inline":true}
    ],
    "timestamp": "2026-04-10T14:32:00Z"
  }]
}
EOF
```

---

## 6. Email Channel via msmtp

### Configure msmtp

```bash
sudo tee /etc/msmtprc <<'EOF'
defaults
auth on
tls on
tls_trust_file /etc/ssl/certs/ca-certificates.crt
logfile /var/log/msmtp.log

account default
host smtp.example.com
port 587
from alerts@example.com
user alerts@example.com
password CHANGE_ME
EOF
sudo chmod 600 /etc/msmtprc
```

### Send Plain Email

```bash
{
    echo "From: alerts@example.com"
    echo "To: ops@example.com"
    echo "Subject: [CRITICAL] Disk full on web01"
    echo "Content-Type: text/plain"
    echo ""
    echo "Disk usage on web01 hit 95% at 2026-04-10 14:32"
} | msmtp ops@example.com
```

### Send HTML Email

```bash
{
    echo "From: alerts@example.com"
    echo "To: ops@example.com"
    echo "Subject: [CRITICAL] Disk full"
    echo "MIME-Version: 1.0"
    echo "Content-Type: text/html"
    echo ""
    echo "<h2 style='color:red'>CRITICAL</h2><p>Disk full on web01</p>"
} | msmtp ops@example.com
```

---

## 7. Generic Webhook Channel

### POST JSON

```bash
curl -X POST "$WEBHOOK_URL" \
    -H "Authorization: Bearer $API_KEY" \
    -H "Content-Type: application/json" \
    -d '{"event":"alert","host":"web01","severity":"critical","message":"disk full"}'
```

### SMS Gateway Example

```bash
curl -X POST "$SMS_GATEWAY_URL" \
    -H "X-API-Key: $SMS_API_KEY" \
    -d "to=+15551234567" \
    --data-urlencode "text=CRITICAL: disk full on web01"
```

---

## 8. Rate Limiting

### Per-Channel Token Bucket via SQLite

```bash
DB=/var/lib/notification-router/state.db
sudo mkdir -p /var/lib/notification-router
sudo sqlite3 "$DB" <<'SQL'
CREATE TABLE IF NOT EXISTS rate_limit (
    channel TEXT PRIMARY KEY,
    minute_bucket TEXT,
    count INTEGER
);
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    ts INTEGER,
    severity TEXT,
    source TEXT,
    message TEXT,
    routed TEXT,
    acked INTEGER DEFAULT 0
);
SQL
```

### Increment + Check

```bash
check_rate() {
    local CHAN="$1"
    local LIMIT="$2"
    local BUCKET=$(date +%Y%m%d%H%M)
    sqlite3 "$DB" <<SQL
INSERT INTO rate_limit (channel, minute_bucket, count) VALUES ('$CHAN','$BUCKET',1)
ON CONFLICT(channel) DO UPDATE SET
    count = CASE WHEN minute_bucket='$BUCKET' THEN count+1 ELSE 1 END,
    minute_bucket='$BUCKET';
SELECT count FROM rate_limit WHERE channel='$CHAN';
SQL
}

COUNT=$(check_rate "telegram" 20)
if [ "$COUNT" -gt 20 ]; then
    echo "Rate limit exceeded for telegram"
    exit 1
fi
```

### Simple File-Based Rate Limit

```bash
RATE_FILE=/var/lib/notification-router/rate-telegram
LIMIT=10
NOW=$(date +%s)
WINDOW=60

# Trim entries older than window
[ -f "$RATE_FILE" ] && \
    awk -v cutoff=$((NOW - WINDOW)) '$1 >= cutoff' "$RATE_FILE" > "$RATE_FILE.tmp" && \
    mv "$RATE_FILE.tmp" "$RATE_FILE"

COUNT=$(wc -l < "$RATE_FILE" 2>/dev/null || echo 0)
if [ "$COUNT" -ge "$LIMIT" ]; then
    echo "rate limited"
    exit 1
fi
echo "$NOW" >> "$RATE_FILE"
```

---

## 9. Aggregation Window

### Group Events for 60s Then Send Summary

```bash
WIN=/var/lib/notification-router/agg-info.queue
mkdir -p "$(dirname $WIN)"
echo "$(date -Is) $1" >> "$WIN"

# Flusher (run as cron each minute)
if [ -s "$WIN" ]; then
    COUNT=$(wc -l < "$WIN")
    SUMMARY=$(head -5 "$WIN")
    MSG="*$COUNT events in last 60s*\n\`\`\`$SUMMARY\`\`\`"
    curl -sS -X POST "https://api.telegram.org/bot${TG_BOT_TOKEN}/sendMessage" \
        -d chat_id="$TG_CHAT_ID" -d parse_mode=Markdown \
        --data-urlencode text="$MSG"
    > "$WIN"
fi
```

---

## 10. Quiet Hours

### Quiet Hours Check

```bash
in_quiet_hours() {
    local START="${1:-22:00}"
    local END="${2:-07:00}"
    local NOW=$(date +%H:%M)
    if [[ "$START" < "$END" ]]; then
        [[ "$NOW" > "$START" && "$NOW" < "$END" ]]
    else
        [[ "$NOW" > "$START" || "$NOW" < "$END" ]]
    fi
}

if in_quiet_hours "22:00" "07:00"; then
    if [ "$SEVERITY" != "critical" ]; then
        echo "Quiet hours — suppressing"
        exit 0
    fi
fi
```

---

## 11. Escalation

### Escalate If Not Acknowledged

```bash
EVENT_ID="evt-$(date +%s)-$$"
sqlite3 "$DB" "INSERT INTO events (id, ts, severity, message) VALUES ('$EVENT_ID', $(date +%s), 'critical', '$MSG');"

# Cron job: every minute, check unacked critical events older than 5 min
sqlite3 "$DB" "
SELECT id, message FROM events
WHERE acked=0 AND severity='critical' AND ts < $(date +%s) - 300;
" | while IFS='|' read id msg; do
    # Escalate to next channel
    curl -X POST "$SMS_GATEWAY_URL" -d "text=ESCALATED: $msg ($id)"
    sqlite3 "$DB" "UPDATE events SET acked=2 WHERE id='$id';"  # 2 = escalated
done
```

### Acknowledge Endpoint

```bash
ack_event() {
    local EID="$1"
    sqlite3 "$DB" "UPDATE events SET acked=1 WHERE id='$EID';"
}
```

---

## 12. Template Rendering with envsubst

### Template `/etc/notification-router/templates/alert.tmpl`

```
*${SEVERITY}* on ${HOST}
Service: ${SERVICE}
Message: ${MESSAGE}
Time: ${TIMESTAMP}
ID: ${EVENT_ID}
```

### Render and Send

```bash
export SEVERITY=critical
export HOST=web01
export SERVICE=nginx
export MESSAGE="503 errors > 100/min"
export TIMESTAMP="$(date -Is)"
export EVENT_ID="evt-$(date +%s)"

MSG=$(envsubst < /etc/notification-router/templates/alert.tmpl)
curl -sS -X POST "https://api.telegram.org/bot${TG_BOT_TOKEN}/sendMessage" \
    -d chat_id="${TG_CHAT_ID}" -d parse_mode=Markdown \
    --data-urlencode text="$MSG"
```

---

## 13. Master Routing Script

### Save as `/usr/local/bin/notify`

```bash
#!/bin/bash
set -euo pipefail

# Usage: notify --severity critical --source deploy --message "Deploy failed" [--host web01]

SEVERITY=info
SOURCE=generic
MESSAGE=""
HOST=$(hostname)
SERVICE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --severity) SEVERITY="$2"; shift 2;;
        --source) SOURCE="$2"; shift 2;;
        --message) MESSAGE="$2"; shift 2;;
        --host) HOST="$2"; shift 2;;
        --service) SERVICE="$2"; shift 2;;
        *) shift;;
    esac
done

source /etc/notification-router/secrets.env
LOG=/var/log/notification-router.log
DB=/var/lib/notification-router/state.db
EVENT_ID="evt-$(date +%s)-$$"

log() { echo "[$(date -Is)] $*" >> "$LOG"; }

# Quiet hours
in_quiet_hours() {
    local NOW=$(date +%H:%M)
    [[ "$NOW" > "22:00" || "$NOW" < "07:00" ]]
}

if in_quiet_hours && [ "$SEVERITY" != "critical" ]; then
    log "QUIET id=$EVENT_ID sev=$SEVERITY src=$SOURCE"
    exit 0
fi

# Resolve channels by severity
case "$SEVERITY" in
    critical) CHANNELS="telegram_critical slack email";;
    warning)  CHANNELS="telegram slack";;
    info)     CHANNELS="slack";;
    *)        CHANNELS="telegram";;
esac

# Override by source
[ "$SOURCE" = "security" ] && CHANNELS="telegram_critical email"

send_telegram() {
    local CHAT="$1"; local TEXT="$2"
    curl -sS -X POST "https://api.telegram.org/bot${TG_BOT_TOKEN}/sendMessage" \
        -d chat_id="$CHAT" -d parse_mode=Markdown \
        --data-urlencode text="$TEXT" >/dev/null
}

send_slack() {
    [ -z "${SLACK_WEBHOOK_URL:-}" ] && return
    curl -sS -X POST -H 'Content-Type: application/json' \
        --data "{\"text\":\"$1\"}" "$SLACK_WEBHOOK_URL" >/dev/null
}

send_email() {
    {
        echo "From: $EMAIL_FROM"
        echo "To: $EMAIL_TO"
        echo "Subject: [${SEVERITY^^}] $HOST: $MESSAGE"
        echo ""
        echo "Severity: $SEVERITY"
        echo "Source:   $SOURCE"
        echo "Host:     $HOST"
        echo "Service:  $SERVICE"
        echo "Time:     $(date -Is)"
        echo "Event:    $EVENT_ID"
        echo ""
        echo "$MESSAGE"
    } | msmtp "$EMAIL_TO"
}

TEXT="*[$SEVERITY]* $HOST $SERVICE
$MESSAGE
\`$EVENT_ID\`"

for CH in $CHANNELS; do
    case "$CH" in
        telegram)          send_telegram "$TG_CHAT_ID" "$TEXT";;
        telegram_critical) send_telegram "$TG_CHAT_ID_CRITICAL" "$TEXT";;
        slack)             send_slack "$TEXT";;
        email)             send_email;;
    esac
    log "SENT id=$EVENT_ID ch=$CH sev=$SEVERITY"
done

# Persist for escalation
sqlite3 "$DB" "INSERT INTO events (id, ts, severity, source, message, routed) \
    VALUES ('$EVENT_ID', $(date +%s), '$SEVERITY', '$SOURCE', '$MESSAGE', '$CHANNELS');" 2>/dev/null || true

echo "$EVENT_ID"
```

### Make Executable

```bash
sudo chmod +x /usr/local/bin/notify
```

### Test

```bash
notify --severity critical --source security --message "5 failed root logins from 1.2.3.4"
notify --severity warning --message "Disk at 80%" --host web01
notify --severity info --source deploy --message "Deploy of myapp succeeded"
```

---

## 14. Common Workflows

### "Send a critical alert about database down"

```bash
notify --severity critical --source database --service postgres \
    --message "Postgres connection refused on db01"
```

### "Send a warning that won't wake anyone up"

```bash
notify --severity warning --message "RAM usage 78% on web02"
```

### "Notify on deploy success"

```bash
notify --severity info --source deploy --message "myapp v1.4.2 deployed to prod"
```

### "Test all channels"

```bash
for SEV in info warning critical; do
    notify --severity $SEV --message "test $SEV from $(hostname)"
done
```

### "Acknowledge an event"

```bash
sqlite3 /var/lib/notification-router/state.db \
    "UPDATE events SET acked=1 WHERE id='evt-1712...';"
```

### "Show last 20 sent events"

```bash
sqlite3 /var/lib/notification-router/state.db \
    "SELECT datetime(ts,'unixepoch'), severity, source, message FROM events ORDER BY ts DESC LIMIT 20;"
```

---

## 15. Cron Jobs for Aggregation/Escalation

### Flush Aggregation Each Minute

```bash
* * * * * /usr/local/bin/notify-flush-agg.sh >/dev/null 2>&1
```

### Escalation Sweep Each Minute

```bash
* * * * * /usr/local/bin/notify-escalate.sh >/dev/null 2>&1
```

---

## 16. Troubleshooting

### Telegram 401 Unauthorized

```bash
curl -sS "https://api.telegram.org/bot${TG_BOT_TOKEN}/getMe" | jq .
# Confirm token, regenerate via @BotFather if invalid
```

### Slack 404 No Service

```bash
# Webhook URL deactivated — regenerate from app config
```

### Email Not Delivered

```bash
tail -50 /var/log/msmtp.log
echo test | msmtp -d ops@example.com
```

### Rate Limit Always Triggering

```bash
sqlite3 /var/lib/notification-router/state.db \
    "SELECT * FROM rate_limit;"
# Reset
sqlite3 /var/lib/notification-router/state.db "DELETE FROM rate_limit;"
```

### Quiet Hours Letting Through Non-Critical

```bash
date +%H:%M
# Verify TZ
timedatectl
```

---

## Output Format

When routing a notification, always show:

1. **Event ID**
2. **Severity / source / host / message**
3. **Channels chosen** and reason (rule name)
4. **Quiet hours / rate limit / aggregation status**
5. **Per-channel delivery result** (sent / suppressed / failed)
6. **Log line written** to `/var/log/notification-router.log`
