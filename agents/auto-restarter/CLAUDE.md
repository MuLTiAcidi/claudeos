# Auto-Restarter Agent

Restarts crashed services intelligently using exponential backoff, dependency-aware ordering, health checks before and after restart, and webhook/email notifications. Configures systemd `Restart=` policies, custom watchdog scripts, monit, and supervisord. Prevents restart-loops on permanently broken services and escalates after a configurable failure threshold.

---

## Safety Rules

- NEVER blindly loop-restart a crashing service — always use exponential backoff.
- ALWAYS run a pre-restart health check to confirm the service is actually dead.
- ALWAYS check dependencies (`Wants=`, `Requires=`, `After=`) before restarting.
- NEVER restart sshd remotely without a watchdog rollback.
- Maximum 5 restart attempts before escalation to a human.
- ALWAYS capture journalctl logs from before the restart for post-mortem.
- NEVER edit a systemd unit in `/lib/systemd/system` — use a drop-in in `/etc/systemd/system/<unit>.d/`.
- ALWAYS reload systemd (`systemctl daemon-reload`) after changing a unit.
- Log every restart action to `/var/log/auto-restarter.log`.
- Notifications must be best-effort (`|| true`) so they never block recovery.

---

## 1. Detect Crashed Services

### List All Failed systemd Units

```bash
systemctl --failed --no-pager
systemctl list-units --state=failed --no-legend --no-pager | awk '{print $1}'
```

### Check One Service

```bash
systemctl is-active nginx
systemctl is-failed nginx
systemctl status nginx --no-pager -l
```

### Get Exit Code and Last Restart Count

```bash
systemctl show nginx -p ExecMainStatus,Result,NRestarts,ActiveState,SubState
```

### Recent Crash Logs

```bash
journalctl -u nginx --no-pager -n 100 --since "10 minutes ago"
journalctl -u nginx -p err --no-pager -n 50
```

---

## 2. Systemd `Restart=` Directives

### Drop-in Override (Safe Way)

```bash
systemctl edit nginx
# Or manually:
mkdir -p /etc/systemd/system/nginx.service.d
cat > /etc/systemd/system/nginx.service.d/restart.conf <<'EOF'
[Service]
Restart=on-failure
RestartSec=5s
StartLimitBurst=5
StartLimitIntervalSec=300
EOF

systemctl daemon-reload
systemctl restart nginx
systemctl show nginx -p Restart,RestartSec,StartLimitBurst,StartLimitIntervalSec
```

### Restart Policy Cheat Sheet

| Value | When systemd restarts |
|-------|----------------------|
| `no` | never |
| `on-success` | only on clean exit |
| `on-failure` | non-zero exit, signal, timeout, watchdog |
| `on-abnormal` | signal or timeout |
| `on-watchdog` | watchdog timeout only |
| `on-abort` | uncaught signal only |
| `always` | always (even clean exit) |

### Recommended Drop-in for a Web Service

```ini
# /etc/systemd/system/<svc>.service.d/restart.conf
[Service]
Restart=on-failure
RestartSec=5s
StartLimitBurst=5
StartLimitIntervalSec=300
TimeoutStartSec=60
TimeoutStopSec=30
WatchdogSec=30
```

### Reset Failed State (clears restart counter)

```bash
systemctl reset-failed nginx
```

---

## 3. Dependency-Aware Restarts

### Show What a Service Depends On

```bash
systemctl list-dependencies nginx
systemctl list-dependencies --reverse nginx     # what depends on nginx
```

### Add Dependencies via Drop-in

```ini
# /etc/systemd/system/myapp.service.d/deps.conf
[Unit]
Wants=postgresql.service redis-server.service
After=network-online.target postgresql.service redis-server.service
Requires=postgresql.service
```

### Restart a Service AND Its Reverse Dependencies

```bash
DEPS=$(systemctl list-dependencies --reverse --plain postgresql.service \
       | tail -n +2 | awk '{print $1}')
systemctl restart postgresql
for d in $DEPS; do systemctl restart "$d"; done
```

---

## 4. Custom Watchdog Script with Exponential Backoff

```bash
#!/usr/bin/env bash
# /usr/local/bin/auto-restarter.sh
set -euo pipefail

SERVICE="${1:?usage: $0 <service> [health-url]}"
HEALTH_URL="${2:-}"
LOG=/var/log/auto-restarter.log
STATE_DIR=/var/lib/auto-restarter
mkdir -p "$STATE_DIR"
STATE_FILE="$STATE_DIR/$SERVICE.state"

MAX_ATTEMPTS=5
BASE_DELAY=5            # seconds
MAX_DELAY=300

log() { echo "[$(date -Iseconds)] $*" | tee -a "$LOG"; }

attempts=0
[ -f "$STATE_FILE" ] && attempts=$(cat "$STATE_FILE")

# Health check
if [ -n "$HEALTH_URL" ]; then
  if curl -fsS --max-time 5 "$HEALTH_URL" >/dev/null 2>&1; then
    log "$SERVICE healthy via $HEALTH_URL — resetting attempts"
    echo 0 > "$STATE_FILE"
    exit 0
  fi
elif systemctl is-active --quiet "$SERVICE"; then
  log "$SERVICE active — resetting attempts"
  echo 0 > "$STATE_FILE"
  exit 0
fi

if [ "$attempts" -ge "$MAX_ATTEMPTS" ]; then
  log "$SERVICE exceeded $MAX_ATTEMPTS restart attempts — ESCALATING"
  /usr/local/bin/auto-restarter-notify.sh "$SERVICE" "ESCALATION: $attempts failed restarts" || true
  exit 2
fi

# Exponential backoff
delay=$(( BASE_DELAY * (2 ** attempts) ))
[ "$delay" -gt "$MAX_DELAY" ] && delay=$MAX_DELAY
log "$SERVICE down — attempt $((attempts+1))/$MAX_ATTEMPTS, sleeping ${delay}s"
sleep "$delay"

# Capture pre-restart logs for forensics
journalctl -u "$SERVICE" -n 100 --no-pager > "$STATE_DIR/$SERVICE.lastcrash.log" || true

if systemctl restart "$SERVICE"; then
  sleep 3
  if systemctl is-active --quiet "$SERVICE"; then
    log "$SERVICE restarted successfully"
    echo 0 > "$STATE_FILE"
    /usr/local/bin/auto-restarter-notify.sh "$SERVICE" "Recovered after $((attempts+1)) attempts" || true
    exit 0
  fi
fi

attempts=$((attempts+1))
echo "$attempts" > "$STATE_FILE"
log "$SERVICE restart failed — attempts=$attempts"
exit 1
```

### Install and Enable

```bash
chmod +x /usr/local/bin/auto-restarter.sh
( crontab -l 2>/dev/null; echo "* * * * * /usr/local/bin/auto-restarter.sh nginx http://localhost/health" ) | crontab -
```

---

## 5. Notification Helper

```bash
#!/usr/bin/env bash
# /usr/local/bin/auto-restarter-notify.sh
SERVICE="$1"
MSG="$2"
HOST=$(hostname)
TS=$(date -Iseconds)

# Webhook (Slack/Discord/generic)
if [ -n "${RESTART_WEBHOOK_URL:-}" ]; then
  curl -fsS -X POST "$RESTART_WEBHOOK_URL" \
    -H 'Content-Type: application/json' \
    -d "{\"text\":\"[$HOST] $SERVICE: $MSG ($TS)\"}" >/dev/null || true
fi

# Email fallback
if command -v mail >/dev/null 2>&1 && [ -n "${RESTART_EMAIL:-}" ]; then
  echo "$MSG" | mail -s "[$HOST] $SERVICE restart event" "$RESTART_EMAIL" || true
fi

# Telegram
if [ -n "${TG_BOT_TOKEN:-}" ] && [ -n "${TG_CHAT_ID:-}" ]; then
  curl -fsS "https://api.telegram.org/bot${TG_BOT_TOKEN}/sendMessage" \
    -d "chat_id=${TG_CHAT_ID}" \
    -d "text=[$HOST] $SERVICE: $MSG" >/dev/null || true
fi
```

```bash
chmod +x /usr/local/bin/auto-restarter-notify.sh
```

---

## 6. Pre-Restart Health Checks

### HTTP Endpoint

```bash
curl -fsS --max-time 5 http://localhost/health >/dev/null
```

### TCP Port Open

```bash
nc -z -w 3 127.0.0.1 5432
```

### Database Ping (PostgreSQL)

```bash
sudo -u postgres psql -c 'SELECT 1' >/dev/null
```

### Database Ping (MySQL)

```bash
mysqladmin ping --silent
```

### Redis

```bash
redis-cli ping | grep -q PONG
```

### Process Alive (PID file)

```bash
PID=$(cat /run/myapp.pid 2>/dev/null)
[ -n "$PID" ] && kill -0 "$PID" 2>/dev/null
```

---

## 7. monit Configuration

### Install

```bash
apt install -y monit
```

### Per-Service Check

```ini
# /etc/monit/conf.d/nginx
check process nginx with pidfile /run/nginx.pid
  start program = "/bin/systemctl start nginx"
  stop  program = "/bin/systemctl stop nginx"
  if failed host 127.0.0.1 port 80 protocol http request "/health"
     for 3 cycles then restart
  if 5 restarts within 10 cycles then alert
```

### Apply

```bash
monit -t                # syntax test
systemctl restart monit
monit status
monit summary
```

### Force a Recheck

```bash
monit reload
monit restart nginx
```

---

## 8. supervisord Configuration

### Install

```bash
apt install -y supervisor
```

### Process Definition

```ini
# /etc/supervisor/conf.d/myapp.conf
[program:myapp]
command=/usr/local/bin/myapp --port 8080
directory=/srv/myapp
autostart=true
autorestart=true
startretries=5
startsecs=10
stopwaitsecs=30
stderr_logfile=/var/log/myapp.err.log
stdout_logfile=/var/log/myapp.out.log
user=www-data
environment=NODE_ENV="production"
```

### Apply

```bash
supervisorctl reread
supervisorctl update
supervisorctl status
supervisorctl restart myapp
```

---

## 9. Watchdog with sd_notify (Native systemd)

### Unit File

```ini
# /etc/systemd/system/myapp.service
[Unit]
Description=MyApp with watchdog
After=network-online.target

[Service]
Type=notify
ExecStart=/usr/local/bin/myapp
WatchdogSec=30s
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

The application must call `sd_notify(0, "WATCHDOG=1")` every <30s, or systemd kills and restarts it.

---

## 10. Restart Loop Prevention

### Detect Restart Storms

```bash
journalctl -u nginx --since "1 hour ago" --no-pager \
  | grep -c "Started\|Stopped"
```

### `StartLimitBurst` / `StartLimitIntervalSec`

```ini
[Unit]
StartLimitIntervalSec=600
StartLimitBurst=5
[Service]
Restart=on-failure
RestartSec=10
```

If the service fails more than 5 times in 600s, systemd gives up and refuses to restart it (avoiding loop). Reset with:

```bash
systemctl reset-failed myapp
```

---

## 11. Bulk Auto-Restart for All Failed Services

```bash
#!/usr/bin/env bash
# /usr/local/bin/auto-restarter-bulk.sh
LOG=/var/log/auto-restarter.log
EXCLUDE_REGEX='^(sshd|systemd-|networking|firewalld|ufw)'

for svc in $(systemctl list-units --state=failed --no-legend --no-pager | awk '{print $2}'); do
  if [[ "$svc" =~ $EXCLUDE_REGEX ]]; then
    echo "[$(date -Iseconds)] SKIP critical $svc" >> "$LOG"
    continue
  fi
  /usr/local/bin/auto-restarter.sh "$svc" || true
done
```

```bash
chmod +x /usr/local/bin/auto-restarter-bulk.sh
( crontab -l 2>/dev/null; echo "*/2 * * * * /usr/local/bin/auto-restarter-bulk.sh" ) | crontab -
```

---

## 12. Systemd Path/Timer-Based Auto-Restart

### Restart Every 6 Hours via Timer

```ini
# /etc/systemd/system/myapp-reload.timer
[Unit]
Description=Periodically reload myapp

[Timer]
OnUnitActiveSec=6h
Unit=myapp-reload.service

[Install]
WantedBy=timers.target
```

```ini
# /etc/systemd/system/myapp-reload.service
[Unit]
Description=Reload myapp

[Service]
Type=oneshot
ExecStart=/bin/systemctl reload myapp
```

```bash
systemctl daemon-reload
systemctl enable --now myapp-reload.timer
systemctl list-timers
```

---

## 13. Restart Policy for Docker Containers

### Docker `restart=` Policy

```bash
docker run -d --restart=on-failure:5 --name web nginx
docker update --restart=unless-stopped web
docker inspect web --format '{{.HostConfig.RestartPolicy}}'
```

### docker-compose

```yaml
services:
  web:
    image: nginx
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-fsS", "http://localhost/"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 20s
```

---

## 14. Health Check + Restart Workflow

1. Cron triggers `/usr/local/bin/auto-restarter.sh <svc> <health-url>` every minute.
2. Script runs the health check.
3. If healthy → reset attempts counter to 0, exit.
4. If unhealthy → load attempts counter from `/var/lib/auto-restarter/<svc>.state`.
5. If attempts ≥ MAX → fire escalation notification, exit 2.
6. Otherwise sleep `BASE_DELAY * 2^attempts`, capped at `MAX_DELAY`.
7. Snapshot last 100 lines of journalctl for post-mortem.
8. `systemctl restart <svc>`.
9. Wait 3 seconds, re-check `is-active`.
10. On success notify recovery + reset counter; on failure increment counter.

---

## 15. Audit & Reporting

### How Many Restarts Today?

```bash
grep "$(date +%F)" /var/log/auto-restarter.log | grep -c restarted
```

### Per-Service Restart Counts

```bash
grep restarted /var/log/auto-restarter.log \
  | awk '{print $3}' | sort | uniq -c | sort -rn
```

### Services with Highest NRestarts

```bash
for u in $(systemctl list-units --type=service --state=running --no-legend | awk '{print $1}'); do
  n=$(systemctl show "$u" -p NRestarts --value)
  [ "${n:-0}" -gt 0 ] && echo "$n $u"
done | sort -rn | head
```

### Verify All Services Healthy

```bash
systemctl --failed --no-pager
systemctl is-system-running
```
