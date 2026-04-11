# Heartbeat Monitor Agent

Lightweight, fast heartbeat/ping system that continuously verifies the liveness of every monitored host and service. Performs ICMP ping, TCP port checks, HTTP endpoint checks, and custom heartbeat protocols in parallel. Detects dead services after configurable consecutive failures, generates an HTML dashboard, tracks uptime, and integrates with the notifications agent.

---

## Safety Rules

- NEVER run heavy port scans against unknown hosts (looks like an attack).
- ALWAYS use timeouts on every probe (`-W`, `--max-time`, `-w`) — never hang.
- NEVER alert on a single failed probe — require 3 consecutive failures by default.
- ALWAYS rate-limit checks (don’t exceed 1 probe/sec/target).
- ALWAYS log results to `/var/log/heartbeat-monitor.log` for forensics.
- NEVER store credentials in the targets file — use environment variables.
- Use parallel checks (`xargs -P` or `parallel`) but cap concurrency to avoid saturating the network.
- Notifications must degrade gracefully (`|| true`).
- Include a maintenance/silence window mechanism to avoid noise during planned work.

---

## 1. Required Tools

```bash
apt update && apt install -y \
  iputils-ping fping nmap netcat-openbsd curl jq \
  parallel bc moreutils dnsutils
```

---

## 2. Targets Configuration

### Format: `/etc/heartbeat-monitor/targets.tsv`

```
# name           type   target                     extra
google-dns       icmp   8.8.8.8                    -
db-primary       tcp    10.0.0.10:5432             -
api-prod         http   https://api.example.com/health  200
web-prod         http   https://example.com/         200
ssh-bastion      tcp    bastion.example.com:22     -
mailserver       tcp    mail.example.com:25        -
internal-cache   tcp    10.0.0.20:6379             -
```

```bash
mkdir -p /etc/heartbeat-monitor /var/lib/heartbeat-monitor /var/log/heartbeat-monitor
```

---

## 3. ICMP Ping Checks

### Single Ping with 2s Timeout

```bash
ping -c 1 -W 2 -q 8.8.8.8 >/dev/null && echo UP || echo DOWN
```

### Bulk ICMP with fping (Fast)

```bash
fping -a -q -r 1 -t 500 -i 10 -p 200 8.8.8.8 1.1.1.1 9.9.9.9 2>/dev/null
```

### fping from a File

```bash
awk '$2=="icmp"{print $3}' /etc/heartbeat-monitor/targets.tsv \
  | fping -a -q -r 1 -t 500 2>/dev/null
```

### Round-Trip Time (parse)

```bash
RTT=$(ping -c 3 -W 2 -q 8.8.8.8 | awk -F'/' '/rtt|round-trip/ {print $5}')
echo "RTT=${RTT}ms"
```

---

## 4. TCP Port Checks

### nc (netcat) — Fastest

```bash
nc -z -w 3 10.0.0.10 5432 && echo UP || echo DOWN
```

### bash builtin (no netcat needed)

```bash
timeout 3 bash -c '</dev/tcp/10.0.0.10/5432' && echo UP || echo DOWN
```

### nmap (verify and read banner)

```bash
nmap -Pn -p 5432 --host-timeout 5s 10.0.0.10 \
  | grep -q '5432/tcp open' && echo UP || echo DOWN
```

### TCP RTT with `nc -v` and `time`

```bash
START=$(date +%s%N)
nc -z -w 3 10.0.0.10 5432
END=$(date +%s%N)
echo "TCP RTT: $(( (END-START)/1000000 ))ms"
```

---

## 5. HTTP Endpoint Checks

### Basic curl with Timeout

```bash
curl -fsS -o /dev/null -w "%{http_code}\n" --max-time 5 https://example.com/health
```

### Strict: code + content match

```bash
RESP=$(curl -fsS --max-time 5 https://api.example.com/health)
echo "$RESP" | jq -e '.status=="ok"' >/dev/null && echo UP || echo DOWN
```

### Capture Multiple Metrics in One Call

```bash
curl -o /dev/null -s -w 'code=%{http_code} time=%{time_total} dns=%{time_namelookup} connect=%{time_connect} ssl=%{time_appconnect}\n' \
  --max-time 10 https://example.com/
```

### TLS Certificate Days Left

```bash
DAYS=$(echo | openssl s_client -servername example.com -connect example.com:443 2>/dev/null \
  | openssl x509 -noout -enddate \
  | cut -d= -f2 \
  | xargs -I{} date -d "{}" +%s \
  | awk -v now=$(date +%s) '{print int(($1-now)/86400)}')
echo "Cert valid for $DAYS days"
```

---

## 6. Custom Heartbeat Protocols

### UDP Echo

```bash
echo "PING $(date +%s)" | nc -u -w 2 10.0.0.30 7777
```

### DNS Resolution Probe

```bash
dig +short +time=2 +tries=1 example.com @8.8.8.8 | grep -qE '^[0-9]'
```

### Database Liveness

```bash
PGPASSWORD=$PG_PASS psql -h db -U monitor -d postgres -c 'SELECT 1' >/dev/null
mysqladmin -hdb -umonitor -p$MY_PASS ping --connect-timeout=3
redis-cli -h cache -t 3 ping | grep -q PONG
```

### Application "/healthz" Convention

```bash
curl -fsS --max-time 3 http://app/healthz | jq -e '.healthy==true' >/dev/null
```

---

## 7. The Heartbeat Engine

```bash
#!/usr/bin/env bash
# /usr/local/bin/heartbeat-monitor.sh
set -uo pipefail

TARGETS=/etc/heartbeat-monitor/targets.tsv
STATE_DIR=/var/lib/heartbeat-monitor
LOG=/var/log/heartbeat-monitor/heartbeat.log
DOWN_THRESHOLD=3                        # consecutive failures before alert
PARALLEL=20

mkdir -p "$STATE_DIR"

probe() {
  local name="$1" type="$2" target="$3" extra="$4"
  local status="DOWN" rtt_ms=0 start end
  start=$(date +%s%N)

  case "$type" in
    icmp)
      ping -c 1 -W 2 -q "$target" >/dev/null 2>&1 && status=UP
      ;;
    tcp)
      local host="${target%:*}" port="${target##*:}"
      timeout 3 bash -c "</dev/tcp/$host/$port" 2>/dev/null && status=UP
      ;;
    http)
      local expect="${extra:-200}"
      local code
      code=$(curl -fsS -o /dev/null -w '%{http_code}' --max-time 5 "$target" 2>/dev/null || echo 000)
      [ "$code" = "$expect" ] && status=UP
      ;;
    *)
      echo "[$(date -Iseconds)] UNKNOWN type=$type for $name" >> "$LOG"
      return
      ;;
  esac

  end=$(date +%s%N)
  rtt_ms=$(( (end-start)/1000000 ))

  local sf="$STATE_DIR/$name.state"
  local fails=0
  [ -f "$sf" ] && fails=$(awk '{print $2}' "$sf")
  if [ "$status" = UP ]; then
    if [ "$fails" -ge "$DOWN_THRESHOLD" ]; then
      /usr/local/bin/heartbeat-notify.sh "$name" RECOVERED "$target" || true
    fi
    echo "UP 0 $(date +%s) $rtt_ms" > "$sf"
  else
    fails=$((fails+1))
    echo "DOWN $fails $(date +%s) $rtt_ms" > "$sf"
    if [ "$fails" -eq "$DOWN_THRESHOLD" ]; then
      /usr/local/bin/heartbeat-notify.sh "$name" DOWN "$target" || true
    fi
  fi

  echo "[$(date -Iseconds)] $name $type $target $status rtt=${rtt_ms}ms fails=$fails" >> "$LOG"
}
export -f probe
export STATE_DIR LOG DOWN_THRESHOLD

grep -vE '^\s*(#|$)' "$TARGETS" \
  | parallel -j "$PARALLEL" --colsep '\s+' probe {1} {2} {3} {4}
```

### Install and Run Every Minute

```bash
chmod +x /usr/local/bin/heartbeat-monitor.sh
( crontab -l 2>/dev/null; echo "* * * * * /usr/local/bin/heartbeat-monitor.sh" ) | crontab -
```

---

## 8. Notification Helper

```bash
#!/usr/bin/env bash
# /usr/local/bin/heartbeat-notify.sh
NAME="$1" STATE="$2" TARGET="$3"
HOST=$(hostname)
TS=$(date -Iseconds)
MSG="[$HOST] $NAME is $STATE ($TARGET) at $TS"

[ -n "${HEARTBEAT_WEBHOOK:-}" ] && curl -fsS -X POST "$HEARTBEAT_WEBHOOK" \
  -H 'Content-Type: application/json' \
  -d "{\"text\":\"$MSG\"}" >/dev/null || true

[ -n "${TG_BOT_TOKEN:-}" ] && [ -n "${TG_CHAT_ID:-}" ] && \
  curl -fsS "https://api.telegram.org/bot${TG_BOT_TOKEN}/sendMessage" \
  -d "chat_id=${TG_CHAT_ID}" -d "text=$MSG" >/dev/null || true

command -v mail >/dev/null && [ -n "${HEARTBEAT_EMAIL:-}" ] && \
  echo "$MSG" | mail -s "[$HOST] heartbeat: $NAME $STATE" "$HEARTBEAT_EMAIL" || true

echo "$MSG" >> /var/log/heartbeat-monitor/notify.log
```

```bash
chmod +x /usr/local/bin/heartbeat-notify.sh
```

---

## 9. HTML Status Dashboard

```bash
#!/usr/bin/env bash
# /usr/local/bin/heartbeat-dashboard.sh
STATE_DIR=/var/lib/heartbeat-monitor
OUT=/var/www/html/heartbeat.html
mkdir -p "$(dirname "$OUT")"

{
  echo '<!doctype html><html><head><meta charset="utf-8"><title>Heartbeat</title>'
  echo '<meta http-equiv="refresh" content="30">'
  echo '<style>body{font-family:sans-serif;background:#111;color:#eee}'
  echo 'table{border-collapse:collapse;width:100%}td,th{padding:6px 12px;border-bottom:1px solid #333}'
  echo '.up{color:#4ade80;font-weight:bold}.down{color:#f87171;font-weight:bold}</style></head><body>'
  echo "<h1>Heartbeat Monitor — $(hostname)</h1>"
  echo "<p>Last updated: $(date -Iseconds)</p>"
  echo '<table><tr><th>Service</th><th>Status</th><th>Fails</th><th>Last Check</th><th>RTT (ms)</th></tr>'
  for f in "$STATE_DIR"/*.state; do
    [ -f "$f" ] || continue
    name=$(basename "$f" .state)
    read -r status fails ts rtt < "$f"
    cls=$(echo "$status" | tr 'A-Z' 'a-z')
    when=$(date -d "@$ts" '+%F %T')
    echo "<tr><td>$name</td><td class=\"$cls\">$status</td><td>$fails</td><td>$when</td><td>$rtt</td></tr>"
  done
  echo '</table></body></html>'
} > "$OUT"
```

### Schedule Every 30 Seconds

```bash
chmod +x /usr/local/bin/heartbeat-dashboard.sh
( crontab -l 2>/dev/null; echo "* * * * * /usr/local/bin/heartbeat-dashboard.sh" ) | crontab -
( crontab -l 2>/dev/null; echo "* * * * * sleep 30 && /usr/local/bin/heartbeat-dashboard.sh" ) | crontab -
```

---

## 10. Uptime Reporting

### Per-Service Uptime % from the Log

```bash
#!/usr/bin/env bash
# /usr/local/bin/heartbeat-uptime.sh
LOG=/var/log/heartbeat-monitor/heartbeat.log
SINCE="${1:-1 day ago}"
EPOCH=$(date -d "$SINCE" +%s)

awk -v since="$EPOCH" '
{
  ts=$1; gsub(/[\[\]]/,"",ts);
  cmd="date -d \"" ts "\" +%s"; cmd | getline t; close(cmd);
  if (t<since) next;
  name=$2; status=$5;
  total[name]++;
  if (status=="UP") up[name]++;
}
END {
  for (n in total) printf "%-25s %6.2f%% (%d/%d)\n", n, up[n]*100/total[n], up[n], total[n];
}' "$LOG" | sort
```

### Run Daily

```bash
( crontab -l 2>/dev/null; echo "0 6 * * * /usr/local/bin/heartbeat-uptime.sh '24 hours ago' | mail -s 'Daily uptime report' admin@example.com" ) | crontab -
```

---

## 11. Maintenance / Silence Windows

### Silence a Target Temporarily

```bash
mkdir -p /etc/heartbeat-monitor/silenced
touch /etc/heartbeat-monitor/silenced/db-primary       # silenced
rm    /etc/heartbeat-monitor/silenced/db-primary       # un-silenced
```

### Engine Skip Logic (add inside `probe()`)

```bash
[ -f "/etc/heartbeat-monitor/silenced/$name" ] && return 0
```

### Auto-expire Silences After 1 Hour

```bash
find /etc/heartbeat-monitor/silenced -type f -mmin +60 -delete
```

---

## 12. Parallel Bulk Probing with GNU parallel

### Probe 1000 Hosts in Parallel (capped at 50 workers)

```bash
cat hosts.txt | parallel -j 50 --bar 'ping -c1 -W1 -q {} >/dev/null && echo "{} UP" || echo "{} DOWN"'
```

### Probe via xargs (no parallel package)

```bash
awk '$2=="icmp"{print $3}' /etc/heartbeat-monitor/targets.tsv \
  | xargs -P 20 -I{} sh -c 'ping -c1 -W2 -q "{}" >/dev/null && echo UP {} || echo DOWN {}'
```

---

## 13. Integration with Notifications Agent

If `agents/notifications/notify.sh` exists, hand off:

```bash
# inside heartbeat-notify.sh
if [ -x /etc/claudeos/agents/notifications/notify.sh ]; then
  /etc/claudeos/agents/notifications/notify.sh "$NAME $STATE on $HOST" || true
fi
```

---

## 14. systemd Timer Alternative (instead of cron)

```ini
# /etc/systemd/system/heartbeat.service
[Unit]
Description=Heartbeat Monitor
[Service]
Type=oneshot
ExecStart=/usr/local/bin/heartbeat-monitor.sh
Nice=10
IOSchedulingClass=best-effort
```

```ini
# /etc/systemd/system/heartbeat.timer
[Unit]
Description=Run heartbeat every 30s
[Timer]
OnBootSec=30s
OnUnitActiveSec=30s
AccuracySec=1s
[Install]
WantedBy=timers.target
```

```bash
systemctl daemon-reload
systemctl enable --now heartbeat.timer
systemctl list-timers | grep heartbeat
```

---

## 15. Quick Status Commands

### Show Current Down Services

```bash
grep -l '^DOWN' /var/lib/heartbeat-monitor/*.state | xargs -r -I{} basename {} .state
```

### Tail Live Probe Output

```bash
tail -F /var/log/heartbeat-monitor/heartbeat.log
```

### Probe Counts Today

```bash
grep -c "$(date +%F)" /var/log/heartbeat-monitor/heartbeat.log
```

### Top 10 Slowest Targets

```bash
awk '{for(i=1;i<=NF;i++) if($i ~ /^rtt=/){gsub("rtt=|ms","",$i); print $i, $2}}' \
  /var/log/heartbeat-monitor/heartbeat.log \
  | sort -rn | head
```

### Failed-Probe Summary

```bash
awk '/DOWN/{print $2}' /var/log/heartbeat-monitor/heartbeat.log \
  | sort | uniq -c | sort -rn | head
```

---

## 16. Workflow Summary

1. Edit `/etc/heartbeat-monitor/targets.tsv` to add services.
2. Cron/systemd timer runs `heartbeat-monitor.sh` every minute (or 30s via timer).
3. Each target probed in parallel via GNU parallel with timeouts.
4. State written to `/var/lib/heartbeat-monitor/<name>.state`.
5. After 3 consecutive failures, `heartbeat-notify.sh` fires once (DOWN).
6. On recovery (UP after being DOWN), a RECOVERED notification fires.
7. `heartbeat-dashboard.sh` regenerates `/var/www/html/heartbeat.html`.
8. Daily uptime report emailed via `heartbeat-uptime.sh`.
9. Silence files in `/etc/heartbeat-monitor/silenced/` suppress noise during maintenance.
