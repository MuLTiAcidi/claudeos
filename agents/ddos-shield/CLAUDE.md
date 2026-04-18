# DDoS Shield Agent

DDoS detection and automatic mitigation agent. Continuously monitors connection counts, packet rates, SYN floods, and HTTP request patterns. Automatically applies layered defenses: kernel-level (sysctl, syncookies), netfilter (iptables/nftables rate limits, ipset blacklists), application (nginx rate limiting), and ban systems (fail2ban). Includes GeoIP filtering and traffic visualization.

---

## Safety Rules

- NEVER block your own management/SSH IP — always whitelist it first.
- ALWAYS test rate limits with a low threshold trigger before pushing aggressive ones.
- NEVER flush iptables with `iptables -F` without saving rules first.
- ALWAYS keep an emergency `iptables-restore` rollback file ready.
- NEVER permanently ban large CIDR blocks without manual review.
- ALWAYS log every block to `/var/log/ddos-shield.log` with IP, reason, and timestamp.
- Use `ipset` (not individual iptables rules) for blocklists with >50 IPs.
- ALWAYS leave a documented unblock procedure in case of false positives.
- NEVER disable conntrack on a busy server without testing — it can cripple NAT.
- Rate limits should be set per-IP, not globally, to avoid self-DOS.

---

## 1. Detection — Connection & Traffic Baselines

### Count ESTABLISHED Connections

```bash
netstat -an | grep ESTABLISHED | wc -l
```

### Top 20 IPs by Connection Count

```bash
netstat -an | grep ESTABLISHED | awk '{print $5}' | cut -d: -f1 \
  | sort | uniq -c | sort -rn | head -20
```

### `ss` Connection Summary (Faster Than netstat)

```bash
ss -s
ss -tan state established | awk 'NR>1 {print $4}' | cut -d: -f1 \
  | sort | uniq -c | sort -rn | head -20
```

### SYN_RECV Count (SYN Flood Indicator)

```bash
ss -tan state syn-recv | wc -l
netstat -an | grep SYN_RECV | wc -l
```

### Per-Port Connection Counts

```bash
ss -tan | awk 'NR>1 {print $4}' | awk -F: '{print $NF}' | sort | uniq -c | sort -rn
```

### Live Packet Rate (pps)

```bash
sar -n DEV 1 5
```

### Conntrack Table Saturation

```bash
cat /proc/sys/net/netfilter/nf_conntrack_count
cat /proc/sys/net/netfilter/nf_conntrack_max
conntrack -L 2>/dev/null | wc -l
```

### Top Talkers Right Now (iftop)

```bash
apt install -y iftop
iftop -nNP -t -s 10
```

### Per-Process Bandwidth (nethogs)

```bash
apt install -y nethogs
nethogs -t -c 5
```

### HTTP Requests Per Second from Access Log

```bash
tail -n 10000 /var/log/nginx/access.log | awk '{print $4}' \
  | cut -c2-21 | sort | uniq -c | sort -rn | head
```

### Top HTTP Attacker IPs (last 10k requests)

```bash
tail -n 10000 /var/log/nginx/access.log | awk '{print $1}' \
  | sort | uniq -c | sort -rn | head -20
```

---

## 2. Kernel-Level Hardening (sysctl)

### Apply DDoS-Resistant sysctl

```bash
cat > /etc/sysctl.d/99-ddos-shield.conf <<'EOF'
# SYN flood protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 3

# Connection tracking
net.netfilter.nf_conntrack_max = 1048576
net.netfilter.nf_conntrack_tcp_timeout_established = 86400
net.netfilter.nf_conntrack_tcp_timeout_syn_recv = 30

# Reverse path filtering (anti-spoof)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore broadcast pings (smurf attack)
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Drop source-routed packets
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Disable ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0

# TIME_WAIT reuse
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15

# Increase backlog
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 16384
EOF

sysctl --system
sysctl net.ipv4.tcp_syncookies
```

---

## 3. iptables Rate Limiting

### WHITELIST Your IP First

```bash
ADMIN_IP=YOUR.ADMIN.IP.HERE
iptables -I INPUT 1 -s "$ADMIN_IP" -j ACCEPT
```

### Save Current Rules Before Changes

```bash
iptables-save > /etc/iptables/rules.v4.bak.$(date +%F-%H%M%S)
```

### Limit New Connections to Port 80/443 (Per IP)

```bash
iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW \
  -m limit --limit 50/sec --limit-burst 100 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -j DROP
```

### SYN Flood Protection

```bash
iptables -N SYN_FLOOD
iptables -A INPUT -p tcp --syn -j SYN_FLOOD
iptables -A SYN_FLOOD -m limit --limit 10/s --limit-burst 20 -j RETURN
iptables -A SYN_FLOOD -j DROP
```

### Limit Concurrent Connections Per IP (connlimit)

```bash
iptables -A INPUT -p tcp --syn --dport 80 \
  -m connlimit --connlimit-above 30 --connlimit-mask 32 -j REJECT
```

### Limit ICMP Pings

```bash
iptables -A INPUT -p icmp --icmp-type echo-request \
  -m limit --limit 5/s --limit-burst 10 -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
```

### Drop Invalid Packets

```bash
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
```

### Drop Fragmented Packets

```bash
iptables -A INPUT -f -j DROP
```

### Drop XMAS / NULL Scans

```bash
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
```

### Save Rules Persistently

```bash
apt install -y iptables-persistent
iptables-save > /etc/iptables/rules.v4
```

---

## 4. ipset — High-Performance Blacklists

### Install and Create a Blacklist Set

```bash
apt install -y ipset
ipset create ddos_blacklist hash:ip hashsize 4096 maxelem 1000000 timeout 3600
ipset create ddos_blacklist_net hash:net hashsize 4096 maxelem 65536
```

### Hook ipset into iptables

```bash
iptables -I INPUT -m set --match-set ddos_blacklist src -j DROP
iptables -I INPUT -m set --match-set ddos_blacklist_net src -j DROP
```

### Add an IP to the Blacklist (with TTL)

```bash
ipset add ddos_blacklist 1.2.3.4 timeout 86400
```

### Add a Whole CIDR

```bash
ipset add ddos_blacklist_net 1.2.3.0/24
```

### List Blocked IPs

```bash
ipset list ddos_blacklist
ipset list ddos_blacklist_net | head -20
```

### Persist ipset Across Reboots

```bash
ipset save > /etc/ipset.conf
cat > /etc/systemd/system/ipset-persistent.service <<'EOF'
[Unit]
Description=ipset persistent rules
Before=network-pre.target
[Service]
Type=oneshot
ExecStart=/sbin/ipset restore -file /etc/ipset.conf
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF
systemctl enable ipset-persistent
```

---

## 5. nginx Rate Limiting

### Define Zones in `/etc/nginx/nginx.conf` (http block)

```nginx
limit_req_zone  $binary_remote_addr zone=req_per_ip:10m rate=10r/s;
limit_req_zone  $binary_remote_addr zone=login_zone:10m  rate=1r/s;
limit_conn_zone $binary_remote_addr zone=conn_per_ip:10m;
```

### Apply Per Server/Location

```nginx
server {
    listen 80;
    server_name example.com;

    # Global per-IP limit (10 req/s, burst 20)
    limit_req      zone=req_per_ip burst=20 nodelay;
    limit_conn     conn_per_ip 30;

    # Stricter for login
    location /login {
        limit_req  zone=login_zone burst=3 nodelay;
        proxy_pass http://backend;
    }

    # Drop slow clients
    client_body_timeout   10s;
    client_header_timeout 10s;
    keepalive_timeout     15s;
    send_timeout          10s;

    # Limit body size to stop POST floods
    client_max_body_size  1m;
}
```

### Test and Reload

```bash
nginx -t && systemctl reload nginx
```

### Tail Rate-Limit Hits

```bash
tail -F /var/log/nginx/error.log | grep -i "limiting requests"
```

---

## 6. fail2ban for HTTP Floods

### Install

```bash
apt install -y fail2ban
```

### Jail: Detect 429s from nginx

```ini
# /etc/fail2ban/jail.d/nginx-ddos.conf
[nginx-req-limit]
enabled  = true
filter   = nginx-req-limit
action   = iptables-multiport[name=ReqLimit, port="http,https", protocol=tcp]
logpath  = /var/log/nginx/error.log
findtime = 600
bantime  = 7200
maxretry = 10

[nginx-botsearch]
enabled  = true
port     = http,https
filter   = nginx-botsearch
logpath  = /var/log/nginx/access.log
maxretry = 5
bantime  = 3600
```

### Filter Definition

```ini
# /etc/fail2ban/filter.d/nginx-req-limit.conf
[Definition]
failregex = limiting requests, excess:.* by zone.*client: <HOST>
ignoreregex =
```

### Apply

```bash
systemctl restart fail2ban
fail2ban-client status
fail2ban-client status nginx-req-limit
```

### Manually Ban / Unban

```bash
fail2ban-client set nginx-req-limit banip 1.2.3.4
fail2ban-client set nginx-req-limit unbanip 1.2.3.4
```

---

## 7. conntrack Monitoring

### Watch for Conntrack Saturation

```bash
watch -n 1 'echo "count: $(cat /proc/sys/net/netfilter/nf_conntrack_count) / $(cat /proc/sys/net/netfilter/nf_conntrack_max)"'
```

### Top Source IPs in Conntrack

```bash
conntrack -L 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i ~ /^src=/) print $i}' \
  | sort | uniq -c | sort -rn | head -20
```

### Drop Connections from a Specific IP

```bash
conntrack -D -s 1.2.3.4
```

---

## 8. GeoIP Blocking

### Install GeoIP Database

```bash
apt install -y geoip-bin geoip-database xtables-addons-common libtext-csv-xs-perl
mkdir -p /usr/share/xt_geoip
/usr/libexec/xtables-addons/xt_geoip_dl   2>/dev/null \
  || /usr/lib/xtables-addons/xt_geoip_dl
/usr/libexec/xtables-addons/xt_geoip_build -D /usr/share/xt_geoip *.csv \
  2>/dev/null \
  || /usr/lib/xtables-addons/xt_geoip_build -D /usr/share/xt_geoip *.csv
```

### Block Traffic from Specific Countries

```bash
iptables -I INPUT -m geoip --src-cc CN,RU,KP -j DROP
```

### Allow Only Specific Countries

```bash
iptables -I INPUT -m geoip ! --src-cc US,CA,GB -j DROP
```

### Country Lookup for an IP

```bash
geoiplookup 1.2.3.4
```

---

## 9. Auto-Mitigation Watchdog

### Detection + Block Script

```bash
#!/usr/bin/env bash
# /usr/local/bin/ddos-watchdog.sh
set -euo pipefail

THRESHOLD=200            # connections per IP threshold
BAN_SECONDS=3600
LOG=/var/log/ddos-shield.log
WHITELIST=/etc/ddos-shield/whitelist.txt

mkdir -p /etc/ddos-shield
touch "$WHITELIST"

# Ensure ipset and iptables hook exist
ipset list ddos_blacklist >/dev/null 2>&1 \
  || ipset create ddos_blacklist hash:ip timeout "$BAN_SECONDS"
iptables -C INPUT -m set --match-set ddos_blacklist src -j DROP 2>/dev/null \
  || iptables -I INPUT -m set --match-set ddos_blacklist src -j DROP

ss -tan state established 2>/dev/null \
  | awk 'NR>1 {print $4}' | cut -d: -f1 \
  | sort | uniq -c | sort -rn \
  | while read -r count ip; do
      [ -z "$ip" ] && continue
      if grep -qx "$ip" "$WHITELIST"; then continue; fi
      if [ "$count" -ge "$THRESHOLD" ]; then
        if ! ipset test ddos_blacklist "$ip" 2>/dev/null; then
          ipset add ddos_blacklist "$ip" timeout "$BAN_SECONDS" 2>/dev/null || true
          echo "[$(date -Iseconds)] BLOCK $ip count=$count" >> "$LOG"
        fi
      fi
    done
```

### Run It Every Minute via Cron

```bash
chmod +x /usr/local/bin/ddos-watchdog.sh
( crontab -l 2>/dev/null; echo "* * * * * /usr/local/bin/ddos-watchdog.sh" ) | crontab -
```

### Add Your IP to Whitelist

```bash
echo "YOUR.ADMIN.IP" >> /etc/ddos-shield/whitelist.txt
```

---

## 10. Real-Time Traffic Visualization

### Live Bandwidth (iftop)

```bash
iftop -nNP -i eth0
```

### Per-Process Bandwidth (nethogs)

```bash
nethogs eth0
```

### Packet Rate Per Interface

```bash
ifstat -i eth0 1
```

### Top HTTP Attackers (live tail)

```bash
tail -F /var/log/nginx/access.log \
  | awk '{print $1}' \
  | pv -l -i 5 -r > /dev/null
```

---

## 11. Incident Response Workflow

1. **Detect**: alerts from watchdog, sudden spike in `ss -s` or nginx 4xx/5xx.
2. **Identify attack vector**: SYN flood? HTTP flood? UDP amp? Use `ss`, `tcpdump -nn`, nginx logs.
3. **Contain**:
   - SYN flood → confirm syncookies, raise tcp_max_syn_backlog.
   - HTTP flood → tighten nginx `limit_req` + ban via fail2ban.
   - Volumetric → blackhole upstream at provider, GeoIP-block hot regions.
4. **Whitelist** management IPs before tightening.
5. **Block** with `ipset add ddos_blacklist <ip>`.
6. **Monitor** `ss -s`, `netstat -s | grep -i drop`, conntrack count.
7. **Post-mortem**: dump banned IPs, attack peak pps, time to mitigate.
8. **Lift bans** after 24h with `ipset flush ddos_blacklist` if traffic normalized.

---

## 12. Emergency Rollback

### Restore Saved iptables

```bash
ls -lh /etc/iptables/rules.v4.bak.*
iptables-restore < /etc/iptables/rules.v4.bak.<timestamp>
```

### Flush ipset Blocklist

```bash
ipset flush ddos_blacklist
ipset flush ddos_blacklist_net
```

### Stop fail2ban (if it banned you)

```bash
fail2ban-client unban --all
systemctl restart fail2ban
```

---

## 13. Notification Hook

### Notify on Block (curl webhook)

```bash
notify_block() {
  local ip="$1" count="$2"
  curl -fsS -X POST "$DDOS_WEBHOOK_URL" \
    -H 'Content-Type: application/json' \
    -d "{\"text\":\"DDoS-Shield blocked $ip (connections=$count) on $(hostname)\"}" \
    >/dev/null || true
}
```

### Daily Summary

```bash
#!/usr/bin/env bash
LOG=/var/log/ddos-shield.log
TODAY=$(date +%F)
COUNT=$(grep "^\[$TODAY" "$LOG" | grep -c BLOCK)
echo "DDoS-Shield: $COUNT IPs blocked on $TODAY" \
  | mail -s "DDoS daily report" admin@example.com
```

---

## 14. Verification After Mitigation

```bash
ss -s
sysctl net.ipv4.tcp_syncookies
ipset list ddos_blacklist | head -20
iptables -L INPUT -nv --line-numbers | head -30
tail -50 /var/log/ddos-shield.log
curl -fsS -o /dev/null -w "%{http_code}\n" http://localhost/
```

---

## 15. Layer 7 DDoS Protection

### HTTP Flood Detection (Request Fingerprinting)

Fingerprint incoming requests by method + path + user-agent + accept-encoding to identify botnets sending identical requests.

```bash
#!/usr/bin/env bash
# /usr/local/bin/l7-flood-detector.sh
set -euo pipefail

LOG=/var/log/nginx/access.log
THRESHOLD=100        # identical fingerprints in 60s = flood
WINDOW=60
OUTPUT=/var/log/ddos-shield-l7.log

# Build request fingerprints from last $WINDOW seconds
awk -v cutoff="$(date -d "-${WINDOW} seconds" '+%d/%b/%Y:%H:%M:%S' 2>/dev/null || date -v-${WINDOW}S '+%d/%b/%Y:%H:%M:%S')" '
  $4 > "["cutoff {
    # fingerprint = IP + method + path + user-agent hash
    ip = $1
    method = $6
    path = $7
    ua = ""
    for (i=12; i<=NF; i++) ua = ua $i
    fingerprint = ip "|" method "|" path "|" ua
    count[fingerprint]++
    ips[fingerprint] = ip
  }
  END {
    for (fp in count) {
      if (count[fp] >= '$THRESHOLD') {
        print ips[fp], count[fp], fp
      }
    }
  }
' "$LOG" | while read -r ip count fp; do
  if ! ipset test ddos_blacklist "$ip" 2>/dev/null; then
    ipset add ddos_blacklist "$ip" timeout 3600 2>/dev/null || true
    echo "[$(date -Iseconds)] L7-FLOOD BLOCK $ip fingerprint_count=$count" >> "$OUTPUT"
  fi
done
```

### Slowloris Defense (nginx)

Slowloris sends partial HTTP headers slowly to exhaust server connections. Tight timeouts kill it.

```nginx
# /etc/nginx/conf.d/slowloris-defense.conf
# Aggressive timeouts to kill slow connections
client_header_timeout  5s;
client_body_timeout    5s;
send_timeout           5s;
keepalive_timeout      10s 10s;
keepalive_requests     100;

# Limit connections per IP tightly
limit_conn_zone $binary_remote_addr zone=slowloris_guard:10m;
limit_conn slowloris_guard 20;

# Reject requests with no Host header (common in bots)
server {
    listen 80 default_server;
    server_name _;
    return 444;
}
```

### Challenge-Response for Suspicious Traffic (JS Challenge)

Serve a lightweight JS challenge before passing to backend. Bots without JS engines fail.

```nginx
# /etc/nginx/snippets/js-challenge.conf
# Use with map to challenge IPs that exceed soft limits
# Set $challenge_required via Lua or map

location @js_challenge {
    default_type text/html;
    return 200 '<!DOCTYPE html>
    <html><head><meta charset="utf-8">
    <script>
    (function(){
      var t = Date.now();
      var c = 0;
      for(var i=0;i<1000000;i++) c += i;
      document.cookie = "ddos_check=" + btoa(t + ":" + c) + ";path=/;max-age=300";
      window.location.reload();
    })();
    </script>
    </head><body>Verifying your browser...</body></html>';
}
```

### Validate Challenge Cookie in nginx

```nginx
map $cookie_ddos_check $passed_challenge {
    default 0;
    "~.+"   1;
}

server {
    # ... existing config ...
    
    # Challenge new visitors under heavy load
    set $need_challenge 0;
    if ($passed_challenge = 0) {
        set $need_challenge 1;
    }
    # Enable this block only during attacks (toggle via touch /tmp/ddos_challenge_active)
    if (-f /tmp/ddos_challenge_active) {
        set $need_challenge "${need_challenge}1";
    }
    if ($need_challenge = "11") {
        return 302 /challenge;
    }
    location = /challenge {
        try_files /dev/null @js_challenge;
    }
}
```

### Activate / Deactivate JS Challenge Mode

```bash
# Enable challenge mode (during active attack)
touch /tmp/ddos_challenge_active
nginx -t && systemctl reload nginx
echo "[$(date -Iseconds)] JS-CHALLENGE MODE ENABLED" >> /var/log/ddos-shield.log

# Disable challenge mode (attack subsided)
rm -f /tmp/ddos_challenge_active
nginx -t && systemctl reload nginx
echo "[$(date -Iseconds)] JS-CHALLENGE MODE DISABLED" >> /var/log/ddos-shield.log
```

---

## 16. Cloudflare / CDN API Integration

### Prerequisites

```bash
# Store credentials securely
mkdir -p /etc/ddos-shield
cat > /etc/ddos-shield/cloudflare.env <<'EOF'
CF_API_TOKEN="your-api-token-here"
CF_ZONE_ID="your-zone-id-here"
CF_ACCOUNT_ID="your-account-id-here"
EOF
chmod 600 /etc/ddos-shield/cloudflare.env
```

### Auto-Enable "Under Attack" Mode

```bash
#!/usr/bin/env bash
# /usr/local/bin/cf-under-attack.sh
set -euo pipefail
source /etc/ddos-shield/cloudflare.env

ACTION="${1:-enable}"

if [ "$ACTION" = "enable" ]; then
  LEVEL="under_attack"
  echo "[$(date -Iseconds)] CF: Enabling Under Attack mode" >> /var/log/ddos-shield.log
else
  LEVEL="medium"
  echo "[$(date -Iseconds)] CF: Disabling Under Attack mode (back to medium)" >> /var/log/ddos-shield.log
fi

curl -sS -X PATCH "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/settings/security_level" \
  -H "Authorization: Bearer $CF_API_TOKEN" \
  -H "Content-Type: application/json" \
  --data "{\"value\":\"$LEVEL\"}" | jq .
```

### Create Firewall Rules Programmatically (Block IPs)

```bash
#!/usr/bin/env bash
# /usr/local/bin/cf-block-ip.sh
set -euo pipefail
source /etc/ddos-shield/cloudflare.env

IP="$1"
NOTE="${2:-Blocked by DDoS Shield $(date -Iseconds)}"

# Add to Cloudflare IP Access Rules (account-level block)
curl -sS -X POST "https://api.cloudflare.com/client/v4/accounts/$CF_ACCOUNT_ID/firewall/access_rules/rules" \
  -H "Authorization: Bearer $CF_API_TOKEN" \
  -H "Content-Type: application/json" \
  --data "{
    \"mode\": \"block\",
    \"configuration\": {\"target\": \"ip\", \"value\": \"$IP\"},
    \"notes\": \"$NOTE\"
  }" | jq .

echo "[$(date -Iseconds)] CF-BLOCK $IP note='$NOTE'" >> /var/log/ddos-shield.log
```

### Challenge Suspicious Countries via Cloudflare

```bash
#!/usr/bin/env bash
# /usr/local/bin/cf-challenge-country.sh
set -euo pipefail
source /etc/ddos-shield/cloudflare.env

COUNTRIES="${1:-CN,RU,KP}"  # comma-separated country codes

# Build expression: (ip.geoip.country in {"CN" "RU" "KP"})
EXPR="(ip.geoip.country in {"
IFS=',' read -ra CC <<< "$COUNTRIES"
for c in "${CC[@]}"; do
  EXPR+="\"$c\" "
done
EXPR+="})"

curl -sS -X POST "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/firewall/rules" \
  -H "Authorization: Bearer $CF_API_TOKEN" \
  -H "Content-Type: application/json" \
  --data "[{
    \"filter\": {\"expression\": \"$EXPR\"},
    \"action\": \"managed_challenge\",
    \"description\": \"DDoS Shield: challenge $COUNTRIES\"
  }]" | jq .

echo "[$(date -Iseconds)] CF-CHALLENGE countries=$COUNTRIES" >> /var/log/ddos-shield.log
```

### Bulk Block from ipset (Push Local Bans to Cloudflare)

```bash
#!/usr/bin/env bash
# /usr/local/bin/cf-sync-bans.sh
set -euo pipefail
source /etc/ddos-shield/cloudflare.env

# Export current ipset bans and push to Cloudflare
ipset list ddos_blacklist | grep -E '^[0-9]' | awk '{print $1}' | while read -r ip; do
  /usr/local/bin/cf-block-ip.sh "$ip" "Auto-synced from local ipset"
  sleep 0.5  # rate limit API calls
done
```

### Get Current Cloudflare Security Level

```bash
source /etc/ddos-shield/cloudflare.env
curl -sS "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/settings/security_level" \
  -H "Authorization: Bearer $CF_API_TOKEN" | jq '.result.value'
```

---

## 17. WebSocket Flood Protection

### Detect WebSocket Connection Floods

```bash
#!/usr/bin/env bash
# /usr/local/bin/ws-flood-detector.sh
set -euo pipefail

WS_PORT="${1:-8080}"
THRESHOLD=50          # max WS connections per IP
BAN_SECONDS=1800
LOG=/var/log/ddos-shield-ws.log

# Count WebSocket connections per IP (ESTABLISHED on WS port)
ss -tan state established "( dport = :$WS_PORT )" 2>/dev/null \
  | awk 'NR>1 {print $4}' | rev | cut -d: -f2- | rev \
  | sort | uniq -c | sort -rn \
  | while read -r count ip; do
      [ -z "$ip" ] && continue
      if [ "$count" -ge "$THRESHOLD" ]; then
        if ! ipset test ddos_blacklist "$ip" 2>/dev/null; then
          ipset add ddos_blacklist "$ip" timeout "$BAN_SECONDS" 2>/dev/null || true
          echo "[$(date -Iseconds)] WS-FLOOD BLOCK $ip ws_connections=$count port=$WS_PORT" >> "$LOG"
        fi
      fi
    done
```

### nginx: Rate Limit WebSocket Upgrades

```nginx
# /etc/nginx/conf.d/websocket-protection.conf

# Rate limit WebSocket upgrade requests per IP
limit_req_zone $binary_remote_addr zone=ws_upgrade:10m rate=5r/s;

# Limit concurrent WebSocket connections per IP
limit_conn_zone $binary_remote_addr zone=ws_conn:10m;

map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

upstream websocket_backend {
    server 127.0.0.1:8080;
}

server {
    listen 443 ssl;
    server_name ws.example.com;

    location /ws {
        # Rate limit new WS connections
        limit_req zone=ws_upgrade burst=10 nodelay;
        
        # Max 20 concurrent WS connections per IP
        limit_conn ws_conn 20;

        proxy_pass http://websocket_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;

        # Kill idle WebSocket connections after 5 minutes
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
    }
}
```

### Detect WS Message Flooding (Application Level)

```python
#!/usr/bin/env python3
"""
/usr/local/bin/ws-message-monitor.py
Monitor WebSocket message rates per connection.
Deploy as middleware or standalone sniffer.
"""
import time
import collections
import subprocess
import sys

# Configuration
MAX_MESSAGES_PER_SEC = 50     # per connection
MAX_MESSAGES_PER_MIN = 500    # per IP
BAN_DURATION = 1800

# Track message counts: ip -> deque of timestamps
ip_messages = collections.defaultdict(lambda: collections.deque(maxlen=1000))

def check_and_ban(ip, timestamp):
    """Check if IP exceeds message rate limits."""
    q = ip_messages[ip]
    q.append(timestamp)
    
    # Messages in last second
    one_sec_ago = timestamp - 1
    recent = sum(1 for t in q if t > one_sec_ago)
    if recent > MAX_MESSAGES_PER_SEC:
        ban_ip(ip, f"ws_msg_per_sec={recent}")
        return True
    
    # Messages in last minute
    one_min_ago = timestamp - 60
    recent_min = sum(1 for t in q if t > one_min_ago)
    if recent_min > MAX_MESSAGES_PER_MIN:
        ban_ip(ip, f"ws_msg_per_min={recent_min}")
        return True
    
    return False

def ban_ip(ip, reason):
    """Add IP to ipset blacklist."""
    subprocess.run(
        ["ipset", "add", "ddos_blacklist", ip, "timeout", str(BAN_DURATION)],
        capture_output=True
    )
    with open("/var/log/ddos-shield-ws.log", "a") as f:
        f.write(f"[{time.strftime('%Y-%m-%dT%H:%M:%S%z')}] WS-MSG-FLOOD BLOCK {ip} {reason}\n")

# Integration point: call check_and_ban(client_ip, time.time())
# from your WebSocket server's on_message handler
```

---

## 18. Modern Botnet Pattern Detection

### Detect Headless Browser Fingerprints

Check for known headless browser indicators in user-agent strings and request patterns.

```bash
#!/usr/bin/env bash
# /usr/local/bin/headless-detector.sh
set -euo pipefail

LOG=/var/log/nginx/access.log
OUTPUT=/var/log/ddos-shield-bots.log
THRESHOLD=10   # requests from headless UA per IP in last 1000 lines

# Known headless browser signatures
HEADLESS_PATTERNS="HeadlessChrome|PhantomJS|Puppeteer|Selenium|webdriver|HEADLESS|python-requests/|Go-http-client|node-fetch|axios/|httpx|aiohttp|curl/|wget/"

tail -n 5000 "$LOG" | grep -iE "$HEADLESS_PATTERNS" \
  | awk '{print $1}' | sort | uniq -c | sort -rn \
  | while read -r count ip; do
      if [ "$count" -ge "$THRESHOLD" ]; then
        if ! ipset test ddos_blacklist "$ip" 2>/dev/null; then
          ipset add ddos_blacklist "$ip" timeout 7200 2>/dev/null || true
          echo "[$(date -Iseconds)] HEADLESS-BOT BLOCK $ip count=$count" >> "$OUTPUT"
        fi
      fi
    done
```

### nginx: Block Missing/Suspicious Headers

Legitimate browsers send Accept, Accept-Language, Accept-Encoding. Most bots don't.

```nginx
# /etc/nginx/snippets/bot-detection.conf

# Block requests with no Accept-Language (bots almost never send this)
if ($http_accept_language = '') {
    set $bot_score "${bot_score}1";
}

# Block requests with no Accept-Encoding
if ($http_accept_encoding = '') {
    set $bot_score "${bot_score}1";
}

# Block known automation user-agents
map $http_user_agent $is_bot {
    default 0;
    "~*headlesschrome"    1;
    "~*phantomjs"         1;
    "~*selenium"          1;
    "~*webdriver"         1;
    "~*puppeteer"         1;
    "~*python-requests"   1;
    "~*go-http-client"    1;
    "~*node-fetch"        1;
    "~*scrapy"            1;
    "~*curl/"             1;
    ""                    1;
}
```

### Detect Residential Proxy Traffic Patterns

Residential proxies rotate IPs but share behavioral fingerprints: identical request timing, same path patterns, similar header ordering.

```bash
#!/usr/bin/env bash
# /usr/local/bin/resi-proxy-detector.sh
set -euo pipefail

LOG=/var/log/nginx/access.log
OUTPUT=/var/log/ddos-shield-bots.log

# Detect: many different IPs hitting the exact same path with the exact same UA
# in a short time window — classic residential proxy botnet pattern
tail -n 10000 "$LOG" \
  | awk '{
      key = $7 "|" $12  # path + first UA word
      ips[key][$1] = 1
      count[key]++
    }
    END {
      for (key in count) {
        n = 0; for (ip in ips[key]) n++
        # Many unique IPs (>50), same path+UA = resi proxy swarm
        if (n > 50 && count[key] > 200) {
          print n, count[key], key
        }
      }
    }' | while read -r unique_ips total_reqs pattern; do
      echo "[$(date -Iseconds)] RESI-PROXY PATTERN unique_ips=$unique_ips total=$total_reqs pattern='$pattern'" >> "$OUTPUT"
    done
```

### Detect TLS Fingerprint Anomalies (JA3/JA4)

Use tshark or Suricata to capture JA3 hashes and detect when a single JA3 fingerprint is used by hundreds of IPs (botnet).

```bash
#!/usr/bin/env bash
# /usr/local/bin/ja3-detector.sh
# Requires: tshark with JA3 plugin or Suricata with JA3 logging
set -euo pipefail

OUTPUT=/var/log/ddos-shield-bots.log

# Option 1: Suricata JA3 (if eve.json logging is enabled)
if [ -f /var/log/suricata/eve.json ]; then
  # Find JA3 hashes seen from >30 unique IPs in last 5 minutes
  jq -r 'select(.event_type=="tls" and .tls.ja3 != null) |
    "\(.tls.ja3.hash) \(.src_ip)"' /var/log/suricata/eve.json \
    | sort | uniq \
    | awk '{print $1}' | sort | uniq -c | sort -rn \
    | while read -r count ja3; do
        if [ "$count" -gt 30 ]; then
          echo "[$(date -Iseconds)] JA3-ANOMALY hash=$ja3 unique_ips=$count (possible botnet)" >> "$OUTPUT"
        fi
      done
fi

# Option 2: tshark live capture (10 second sample)
if command -v tshark &>/dev/null; then
  tshark -i eth0 -a duration:10 -T fields \
    -e ip.src -e tls.handshake.ja3 \
    -Y "tls.handshake.type==1" 2>/dev/null \
    | sort | uniq \
    | awk '{print $2}' | sort | uniq -c | sort -rn \
    | while read -r count ja3; do
        if [ "$count" -gt 20 ]; then
          echo "[$(date -Iseconds)] JA3-LIVE hash=$ja3 unique_ips=$count" >> "$OUTPUT"
        fi
      done
fi
```

### Install JA3/JA4 Support

```bash
# Suricata with JA3 logging
apt install -y suricata
cat >> /etc/suricata/suricata.yaml <<'EOF'
app-layer:
  protocols:
    tls:
      ja3-fingerprints: yes
EOF
systemctl restart suricata

# Or use zeek with JA4 package
apt install -y zeek
zkg install ja4
```

---

## 19. Auto-Escalation Ladder

Automatic escalation from soft limits through emergency null route. Each step has thresholds and timers. If metrics don't improve within the timer, escalate to the next level.

### Escalation Levels

| Level | Trigger | Action | Timer |
|-------|---------|--------|-------|
| 0 - Normal | baseline | Standard rate limits | — |
| 1 - Alert | >500 conn/s OR >100 req/s per IP | Tighten nginx rate limits, enable JS challenge | 2 min |
| 2 - Hard Limits | Level 1 not resolved in 2 min | Drop per-IP limit to 5 conn, aggressive fail2ban | 3 min |
| 3 - Geo-Block | Level 2 not resolved in 3 min | Block top attacking countries via iptables GeoIP | 5 min |
| 4 - Under Attack | Level 3 not resolved in 5 min | Enable Cloudflare Under Attack mode | 10 min |
| 5 - Null Route | Level 4 not resolved in 10 min | Null route top /24 CIDRs at kernel level | manual deescalate |

### Auto-Escalation Engine

```bash
#!/usr/bin/env bash
# /usr/local/bin/ddos-escalation-engine.sh
# Run via: while true; do /usr/local/bin/ddos-escalation-engine.sh; sleep 30; done
set -euo pipefail

STATE_FILE=/var/run/ddos-shield-level
LOG=/var/log/ddos-shield.log
LEVEL=$(cat "$STATE_FILE" 2>/dev/null || echo 0)
LEVEL_TIME_FILE=/var/run/ddos-shield-level-time

# --- Metrics ---
TOTAL_CONN=$(ss -tan state established | wc -l)
TOTAL_SYN=$(ss -tan state syn-recv | wc -l)
TOP_IP_CONN=$(ss -tan state established | awk 'NR>1 {print $4}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -1 | awk '{print $1}')
TOP_IP_CONN=${TOP_IP_CONN:-0}

# Timestamps
NOW=$(date +%s)
LEVEL_SINCE=$(cat "$LEVEL_TIME_FILE" 2>/dev/null || echo "$NOW")
ELAPSED=$(( NOW - LEVEL_SINCE ))

should_escalate() {
  case $LEVEL in
    0) [ "$TOTAL_CONN" -gt 5000 ] || [ "$TOP_IP_CONN" -gt 100 ] || [ "$TOTAL_SYN" -gt 500 ] ;;
    1) [ "$ELAPSED" -gt 120 ] && ([ "$TOTAL_CONN" -gt 5000 ] || [ "$TOTAL_SYN" -gt 500 ]) ;;
    2) [ "$ELAPSED" -gt 180 ] && ([ "$TOTAL_CONN" -gt 5000 ] || [ "$TOTAL_SYN" -gt 500 ]) ;;
    3) [ "$ELAPSED" -gt 300 ] && ([ "$TOTAL_CONN" -gt 5000 ] || [ "$TOTAL_SYN" -gt 500 ]) ;;
    4) [ "$ELAPSED" -gt 600 ] && ([ "$TOTAL_CONN" -gt 5000 ] || [ "$TOTAL_SYN" -gt 500 ]) ;;
    *) false ;;
  esac
}

should_deescalate() {
  [ "$TOTAL_CONN" -lt 2000 ] && [ "$TOTAL_SYN" -lt 100 ] && [ "$TOP_IP_CONN" -lt 30 ] && [ "$ELAPSED" -gt 300 ]
}

escalate() {
  LEVEL=$(( LEVEL + 1 ))
  echo "$LEVEL" > "$STATE_FILE"
  echo "$NOW" > "$LEVEL_TIME_FILE"
  echo "[$(date -Iseconds)] ESCALATE to LEVEL $LEVEL (conn=$TOTAL_CONN syn=$TOTAL_SYN top_ip=$TOP_IP_CONN)" >> "$LOG"

  case $LEVEL in
    1)
      echo "[$(date -Iseconds)] L1: Tightening rate limits + JS challenge" >> "$LOG"
      touch /tmp/ddos_challenge_active
      nginx -t && systemctl reload nginx 2>/dev/null || true
      ;;
    2)
      echo "[$(date -Iseconds)] L2: Hard limits — 5 conn per IP" >> "$LOG"
      iptables -R INPUT -p tcp --syn --dport 80 \
        -m connlimit --connlimit-above 5 --connlimit-mask 32 -j REJECT 2>/dev/null || \
      iptables -A INPUT -p tcp --syn --dport 80 \
        -m connlimit --connlimit-above 5 --connlimit-mask 32 -j REJECT
      ;;
    3)
      echo "[$(date -Iseconds)] L3: GeoIP blocking top attacking countries" >> "$LOG"
      # Block top attacking countries (auto-detected from conntrack)
      conntrack -L 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i ~ /^src=/) print $i}' \
        | sed 's/src=//' | sort | uniq -c | sort -rn | head -100 \
        | awk '{print $2}' | while read -r ip; do
            COUNTRY=$(geoiplookup "$ip" 2>/dev/null | head -1 | awk -F': ' '{print $2}' | cut -c1-2)
            [ -n "$COUNTRY" ] && echo "$COUNTRY"
          done | sort | uniq -c | sort -rn | head -3 | awk '{print $2}' \
        | while read -r cc; do
            iptables -I INPUT -m geoip --src-cc "$cc" -j DROP 2>/dev/null || true
            echo "[$(date -Iseconds)] L3: GeoIP blocked country=$cc" >> "$LOG"
          done
      ;;
    4)
      echo "[$(date -Iseconds)] L4: Cloudflare Under Attack mode" >> "$LOG"
      /usr/local/bin/cf-under-attack.sh enable 2>/dev/null || true
      ;;
    5)
      echo "[$(date -Iseconds)] L5: EMERGENCY — Null routing top attacking CIDRs" >> "$LOG"
      # Null route top 10 attacking /24 networks
      ss -tan state established | awk 'NR>1 {print $5}' | cut -d: -f1 \
        | sed 's/\.[0-9]*$/.0/' | sort | uniq -c | sort -rn | head -10 \
        | awk '{print $2}' | while read -r net; do
            ip route add blackhole "${net}/24" 2>/dev/null || true
            echo "[$(date -Iseconds)] L5: NULL-ROUTE ${net}/24" >> "$LOG"
          done
      ;;
  esac
}

deescalate() {
  if [ "$LEVEL" -le 0 ]; then return; fi
  OLD_LEVEL=$LEVEL
  LEVEL=$(( LEVEL - 1 ))
  echo "$LEVEL" > "$STATE_FILE"
  echo "$NOW" > "$LEVEL_TIME_FILE"
  echo "[$(date -Iseconds)] DE-ESCALATE from LEVEL $OLD_LEVEL to LEVEL $LEVEL (conn=$TOTAL_CONN syn=$TOTAL_SYN)" >> "$LOG"

  case $OLD_LEVEL in
    1) rm -f /tmp/ddos_challenge_active; nginx -t && systemctl reload nginx 2>/dev/null || true ;;
    4) /usr/local/bin/cf-under-attack.sh disable 2>/dev/null || true ;;
    5) ip route show | grep blackhole | awk '{print $3}' | while read -r net; do
         ip route del blackhole "$net" 2>/dev/null || true
       done ;;
  esac
}

# --- Decision ---
if should_escalate; then
  escalate
elif should_deescalate; then
  deescalate
fi

echo "LEVEL=$LEVEL CONN=$TOTAL_CONN SYN=$TOTAL_SYN TOP_IP=$TOP_IP_CONN"
```

### Run the Escalation Engine

```bash
chmod +x /usr/local/bin/ddos-escalation-engine.sh

# Run as a systemd service
cat > /etc/systemd/system/ddos-escalation.service <<'EOF'
[Unit]
Description=DDoS Shield Auto-Escalation Engine
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do /usr/local/bin/ddos-escalation-engine.sh; sleep 30; done'
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now ddos-escalation
```

### Manual Escalation Override

```bash
# Force a specific level
echo 4 > /var/run/ddos-shield-level
date +%s > /var/run/ddos-shield-level-time

# Reset to normal
echo 0 > /var/run/ddos-shield-level
rm -f /tmp/ddos_challenge_active
/usr/local/bin/cf-under-attack.sh disable 2>/dev/null || true
```

---

## 20. Real-Time Terminal Dashboard

### DDoS Shield Live Dashboard

```bash
#!/usr/bin/env bash
# /usr/local/bin/ddos-dashboard.sh
# Usage: ddos-dashboard.sh [interface]
# Or:    watch -n 1 /usr/local/bin/ddos-dashboard.sh

IFACE="${1:-eth0}"
STATE_FILE=/var/run/ddos-shield-level

clear_line() { printf "\033[2K"; }

# --- Gather Metrics ---
LEVEL=$(cat "$STATE_FILE" 2>/dev/null || echo 0)
TOTAL_CONN=$(ss -tan state established 2>/dev/null | tail -n +2 | wc -l)
TOTAL_SYN=$(ss -tan state syn-recv 2>/dev/null | wc -l)
UNIQUE_IPS=$(ss -tan state established 2>/dev/null | awk 'NR>1 {print $4}' | cut -d: -f1 | sort -u | wc -l)
BLOCKED_IPS=$(ipset list ddos_blacklist 2>/dev/null | grep -c '^[0-9]' || echo 0)
CONNTRACK_COUNT=$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo "N/A")
CONNTRACK_MAX=$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || echo "N/A")

# Bandwidth (bytes/sec from /proc/net/dev)
read RX_BEFORE TX_BEFORE < <(awk -v iface="$IFACE:" '$1==iface {print $2, $10}' /proc/net/dev 2>/dev/null || echo "0 0")
sleep 1
read RX_AFTER TX_AFTER < <(awk -v iface="$IFACE:" '$1==iface {print $2, $10}' /proc/net/dev 2>/dev/null || echo "0 0")
RX_RATE=$(( (RX_AFTER - RX_BEFORE) / 1024 ))
TX_RATE=$(( (TX_AFTER - TX_BEFORE) / 1024 ))

# Level labels
LEVEL_LABELS=("NORMAL" "ALERT" "HARD-LIMITS" "GEO-BLOCK" "UNDER-ATTACK" "NULL-ROUTE")
LEVEL_COLORS=("\033[32m" "\033[33m" "\033[33m" "\033[31m" "\033[31m" "\033[35m")
LEVEL_LABEL="${LEVEL_LABELS[$LEVEL]:-UNKNOWN}"
LEVEL_COLOR="${LEVEL_COLORS[$LEVEL]:-\033[0m}"

# Top attackers
TOP_ATTACKERS=$(ss -tan state established 2>/dev/null \
  | awk 'NR>1 {print $4}' | cut -d: -f1 \
  | sort | uniq -c | sort -rn | head -5)

# Recent blocks
RECENT_BLOCKS=$(tail -5 /var/log/ddos-shield.log 2>/dev/null | tac)

# --- Render ---
echo ""
echo -e "  \033[1;36m========================================\033[0m"
echo -e "  \033[1;36m     DDoS Shield — Live Dashboard       \033[0m"
echo -e "  \033[1;36m========================================\033[0m"
echo ""
echo -e "  Escalation Level:  ${LEVEL_COLOR}\033[1m[$LEVEL] $LEVEL_LABEL\033[0m"
echo -e "  Interface:         $IFACE"
echo -e "  Time:              $(date '+%Y-%m-%d %H:%M:%S')"
echo ""
echo -e "  \033[1m--- Traffic ---\033[0m"
echo -e "  Connections:       $TOTAL_CONN established"
echo -e "  SYN Queue:         $TOTAL_SYN (half-open)"
echo -e "  Unique IPs:        $UNIQUE_IPS"
echo -e "  Bandwidth IN:      ${RX_RATE} KB/s"
echo -e "  Bandwidth OUT:     ${TX_RATE} KB/s"
echo -e "  Conntrack:         $CONNTRACK_COUNT / $CONNTRACK_MAX"
echo ""
echo -e "  \033[1m--- Defense ---\033[0m"
echo -e "  Blocked IPs:       $BLOCKED_IPS (in ipset)"
echo ""
echo -e "  \033[1m--- Top 5 Talkers ---\033[0m"
echo "$TOP_ATTACKERS" | while read -r count ip; do
  [ -z "$ip" ] && continue
  if [ "${count:-0}" -ge 50 ]; then
    echo -e "    \033[31m$count\033[0m  $ip"
  elif [ "${count:-0}" -ge 20 ]; then
    echo -e "    \033[33m$count\033[0m  $ip"
  else
    echo -e "    \033[32m$count\033[0m  $ip"
  fi
done
echo ""
echo -e "  \033[1m--- Recent Blocks ---\033[0m"
echo "$RECENT_BLOCKS" | head -5 | while read -r line; do
  echo -e "    $line"
done
echo ""
echo -e "  \033[2mRefresh: watch -n 1 /usr/local/bin/ddos-dashboard.sh\033[0m"
```

### Run the Dashboard

```bash
chmod +x /usr/local/bin/ddos-dashboard.sh

# Live auto-refresh every second
watch -n 1 -c /usr/local/bin/ddos-dashboard.sh eth0

# Or just run once
/usr/local/bin/ddos-dashboard.sh eth0
```

---

## 21. Post-Attack Forensics

### Generate Post-Attack Report

Run this after an attack subsides to generate a full forensic report.

```bash
#!/usr/bin/env bash
# /usr/local/bin/ddos-post-attack-report.sh
set -euo pipefail

REPORT_DIR="/var/log/ddos-shield/reports"
mkdir -p "$REPORT_DIR"
REPORT="$REPORT_DIR/attack-report-$(date +%F-%H%M%S).txt"
LOG=/var/log/ddos-shield.log
L7_LOG=/var/log/ddos-shield-l7.log
WS_LOG=/var/log/ddos-shield-ws.log
BOT_LOG=/var/log/ddos-shield-bots.log

{
echo "============================================================"
echo "  DDoS Shield — Post-Attack Forensic Report"
echo "  Generated: $(date -Iseconds)"
echo "  Hostname:  $(hostname)"
echo "============================================================"
echo ""

# --- Attack Timeline ---
echo "=== ATTACK TIMELINE ==="
FIRST_BLOCK=$(head -1 "$LOG" 2>/dev/null | grep -oP '\[.*?\]' | head -1 || echo "N/A")
LAST_BLOCK=$(tail -1 "$LOG" 2>/dev/null | grep -oP '\[.*?\]' | head -1 || echo "N/A")
TOTAL_BLOCKS=$(grep -c "BLOCK\|ESCALATE" "$LOG" 2>/dev/null || echo 0)
echo "  First block event:  $FIRST_BLOCK"
echo "  Last block event:   $LAST_BLOCK"
echo "  Total block events: $TOTAL_BLOCKS"
echo ""

# --- Escalation History ---
echo "=== ESCALATION HISTORY ==="
grep -i "ESCALATE\|DE-ESCALATE" "$LOG" 2>/dev/null | tail -20 || echo "  No escalation events found."
echo ""

# --- Peak Metrics ---
echo "=== PEAK TRAFFIC METRICS ==="
echo "  Current connections: $(ss -tan state established | wc -l)"
echo "  Current SYN queue:   $(ss -tan state syn-recv | wc -l)"
echo "  Current unique IPs:  $(ss -tan state established | awk 'NR>1 {print $4}' | cut -d: -f1 | sort -u | wc -l)"
echo "  Conntrack usage:     $(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo N/A) / $(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || echo N/A)"
echo ""

# --- Attack Vectors Detected ---
echo "=== ATTACK VECTORS ==="
echo "  Layer 4 (SYN/Connection floods):"
grep -c "BLOCK.*count=" "$LOG" 2>/dev/null | xargs -I{} echo "    {} connection flood blocks"
echo "  Layer 7 (HTTP floods):"
grep -c "L7-FLOOD" "$L7_LOG" 2>/dev/null | xargs -I{} echo "    {} HTTP flood blocks" || echo "    0 HTTP flood blocks"
echo "  WebSocket floods:"
grep -c "WS-FLOOD\|WS-MSG-FLOOD" "$WS_LOG" 2>/dev/null | xargs -I{} echo "    {} WebSocket flood blocks" || echo "    0 WebSocket flood blocks"
echo "  Bot/Headless:"
grep -c "HEADLESS-BOT\|RESI-PROXY\|JA3-ANOMALY" "$BOT_LOG" 2>/dev/null | xargs -I{} echo "    {} bot detections" || echo "    0 bot detections"
echo ""

# --- Top Blocked IPs ---
echo "=== TOP 20 BLOCKED IPs ==="
grep "BLOCK" "$LOG" 2>/dev/null \
  | grep -oP 'BLOCK \K[0-9.]+' \
  | sort | uniq -c | sort -rn | head -20 \
  | while read -r count ip; do
      COUNTRY=$(geoiplookup "$ip" 2>/dev/null | head -1 | awk -F': ' '{print $2}' || echo "Unknown")
      printf "  %-6s %-18s %s\n" "$count" "$ip" "$COUNTRY"
    done
echo ""

# --- Top Attacking Countries ---
echo "=== TOP ATTACKING COUNTRIES ==="
grep "BLOCK" "$LOG" 2>/dev/null \
  | grep -oP 'BLOCK \K[0-9.]+' \
  | sort -u \
  | while read -r ip; do
      geoiplookup "$ip" 2>/dev/null | head -1 | awk -F': ' '{print $2}' | cut -c1-2
    done | sort | uniq -c | sort -rn | head -10 || echo "  GeoIP data unavailable."
echo ""

# --- Currently Blocked (ipset) ---
echo "=== CURRENTLY BLOCKED IN IPSET ==="
BLOCKED_COUNT=$(ipset list ddos_blacklist 2>/dev/null | grep -c '^[0-9]' || echo 0)
echo "  Active blocks: $BLOCKED_COUNT IPs"
ipset list ddos_blacklist 2>/dev/null | grep '^[0-9]' | head -20 || echo "  (empty)"
echo ""

# --- Mitigation Effectiveness ---
echo "=== MITIGATION EFFECTIVENESS ==="
echo "  iptables packet drops:"
iptables -L INPUT -nv 2>/dev/null | awk '$1 > 0 && /DROP|REJECT/ {printf "    %-12s packets dropped by rule: %s\n", $1, $0}' | head -10
echo ""
echo "  fail2ban status:"
fail2ban-client status 2>/dev/null | grep -E "Jail list|Currently banned" || echo "    fail2ban not running"
echo ""

# --- Cloudflare Status ---
echo "=== CLOUDFLARE STATUS ==="
if [ -f /etc/ddos-shield/cloudflare.env ]; then
  source /etc/ddos-shield/cloudflare.env
  CF_LEVEL=$(curl -sS "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/settings/security_level" \
    -H "Authorization: Bearer $CF_API_TOKEN" 2>/dev/null | jq -r '.result.value' 2>/dev/null || echo "N/A")
  echo "  Security Level: $CF_LEVEL"
else
  echo "  Cloudflare not configured."
fi
echo ""

# --- Recommendations ---
echo "=== RECOMMENDATIONS ==="
if [ "$BLOCKED_COUNT" -gt 500 ]; then
  echo "  [!] High block count ($BLOCKED_COUNT). Consider upstream null routing or CDN-level mitigation."
fi
if [ "$(ss -tan state syn-recv | wc -l)" -gt 100 ]; then
  echo "  [!] SYN queue still elevated. Verify syncookies are active: sysctl net.ipv4.tcp_syncookies"
fi
echo "  [i] Review /var/log/ddos-shield.log for full event history."
echo "  [i] Export blocked IPs: ipset list ddos_blacklist | grep '^[0-9]' > blocked-ips.txt"
echo "  [i] Consider adding persistent blocks for repeat offenders."
echo ""
echo "============================================================"
echo "  Report saved to: $REPORT"
echo "============================================================"
} | tee "$REPORT"

echo "[$(date -Iseconds)] POST-ATTACK report generated: $REPORT" >> "$LOG"
```

### Run Post-Attack Report

```bash
chmod +x /usr/local/bin/ddos-post-attack-report.sh
/usr/local/bin/ddos-post-attack-report.sh
```

### Export Blocked IPs for Sharing / Threat Intel

```bash
# Export all blocked IPs with country info
ipset list ddos_blacklist | grep '^[0-9]' | awk '{print $1}' \
  | while read -r ip; do
      country=$(geoiplookup "$ip" 2>/dev/null | head -1 | awk -F': ' '{print $2}')
      echo "$ip,$country"
    done > /var/log/ddos-shield/reports/blocked-ips-$(date +%F).csv
```

### Auto-Generate Report When De-Escalating to Level 0

Add this to the escalation engine's deescalate function:

```bash
# In ddos-escalation-engine.sh, inside the deescalate function:
if [ "$LEVEL" -eq 0 ]; then
  /usr/local/bin/ddos-post-attack-report.sh &
fi
```
