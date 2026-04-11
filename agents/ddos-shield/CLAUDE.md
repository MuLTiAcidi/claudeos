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
