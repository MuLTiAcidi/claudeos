# Defense Monitor Agent

Real-time security monitoring agent that watches all attack vectors simultaneously. Combines log analysis, network monitoring, authentication monitoring, and anomaly detection into a single unified defense dashboard. The eyes of the pack.

---

## Safety Rules

- NEVER block IPs automatically without at least 3 confirmed malicious events.
- ALWAYS whitelist management IPs before enabling any blocking.
- NEVER modify firewall rules without logging the change.
- ALWAYS keep a rollback state before applying defensive measures.
- Log all detections to `/var/log/claudeos/defense-monitor.log`.

---

## 1. Unified Threat Dashboard

### Launch Real-Time Dashboard
```bash
#!/bin/bash
# ClaudeOS Defense Monitor — Real-Time Dashboard
watch -n 2 '
echo "╔══════════════════════════════════════════════════════╗"
echo "║          ClaudeOS Defense Monitor v2.0               ║"
echo "║          $(date "+%Y-%m-%d %H:%M:%S")                ║"
echo "╠══════════════════════════════════════════════════════╣"

# Connection stats
ESTABLISHED=$(ss -tan state established | wc -l)
SYN_RECV=$(ss -tan state syn-recv | wc -l)
TIME_WAIT=$(ss -tan state time-wait | wc -l)
TOTAL=$(ss -tan | wc -l)
echo "║ CONNECTIONS: $ESTABLISHED est | $SYN_RECV syn | $TIME_WAIT tw | $TOTAL total"

# Top 5 connecting IPs
echo "║ TOP IPs:"
ss -tan state established | awk "NR>1 {print \$4}" | cut -d: -f1 | sort | uniq -c | sort -rn | head -5 | while read count ip; do
    echo "║   $count connections ← $ip"
done

# Failed SSH attempts (last 5 min)
SSH_FAILS=$(journalctl -u sshd --since "5 min ago" 2>/dev/null | grep -c "Failed password" || echo 0)
echo "║ SSH FAILS (5min): $SSH_FAILS"

# Blocked by iptables (last 5 min)
BLOCKED=$(dmesg --time-format iso 2>/dev/null | tail -100 | grep -c "DPT=" || echo 0)
echo "║ FIREWALL BLOCKS: ~$BLOCKED"

# Disk and Memory
DISK=$(df -h / | awk "NR==2 {print \$5}")
MEM=$(free -h | awk "/Mem:/ {print \$3\"/\"\$2}")
LOAD=$(uptime | awk -F"load average:" "{print \$2}" | xargs)
echo "║ RESOURCES: Disk $DISK | RAM $MEM | Load $LOAD"

# Fail2ban status
if command -v fail2ban-client &>/dev/null; then
    BANNED=$(fail2ban-client status 2>/dev/null | grep "Total banned" | awk "{print \$NF}" || echo "N/A")
    echo "║ FAIL2BAN: $BANNED total banned"
fi

echo "╚══════════════════════════════════════════════════════╝"
'
```

---

## 2. Authentication Attack Detection

### Monitor Failed Logins (All Services)
```bash
# Real-time failed login monitor
tail -f /var/log/auth.log 2>/dev/null | while read line; do
    if echo "$line" | grep -qiE "failed|invalid|error|denied"; then
        IP=$(echo "$line" | grep -oP '\d+\.\d+\.\d+\.\d+' | head -1)
        SERVICE=$(echo "$line" | awk '{print $5}' | cut -d'[' -f1)
        echo "[$(date '+%H:%M:%S')] ALERT: $SERVICE auth failure from $IP"
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] AUTH_FAIL service=$SERVICE ip=$IP line=$line" >> /var/log/claudeos/defense-monitor.log
    fi
done
```

### Brute Force Detection
```bash
# Count failed attempts per IP in last 10 minutes
journalctl --since "10 min ago" 2>/dev/null | grep -i "failed\|invalid" | \
    grep -oP '\d+\.\d+\.\d+\.\d+' | sort | uniq -c | sort -rn | \
    awk '$1 > 5 {print "BRUTE FORCE DETECTED: " $1 " attempts from " $2}'
```

---

## 3. Network Anomaly Detection

### Detect Port Scans
```bash
# Quick port scan detection via connection patterns
ss -tan | awk '{print $4}' | grep -oP ':\K\d+$' | sort -n | uniq -c | sort -rn | head -10 | \
    awk '$1 > 20 {print "PORT SCAN? " $1 " connections to port " $2}'
```

### Detect Unusual Outbound Connections
```bash
# Check for unexpected outbound connections (data exfiltration, reverse shells)
ss -tan state established | awk '{print $4}' | grep -v "127.0.0.1\|::1" | \
    cut -d: -f1 | sort -u | while read ip; do
    # Check if IP is in known-good list
    if ! grep -q "$ip" /etc/claudeos/known-good-ips.txt 2>/dev/null; then
        echo "UNKNOWN OUTBOUND: $ip"
        # Reverse DNS
        host "$ip" 2>/dev/null | head -1
    fi
done
```

### Bandwidth Spike Detection
```bash
# Monitor interface bandwidth
IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
RX1=$(cat /sys/class/net/$IFACE/statistics/rx_bytes)
TX1=$(cat /sys/class/net/$IFACE/statistics/tx_bytes)
sleep 5
RX2=$(cat /sys/class/net/$IFACE/statistics/rx_bytes)
TX2=$(cat /sys/class/net/$IFACE/statistics/tx_bytes)
RX_RATE=$(( ($RX2 - $RX1) / 5 / 1024 ))
TX_RATE=$(( ($TX2 - $TX1) / 5 / 1024 ))
echo "Bandwidth: RX ${RX_RATE} KB/s | TX ${TX_RATE} KB/s"
if [ $RX_RATE -gt 10240 ]; then
    echo "WARNING: High inbound traffic (${RX_RATE} KB/s > 10 MB/s)"
fi
```

---

## 4. Web Application Attack Detection

### Monitor Nginx/Apache for Attacks
```bash
# Real-time web attack monitor
tail -f /var/log/nginx/access.log 2>/dev/null | while read line; do
    # Detect SQLi attempts
    if echo "$line" | grep -qiE "union.*select|or.*1=1|drop.*table|sleep\(|benchmark\("; then
        echo "[SQLI] $line"
    fi
    # Detect XSS attempts
    if echo "$line" | grep -qiE "<script|onerror=|onload=|javascript:|alert\("; then
        echo "[XSS] $line"
    fi
    # Detect path traversal
    if echo "$line" | grep -qiE "\.\./|\.\.\\\\|/etc/passwd|/proc/self"; then
        echo "[TRAVERSAL] $line"
    fi
    # Detect scanner signatures
    if echo "$line" | grep -qiE "nikto|sqlmap|nmap|dirbuster|gobuster|ffuf|nuclei|burp"; then
        echo "[SCANNER] $line"
    fi
    # Detect high request rate from single IP
done
```

### Request Rate Monitor
```bash
# Count requests per IP in last minute
awk -v now="$(date -d '1 minute ago' '+%d/%b/%Y:%H:%M')" \
    '$4 >= "["now' /var/log/nginx/access.log 2>/dev/null | \
    awk '{print $1}' | sort | uniq -c | sort -rn | \
    awk '$1 > 100 {print "HIGH RATE: " $1 " req/min from " $2}'
```

---

## 5. File Integrity Monitoring

### Watch Critical Files
```bash
# Monitor critical config files for changes
WATCH_FILES="/etc/passwd /etc/shadow /etc/sudoers /etc/ssh/sshd_config /etc/nginx/nginx.conf"
for file in $WATCH_FILES; do
    if [ -f "$file" ]; then
        HASH=$(md5sum "$file" | awk '{print $1}')
        STORED=$(cat "/var/lib/claudeos/hashes/$(echo $file | tr '/' '_')" 2>/dev/null)
        if [ -n "$STORED" ] && [ "$HASH" != "$STORED" ]; then
            echo "FILE MODIFIED: $file (hash changed)"
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] FILE_CHANGE file=$file old=$STORED new=$HASH" >> /var/log/claudeos/defense-monitor.log
        fi
        echo "$HASH" > "/var/lib/claudeos/hashes/$(echo $file | tr '/' '_')"
    fi
done
```

### Watch for New SUID Files
```bash
# Detect new SUID/SGID binaries (potential privilege escalation)
find / -perm -4000 -o -perm -2000 2>/dev/null | sort > /tmp/suid_current.txt
if [ -f /var/lib/claudeos/suid_baseline.txt ]; then
    diff /var/lib/claudeos/suid_baseline.txt /tmp/suid_current.txt | grep "^>" | while read line; do
        echo "NEW SUID BINARY: $line"
    done
fi
cp /tmp/suid_current.txt /var/lib/claudeos/suid_baseline.txt
```

---

## 6. Process Anomaly Detection

### Detect Suspicious Processes
```bash
# Check for common attack tools running
SUSPICIOUS="nc ncat netcat socat msfconsole msfvenom hydra john hashcat mimikatz"
for proc in $SUSPICIOUS; do
    PID=$(pgrep -x "$proc" 2>/dev/null)
    if [ -n "$PID" ]; then
        echo "SUSPICIOUS PROCESS: $proc (PID $PID)"
        ps -p $PID -o user,pid,ppid,cmd
    fi
done

# Check for processes running as root that shouldn't be
ps aux | awk '$1 == "root" && $11 !~ /^\[/' | grep -vE "sshd|nginx|mysql|systemd|init|cron|fail2ban" | \
    awk '{print "ROOT PROCESS: " $11 " (PID " $2 ")"}'
```

### Detect Reverse Shells
```bash
# Check for common reverse shell patterns
ss -tan state established | while read line; do
    LOCAL_PORT=$(echo "$line" | awk '{print $3}' | rev | cut -d: -f1 | rev)
    REMOTE=$(echo "$line" | awk '{print $4}')
    PID=$(ss -tanp state established | grep "$REMOTE" | grep -oP 'pid=\K\d+' | head -1)
    if [ -n "$PID" ]; then
        CMD=$(ps -p $PID -o cmd= 2>/dev/null)
        if echo "$CMD" | grep -qiE "bash -i|/bin/sh|python.*pty|nc -e|perl.*socket"; then
            echo "REVERSE SHELL DETECTED: PID $PID → $REMOTE (cmd: $CMD)"
        fi
    fi
done
```

---

## 7. Automated Response

### Auto-Block Attackers
```bash
# Block IPs with > 10 failed SSH attempts in last 5 minutes
journalctl -u sshd --since "5 min ago" 2>/dev/null | grep "Failed password" | \
    grep -oP 'from \K[\d.]+' | sort | uniq -c | sort -rn | \
    awk '$1 > 10 {print $2}' | while read ip; do
    # Check if already blocked
    if ! iptables -L INPUT -n | grep -q "$ip"; then
        echo "AUTO-BLOCKING: $ip (SSH brute force)"
        iptables -I INPUT -s "$ip" -j DROP
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] AUTO_BLOCK ip=$ip reason=ssh_bruteforce" >> /var/log/claudeos/defense-monitor.log
    fi
done
```

### Emergency Lockdown
```bash
# Emergency lockdown — only allow SSH from management IP
MANAGEMENT_IP="YOUR_IP_HERE"
echo "EMERGENCY LOCKDOWN ACTIVATED"
iptables-save > /var/lib/claudeos/pre-lockdown-rules.bak
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -A INPUT -s $MANAGEMENT_IP -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
echo "Only $MANAGEMENT_IP can connect. Restore: iptables-restore < /var/lib/claudeos/pre-lockdown-rules.bak"
```

---

## 8. Daily Security Report

### Generate Report
```bash
cat > /tmp/daily-security-report.txt << REPORT
=== ClaudeOS Daily Security Report ===
Date: $(date '+%Y-%m-%d %H:%M:%S')
Host: $(hostname)

AUTHENTICATION
  Failed SSH (24h): $(journalctl -u sshd --since "24 hours ago" 2>/dev/null | grep -c "Failed password")
  Unique attacking IPs: $(journalctl -u sshd --since "24 hours ago" 2>/dev/null | grep "Failed password" | grep -oP 'from \K[\d.]+' | sort -u | wc -l)

FIREWALL
  Total rules: $(iptables -L INPUT -n | wc -l)
  Blocked IPs: $(iptables -L INPUT -n | grep -c DROP)
  Fail2ban banned: $(fail2ban-client status 2>/dev/null | grep -oP 'Total banned:\s+\K\d+' || echo N/A)

NETWORK
  Established connections: $(ss -tan state established | wc -l)
  Listening ports: $(ss -tln | wc -l)

FILESYSTEM
  Disk usage: $(df -h / | awk 'NR==2 {print $5}')
  Modified config files: $(find /etc -mtime -1 -type f 2>/dev/null | wc -l)
  New SUID files: $(diff /var/lib/claudeos/suid_baseline.txt <(find / -perm -4000 2>/dev/null | sort) 2>/dev/null | grep -c "^>")

PROCESSES
  Total: $(ps aux | wc -l)
  Root processes: $(ps aux | awk '$1 == "root"' | wc -l)
  Zombie: $(ps aux | awk '$8 ~ /Z/' | wc -l)

UPDATES
  Available: $(apt list --upgradable 2>/dev/null | grep -c "upgradable" || echo N/A)
  Security: $(apt list --upgradable 2>/dev/null | grep -c "security" || echo N/A)
REPORT

cat /tmp/daily-security-report.txt
```

---

## Quick Reference

| Check | Command |
|-------|---------|
| Live connections | `ss -tan state established \| wc -l` |
| Top connecting IPs | `ss -tan \| awk '{print $4}' \| cut -d: -f1 \| sort \| uniq -c \| sort -rn \| head` |
| Failed SSH (last hour) | `journalctl -u sshd --since "1 hour ago" \| grep -c "Failed"` |
| Blocked by firewall | `iptables -L INPUT -n -v \| grep DROP` |
| Listening ports | `ss -tln` |
| Bandwidth | `nload` or `iftop` |
| Suspicious processes | `ps aux \| grep -iE "nc\|ncat\|socat\|msfconsole"` |
| Recent file changes | `find /etc -mtime -1 -type f` |
| System load | `uptime && free -h && df -h` |
| Full dashboard | Run Section 1 dashboard script |
