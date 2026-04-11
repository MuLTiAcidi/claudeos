# Bandwidth Monitor Agent

## Role
Monitor real-time and historical network traffic on Ubuntu/Debian, identify bandwidth-hungry processes and hosts, throttle traffic per interface or per port using `tc` and `wondershaper`, and emit alerts when usage crosses configured thresholds.

---

## Capabilities

### Real-Time Monitoring
- Per-interface throughput with `iftop`, `bmon`, `nload`
- Per-process traffic accounting with `nethogs`
- Per-connection visibility with `ss`, `nettop`
- TCP retransmits and errors via `nstat`/`netstat -s`

### Historical Tracking
- `vnstat` daily/monthly database per interface
- `iptables` byte counters for ad-hoc accounting
- Promtail/journalctl integration for long-term storage

### Throttling / QoS
- Linux Traffic Control (`tc`) with HTB and TBF qdiscs
- `wondershaper` quick caps
- Per-port and per-IP shaping with `tc filter`
- Egress + ingress (via IFB) shaping

### Alerts
- Threshold-based bash watcher with notification dispatch
- vnstat monthly cap warnings

---

## Safety Rules

1. **NEVER** apply `tc` rules to a remote SSH interface without a safety rollback (`at now+5min` to flush)
2. **ALWAYS** confirm the active interface name (`ip -br link`) — `eth0` is not universal
3. **NEVER** run `wondershaper clear` blindly — it removes all qdiscs on the interface
4. **ALWAYS** use `tc qdisc show dev IFACE` before mutating to record current state
5. **NEVER** start `iftop`/`nethogs` in a tight loop — they need a TTY and consume CPU
6. **ALWAYS** size vnstat database directory on persistent storage (`/var/lib/vnstat`)
7. **NEVER** silently drop traffic — log policed packets for forensics
8. **ALWAYS** test ingress shaping with IFB on a lab interface first
9. **NEVER** alert flood — debounce notifications (cooldown >= 5 minutes)
10. **ALWAYS** snapshot baseline traffic before applying throttles

---

## Installation

```bash
sudo apt update
sudo apt install -y iftop nethogs vnstat bmon nload iproute2 wondershaper ifstat sysstat tcpdump

# Enable vnstat database collector
sudo systemctl enable --now vnstat
```

---

## Real-Time Tools

### iftop — Live per-host throughput
```bash
# All interfaces with port info, no DNS resolution
sudo iftop -i eth0 -P -n

# Filter to a single host
sudo iftop -i eth0 -f "host 1.2.3.4"

# Text mode for one snapshot (good for scripting)
sudo iftop -i eth0 -t -s 5 -L 20 2>/dev/null
```

### nethogs — Per-process bandwidth
```bash
sudo nethogs eth0
sudo nethogs -d 2 eth0          # 2-second refresh
sudo nethogs -t eth0             # trace mode (machine-readable)
sudo nethogs -v 3 eth0           # 0=KB/s 1=total KB 2=total B 3=total MB
```

### bmon — Multi-interface dashboard
```bash
sudo bmon -p eth0,wg0,docker0
sudo bmon -o ascii:fgchar=":"    # ascii output
```

### nload — Two-pane in/out graph
```bash
nload eth0
nload -m                          # multi-interface
```

### ss / ip — Connection accounting
```bash
# Top sockets by bytes (kernel-side counters)
ss -tin | head -50

# Bytes per interface (snapshot)
ip -s link show eth0

# Two snapshots → bps
R1=$(cat /sys/class/net/eth0/statistics/rx_bytes); sleep 1; R2=$(cat /sys/class/net/eth0/statistics/rx_bytes); echo "$(((R2-R1)*8)) bps in"
```

### sar (sysstat)
```bash
# Live network usage every 2s, 5 samples
sar -n DEV 2 5

# Historical (after sar collector enabled)
sudo sed -i 's/false/true/' /etc/default/sysstat
sudo systemctl enable --now sysstat
sar -n DEV -f /var/log/sysstat/sa$(date +%d)
```

---

## Historical — vnstat

```bash
# Add interface to vnstat DB
sudo vnstat -u -i eth0
sudo systemctl restart vnstat

# Hourly / daily / monthly summaries
vnstat -i eth0
vnstat -i eth0 -h
vnstat -i eth0 -d
vnstat -i eth0 -m
vnstat -i eth0 -y

# Top 10 days
vnstat -i eth0 --top 10

# Live mode
vnstat -i eth0 -l

# JSON for scripting
vnstat -i eth0 --json | jq '.interfaces[0].traffic.month[-1]'
```

### Monthly cap warning
```bash
# Warn when >80% of 1 TB plan used in current month
USED=$(vnstat -i eth0 --json | jq '.interfaces[0].traffic.month[-1].rx + .interfaces[0].traffic.month[-1].tx')
CAP=$((1024*1024*1024*1024))   # 1 TiB in bytes
PCT=$((USED*100/CAP))
echo "Used ${PCT}% of monthly cap"
[ "$PCT" -ge 80 ] && echo "ALERT: bandwidth usage >= 80%"
```

---

## Throttling with tc

### Show current qdiscs
```bash
tc qdisc show dev eth0
tc class show dev eth0
tc filter show dev eth0
```

### Cap an entire interface (TBF)
```bash
# 50 Mbit/s outbound cap, 32 KB burst, 400 ms latency tolerance
sudo tc qdisc add dev eth0 root tbf rate 50mbit burst 32kbit latency 400ms

# Remove
sudo tc qdisc del dev eth0 root
```

### HTB hierarchical shaping per class
```bash
IFACE=eth0
sudo tc qdisc del dev $IFACE root 2>/dev/null

# Root htb
sudo tc qdisc add dev $IFACE root handle 1: htb default 30

# Total ceiling 100 Mbit
sudo tc class add dev $IFACE parent 1: classid 1:1 htb rate 100mbit ceil 100mbit

# Class 10: SSH/critical — guaranteed 20 Mbit, can burst to 100
sudo tc class add dev $IFACE parent 1:1 classid 1:10 htb rate 20mbit ceil 100mbit prio 1

# Class 20: HTTP/HTTPS — 60 Mbit
sudo tc class add dev $IFACE parent 1:1 classid 1:20 htb rate 60mbit ceil 80mbit prio 2

# Class 30: default/bulk — 20 Mbit
sudo tc class add dev $IFACE parent 1:1 classid 1:30 htb rate 20mbit ceil 30mbit prio 3

# Add fair queue under each leaf
sudo tc qdisc add dev $IFACE parent 1:10 handle 10: sfq perturb 10
sudo tc qdisc add dev $IFACE parent 1:20 handle 20: sfq perturb 10
sudo tc qdisc add dev $IFACE parent 1:30 handle 30: sfq perturb 10

# Filters by destination port
sudo tc filter add dev $IFACE protocol ip parent 1: prio 1 u32 match ip dport 22 0xffff flowid 1:10
sudo tc filter add dev $IFACE protocol ip parent 1: prio 2 u32 match ip dport 80 0xffff flowid 1:20
sudo tc filter add dev $IFACE protocol ip parent 1: prio 2 u32 match ip dport 443 0xffff flowid 1:20
```

### Filter by source IP
```bash
sudo tc filter add dev eth0 protocol ip parent 1: prio 3 \
    u32 match ip src 10.0.0.50/32 flowid 1:30
```

### Ingress shaping via IFB
```bash
sudo modprobe ifb numifbs=1
sudo ip link set dev ifb0 up

# Redirect ingress of eth0 → ifb0
sudo tc qdisc add dev eth0 handle ffff: ingress
sudo tc filter add dev eth0 parent ffff: protocol ip u32 match u32 0 0 \
    action mirred egress redirect dev ifb0

# Now shape ifb0 like a normal egress interface
sudo tc qdisc add dev ifb0 root tbf rate 30mbit burst 32kbit latency 400ms
```

### Safety net — auto-flush after 5 minutes
```bash
echo "tc qdisc del dev eth0 root; tc qdisc del dev eth0 ingress" | sudo at now + 5 minutes
```

---

## wondershaper (quick caps)

```bash
# Limit eth0 to 10 Mbit down / 2 Mbit up (kbit)
sudo wondershaper eth0 10240 2048

# Show current
sudo wondershaper eth0

# Clear
sudo wondershaper clear eth0
```

---

## Per-Process Throttling (cgroups + tc)
```bash
# Mark packets from a cgroup
sudo mkdir -p /sys/fs/cgroup/net_cls/throttled
echo 0x10001 | sudo tee /sys/fs/cgroup/net_cls/throttled/net_cls.classid

# Tag iptables → tc class 1:30
sudo iptables -t mangle -A POSTROUTING -m cgroup --cgroup 0x10001 -j CLASSIFY --set-class 1:30

# Run a process inside the cgroup
sudo cgexec -g net_cls:throttled curl -O https://example.com/large.iso
```

---

## Alerting Watcher

```bash
sudo tee /usr/local/bin/bw-watch.sh >/dev/null <<'EOF'
#!/usr/bin/env bash
# Alert if eth0 sustained bandwidth > THRESHOLD_MBPS for 60s
IFACE=${1:-eth0}
THRESHOLD_MBPS=${2:-800}
COOLDOWN=${COOLDOWN:-300}
STATE=/tmp/.bwwatch_$IFACE

R1=$(cat /sys/class/net/$IFACE/statistics/rx_bytes)
T1=$(cat /sys/class/net/$IFACE/statistics/tx_bytes)
sleep 1
R2=$(cat /sys/class/net/$IFACE/statistics/rx_bytes)
T2=$(cat /sys/class/net/$IFACE/statistics/tx_bytes)

RX_MBPS=$(( (R2-R1)*8/1000000 ))
TX_MBPS=$(( (T2-T1)*8/1000000 ))
TOT=$((RX_MBPS+TX_MBPS))

NOW=$(date +%s)
LAST=$(cat $STATE 2>/dev/null || echo 0)

if [ "$TOT" -ge "$THRESHOLD_MBPS" ] && [ $((NOW-LAST)) -ge "$COOLDOWN" ]; then
    echo "$(date) ALERT: $IFACE total ${TOT} Mbps (rx ${RX_MBPS} tx ${TX_MBPS})"
    # hand off to notifications agent (or curl webhook here)
    logger -t bw-watch "ALERT $IFACE ${TOT}Mbps"
    echo "$NOW" > $STATE
fi
EOF
sudo chmod +x /usr/local/bin/bw-watch.sh

# Run every minute
( sudo crontab -l 2>/dev/null; echo "* * * * * /usr/local/bin/bw-watch.sh eth0 800" ) | sudo crontab -
```

---

## TCP Health Snapshot
```bash
# Retransmits, drops, errors (cumulative)
nstat -az Tcp* | grep -E 'Retrans|Lost|Drop'

# Per-interface drops/errors
ip -s link show eth0

# Active connection state breakdown
ss -s
```

---

## Workflows

### Find What's Eating Bandwidth Right Now
1. `sudo iftop -i eth0 -P -n` — top hosts/ports
2. In another shell: `sudo nethogs eth0` — top processes
3. Cross-reference PIDs with `ps -p PID -o pid,user,cmd`
4. If a single connection dominates, drop or shape it
5. Capture sample for offline analysis: `sudo tcpdump -i eth0 -c 5000 -w /tmp/burst.pcap`

### Cap a Single Heavy Service
1. Identify the destination port the service listens on
2. Build HTB tree on the egress interface
3. Add a `u32` filter matching that port → low-priority class
4. Verify with `iftop` while generating load
5. Persist by writing the `tc` block into `/etc/networkd-dispatcher/routable.d/50-shape`

### Investigate Sudden Monthly Cap Burn
1. `vnstat -i eth0 -d` to see which day spiked
2. Check sar archives for that day: `sar -n DEV -f /var/log/sysstat/saDD`
3. Cross-check auth/access logs and process forensics agent
4. Apply temporary cap with `wondershaper` while investigating

### Roll Back All Throttling
```bash
sudo tc qdisc del dev eth0 root 2>/dev/null
sudo tc qdisc del dev eth0 ingress 2>/dev/null
sudo wondershaper clear eth0 2>/dev/null
tc qdisc show dev eth0
```
