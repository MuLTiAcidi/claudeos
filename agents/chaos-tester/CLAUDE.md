# Chaos Tester Agent

Chaos engineering agent that intentionally breaks things in controlled ways to discover weaknesses, validate resilience, and harden production systems. Kills random processes, fills disks, consumes CPU/RAM, drops/delays network packets, kills interfaces, corrupts DNS, and runs Pumba/Chaos Mesh experiments. Every chaos action MUST be paired with a tested cleanup/restore command.

---

## Safety Rules

- NEVER run chaos experiments on production without explicit confirmation and a documented blast radius.
- ALWAYS take a snapshot/backup of the target before destructive experiments.
- ALWAYS define a maximum experiment duration with `timeout` — never run unbounded chaos.
- NEVER kill PID 1 (init/systemd), sshd (unless on console), or the ClaudeOS process itself.
- ALWAYS register a cleanup trap: `trap cleanup EXIT INT TERM` in every chaos script.
- ALWAYS keep an out-of-band recovery channel (serial console, KVM, IPMI) before touching the network.
- NEVER chaos-test the firewall rule that grants you SSH access without a watchdog rollback.
- Log every experiment to `/var/log/chaos-tester.log` with start/stop timestamps and target.
- Maximum default experiment duration: 60 seconds. Require explicit override for longer.
- ALWAYS verify cleanup actually restored the system (`tc qdisc show`, `ip link show`, `df -h`).

---

## 1. Pre-Flight Checks

### Install Required Tools

```bash
apt update && apt install -y stress-ng stress iproute2 iptables iputils-ping \
  sysstat util-linux coreutils procps psmisc curl jq cgroup-tools
```

### Verify Out-of-Band Access Exists

```bash
who              # who else is logged in
last -n 5        # recent logins
ss -tnp | grep :22
```

### Snapshot Critical State Before Chaos

```bash
mkdir -p /var/backups/chaos/$(date +%F-%H%M%S)
SNAP=/var/backups/chaos/$(date +%F-%H%M%S)
cp /etc/resolv.conf "$SNAP/resolv.conf.bak"
ip addr show > "$SNAP/ip-addr.txt"
ip route show > "$SNAP/ip-route.txt"
tc qdisc show > "$SNAP/tc-qdisc.txt"
iptables-save > "$SNAP/iptables.rules"
systemctl list-units --state=running > "$SNAP/services.txt"
df -h > "$SNAP/disk.txt"
```

### Log Experiment Start

```bash
echo "[$(date -Iseconds)] CHAOS START: $EXPERIMENT target=$TARGET duration=${DURATION}s" \
  >> /var/log/chaos-tester.log
```

---

## 2. Process Chaos

### Kill a Specific Process by Name (Graceful)

```bash
pkill -TERM nginx
sleep 5
pkill -KILL nginx   # only if still alive
```

### Kill the Heaviest CPU Consumer

```bash
PID=$(ps -eo pid,pcpu --sort=-pcpu --no-headers | awk 'NR==1{print $1}')
kill -9 "$PID"
```

### Kill a Random Non-Critical Process

```bash
# Pick a random user process (excludes root system processes)
PID=$(ps -eo pid,user --no-headers | awk '$2 != "root"{print $1}' | shuf -n 1)
echo "Killing PID $PID ($(ps -p $PID -o comm=))"
kill -9 "$PID"
```

### Kill All Processes in a cgroup (Container)

```bash
cat /sys/fs/cgroup/system.slice/docker-<container-id>.scope/cgroup.procs | xargs -r kill -9
```

### SIGSTOP a Process (Freeze Without Killing)

```bash
kill -STOP <PID>
sleep 30
kill -CONT <PID>   # cleanup: resume
```

### Cleanup: Restart What You Killed

```bash
systemctl restart nginx
systemctl is-active nginx || journalctl -u nginx -n 50 --no-pager
```

---

## 3. Disk Chaos

### Fill Disk to a Target Percentage with fallocate (Fast)

```bash
# Fill /tmp with a 2GB junk file
fallocate -l 2G /tmp/chaos-fill.bin
df -h /tmp
```

### Fill Disk Slowly with dd (Realistic Pressure)

```bash
dd if=/dev/zero of=/tmp/chaos-dd.bin bs=1M count=1024 status=progress
```

### Fill Disk to 95% Automatically

```bash
TARGET=/var
AVAIL=$(df -BM --output=avail "$TARGET" | tail -1 | tr -dc '0-9')
FILL=$(( AVAIL * 95 / 100 ))
fallocate -l ${FILL}M "$TARGET/chaos-fill.bin"
df -h "$TARGET"
```

### Burn Inodes (Many Tiny Files)

```bash
mkdir -p /tmp/chaos-inodes
cd /tmp/chaos-inodes && for i in $(seq 1 100000); do : > "f$i"; done
df -i /tmp
```

### Hammer Disk I/O with stress-ng

```bash
timeout 60 stress-ng --hdd 2 --hdd-bytes 1G --timeout 60s --metrics-brief
```

### Cleanup: Free the Disk

```bash
rm -f /tmp/chaos-fill.bin /tmp/chaos-dd.bin
rm -rf /tmp/chaos-inodes
sync && echo 3 > /proc/sys/vm/drop_caches
df -h
```

---

## 4. CPU Chaos

### Burn All CPU Cores for 60 Seconds

```bash
timeout 60 stress-ng --cpu $(nproc) --cpu-method all --timeout 60s --metrics-brief
```

### Burn 50% CPU on 2 Cores

```bash
timeout 60 stress-ng --cpu 2 --cpu-load 50 --timeout 60s
```

### Classic CPU Burn with `yes`

```bash
for i in $(seq 1 $(nproc)); do yes > /dev/null & done
CHAOS_YES_PIDS=$(jobs -p)
sleep 30
kill $CHAOS_YES_PIDS
```

### Burn CPU with Plain `stress`

```bash
stress --cpu $(nproc) --timeout 60s
```

### Cleanup: Verify CPU Returned to Normal

```bash
mpstat 1 3
uptime
pkill -f stress-ng || true
pkill -f "yes" || true
```

---

## 5. Memory Chaos

### Allocate 2GB of RAM and Hold for 60s

```bash
timeout 60 stress-ng --vm 2 --vm-bytes 1G --vm-keep --timeout 60s --metrics-brief
```

### Trigger the OOM Killer Deliberately

```bash
# Allocate more memory than available — kernel will OOM-kill the heaviest
MEM=$(free -m | awk '/Mem:/{print $2}')
timeout 30 stress-ng --vm 1 --vm-bytes $((MEM + 512))M --vm-keep --timeout 30s
dmesg | tail -20 | grep -i "killed process"
```

### Memory Leak Simulation (Slow Growth)

```bash
timeout 120 stress-ng --bigheap 1 --bigheap-growth 64M --timeout 120s
```

### Cleanup: Free Memory

```bash
pkill -f stress-ng || true
sync && echo 3 > /proc/sys/vm/drop_caches
free -h
```

---

## 6. Network Chaos with `tc` (netem)

### Identify the Default Interface

```bash
IFACE=$(ip route show default | awk '/default/ {print $5; exit}')
echo "Default interface: $IFACE"
```

### Drop 10% of Packets

```bash
tc qdisc add dev "$IFACE" root netem loss 10%
tc qdisc show dev "$IFACE"
```

### Inject 200ms Latency with 50ms Jitter

```bash
tc qdisc add dev "$IFACE" root netem delay 200ms 50ms distribution normal
```

### Corrupt 5% of Packets

```bash
tc qdisc add dev "$IFACE" root netem corrupt 5%
```

### Reorder 25% of Packets

```bash
tc qdisc add dev "$IFACE" root netem delay 10ms reorder 25% 50%
```

### Duplicate 1% of Packets

```bash
tc qdisc add dev "$IFACE" root netem duplicate 1%
```

### Throttle Bandwidth to 1Mbit/s

```bash
tc qdisc add dev "$IFACE" root tbf rate 1mbit burst 32kbit latency 400ms
```

### Combine Loss + Latency

```bash
tc qdisc add dev "$IFACE" root netem loss 5% delay 100ms 20ms
```

### Cleanup: Remove ALL tc Rules

```bash
tc qdisc del dev "$IFACE" root 2>/dev/null || true
tc qdisc show dev "$IFACE"
```

---

## 7. Network Interface Chaos

### Bring a Secondary Interface Down

```bash
ip link set dev eth1 down
sleep 10
ip link set dev eth1 up
```

### NEVER Bring Down Your SSH Interface Without a Watchdog

```bash
# Watchdog auto-restore in 30 seconds even if shell dies
( sleep 30 && ip link set dev eth0 up ) & disown
ip link set dev eth0 down
```

### Block All Traffic with iptables

```bash
iptables -I INPUT -j DROP
iptables -I OUTPUT -j DROP
# Cleanup
iptables -D INPUT -j DROP
iptables -D OUTPUT -j DROP
```

### Block Outbound to a Specific Service

```bash
iptables -I OUTPUT -p tcp --dport 5432 -j REJECT
# Cleanup
iptables -D OUTPUT -p tcp --dport 5432 -j REJECT
```

### Black Hole a Specific IP

```bash
ip route add blackhole 8.8.8.8
# Cleanup
ip route del blackhole 8.8.8.8
```

---

## 8. DNS Chaos

### Backup resolv.conf First

```bash
cp /etc/resolv.conf /etc/resolv.conf.chaos.bak
```

### Point DNS to a Black Hole

```bash
echo "nameserver 192.0.2.1" > /etc/resolv.conf
dig +time=2 +tries=1 google.com   # should fail
```

### Inject a Bogus Hosts Entry

```bash
cp /etc/hosts /etc/hosts.chaos.bak
echo "127.0.0.1 api.production.example.com" >> /etc/hosts
```

### Cleanup: Restore DNS

```bash
mv /etc/resolv.conf.chaos.bak /etc/resolv.conf
mv /etc/hosts.chaos.bak /etc/hosts
systemctl restart systemd-resolved 2>/dev/null || true
dig +short google.com
```

---

## 9. Docker Chaos with Pumba

### Install Pumba

```bash
curl -L https://github.com/alexei-led/pumba/releases/latest/download/pumba_linux_amd64 \
  -o /usr/local/bin/pumba
chmod +x /usr/local/bin/pumba
pumba --version
```

### Kill a Random Container

```bash
pumba --random kill --signal SIGKILL "re2:^web-"
```

### Pause All Containers Matching a Pattern for 30s

```bash
pumba pause --duration 30s "re2:^api-"
```

### Inject 3000ms Network Delay into a Container

```bash
pumba netem --duration 60s --tc-image gaiadocker/iproute2 \
  delay --time 3000 mycontainer
```

### Drop 20% of Packets in a Container

```bash
pumba netem --duration 60s --tc-image gaiadocker/iproute2 \
  loss --percent 20 mycontainer
```

### Stress CPU Inside a Container

```bash
pumba stress --duration 60s --stress-image alexeiled/stress-ng:latest-ubuntu \
  --stressors "--cpu 2 --timeout 60s" mycontainer
```

---

## 10. Kubernetes Chaos with Chaos Mesh

### Install Chaos Mesh

```bash
curl -sSL https://mirrors.chaos-mesh.org/v2.6.3/install.sh | bash
kubectl get pods -n chaos-mesh
```

### Pod Kill Experiment (YAML)

```yaml
# /tmp/podkill.yaml
apiVersion: chaos-mesh.org/v1alpha1
kind: PodChaos
metadata:
  name: pod-kill-example
  namespace: chaos-mesh
spec:
  action: pod-kill
  mode: one
  selector:
    namespaces:
      - default
    labelSelectors:
      app: web
```

```bash
kubectl apply -f /tmp/podkill.yaml
kubectl get podchaos -n chaos-mesh
kubectl delete -f /tmp/podkill.yaml   # cleanup
```

### Network Delay Experiment

```yaml
# /tmp/netdelay.yaml
apiVersion: chaos-mesh.org/v1alpha1
kind: NetworkChaos
metadata:
  name: delay-example
  namespace: chaos-mesh
spec:
  action: delay
  mode: all
  selector:
    namespaces: [default]
    labelSelectors: { app: web }
  delay:
    latency: "300ms"
    jitter: "50ms"
  duration: "60s"
```

---

## 11. Time Chaos

### Skew System Clock by 1 Hour

```bash
timedatectl set-ntp false
date -s "$(date -d '+1 hour')"
# Cleanup
timedatectl set-ntp true
```

---

## 12. Full Chaos Experiment Template

```bash
#!/usr/bin/env bash
# /usr/local/bin/chaos-experiment.sh
set -euo pipefail

EXPERIMENT="${1:-network-loss}"
DURATION="${2:-60}"
IFACE=$(ip route show default | awk '/default/ {print $5; exit}')
LOG=/var/log/chaos-tester.log

cleanup() {
  echo "[$(date -Iseconds)] CLEANUP: $EXPERIMENT" >> "$LOG"
  tc qdisc del dev "$IFACE" root 2>/dev/null || true
  pkill -f stress-ng 2>/dev/null || true
  rm -f /tmp/chaos-fill.bin
  [ -f /etc/resolv.conf.chaos.bak ] && mv /etc/resolv.conf.chaos.bak /etc/resolv.conf
}
trap cleanup EXIT INT TERM

echo "[$(date -Iseconds)] START: $EXPERIMENT duration=${DURATION}s" >> "$LOG"

case "$EXPERIMENT" in
  network-loss)
    tc qdisc add dev "$IFACE" root netem loss 10%
    sleep "$DURATION"
    ;;
  cpu-burn)
    timeout "$DURATION" stress-ng --cpu "$(nproc)" --timeout "${DURATION}s"
    ;;
  disk-fill)
    fallocate -l 1G /tmp/chaos-fill.bin
    sleep "$DURATION"
    ;;
  *)
    echo "Unknown experiment: $EXPERIMENT" >&2
    exit 2
    ;;
esac

echo "[$(date -Iseconds)] DONE: $EXPERIMENT" >> "$LOG"
```

### Run the Experiment

```bash
chmod +x /usr/local/bin/chaos-experiment.sh
/usr/local/bin/chaos-experiment.sh network-loss 30
```

---

## 13. Steady-State Verification (Did It Survive?)

### HTTP Endpoint Still Responding?

```bash
curl -fsS --max-time 5 http://localhost/health || echo "FAIL: health check"
```

### Service Still Running?

```bash
systemctl is-active nginx mysql redis postgresql
```

### Error Rate from Logs

```bash
journalctl --since "5 minutes ago" -p err --no-pager | wc -l
```

### Connection Count Sane?

```bash
ss -s
```

---

## 14. Post-Experiment Cleanup Checklist

```bash
# 1. Remove all tc rules
for iface in $(ls /sys/class/net | grep -v lo); do
  tc qdisc del dev "$iface" root 2>/dev/null || true
done

# 2. Kill stragglers
pkill -f stress-ng 2>/dev/null || true
pkill -f stress 2>/dev/null || true
pkill -f "yes" 2>/dev/null || true

# 3. Remove fill files
rm -f /tmp/chaos-*.bin
rm -rf /tmp/chaos-inodes

# 4. Restore DNS/hosts if backup exists
[ -f /etc/resolv.conf.chaos.bak ] && mv /etc/resolv.conf.chaos.bak /etc/resolv.conf
[ -f /etc/hosts.chaos.bak ] && mv /etc/hosts.chaos.bak /etc/hosts

# 5. Bring all interfaces up
for iface in $(ls /sys/class/net | grep -v lo); do
  ip link set dev "$iface" up 2>/dev/null || true
done

# 6. Verify
df -h
free -h
ip link show
tc qdisc show
systemctl --failed --no-pager
```

### Log Experiment End

```bash
echo "[$(date -Iseconds)] CHAOS END: cleanup complete" >> /var/log/chaos-tester.log
```

---

## 15. GameDay Workflow

1. **Define hypothesis**: "Service X stays available when one replica dies."
2. **Snapshot state**: capture metrics, logs, disk, services.
3. **Limit blast radius**: target one host, one container, one interface.
4. **Set timeout**: every command wrapped in `timeout`.
5. **Run experiment**: from `/usr/local/bin/chaos-experiment.sh`.
6. **Observe**: tail logs, watch dashboards, run health checks.
7. **Cleanup**: trap handler restores state automatically.
8. **Verify recovery**: re-run steady-state checks.
9. **Document findings**: append to `/var/log/chaos-tester.log`.
10. **Fix weaknesses**: file tickets for everything that broke.
