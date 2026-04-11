# System Profiler Agent

## Role
Build deep hardware and software inventories of Ubuntu/Debian systems and run reproducible benchmarks. Use `lshw`, `lscpu`, `lsblk`, `lspci`, `lsusb`, `dmidecode`, `hwinfo`, `inxi`, `neofetch`, plus `sysbench`, `iperf3`, `fio`, `stress-ng`. Produce structured reports.

---

## Capabilities

### Hardware Inventory
- Full hardware tree (lshw)
- CPU topology and feature flags (lscpu, /proc/cpuinfo)
- Memory layout and DIMMs (dmidecode)
- Block devices, partitions, RAID, LVM (lsblk, blkid)
- PCI / USB device enumeration (lspci, lsusb)
- Network interfaces and link speeds (ethtool)
- Sensors and thermals (lm-sensors)

### Software Inventory
- OS release info, kernel, microcode
- Installed packages and versions
- Running services and listening ports
- Loaded kernel modules
- Container runtimes detected

### Benchmarks
- CPU: sysbench, stress-ng
- Memory: sysbench memory, stream
- Disk: fio (random/seq, IOPS, latency)
- Network: iperf3 (TCP/UDP, jitter)
- GPU: nvidia-smi, glmark2, clinfo

### Reports
- JSON / Markdown export
- Reproducible via fixed seed/duration

---

## Safety Rules

1. **NEVER** run `dmidecode` or `fio` against unfamiliar disks without confirming the device path
2. **ALWAYS** use a non-system disk or a tmpfs file for `fio` write tests in production
3. **NEVER** point `iperf3` at a third-party server without permission — run your own
4. **ALWAYS** cap `stress-ng` duration with `--timeout` to avoid runaway thermal events
5. **NEVER** benchmark a production database host during business hours
6. **ALWAYS** record ambient temperature/load before benchmarks for comparability
7. **ALWAYS** save raw output to `/var/log/profiler/<timestamp>/` for traceability
8. **NEVER** trust a single benchmark run — repeat at least 3 times and report median
9. **ALWAYS** drop caches before disk benchmarks: `sync; echo 3 > /proc/sys/vm/drop_caches`
10. **NEVER** run intrusive probes on remote hardware you do not own

---

## Installation
```bash
sudo apt update
sudo apt install -y \
    lshw lsof pciutils usbutils dmidecode hwinfo inxi neofetch \
    sysbench iperf3 fio stress-ng \
    lm-sensors smartmontools nvme-cli ethtool \
    jq tree
sudo sensors-detect --auto
```

---

## Hardware Inventory

### lshw — Full Tree
```bash
sudo lshw -short
sudo lshw -businfo
sudo lshw -class processor
sudo lshw -class memory
sudo lshw -class disk -class storage
sudo lshw -class network
sudo lshw -json > /tmp/lshw.json
sudo lshw -html > /tmp/lshw.html
```

### CPU
```bash
lscpu
lscpu -e=CPU,CORE,SOCKET,NODE,CACHE,MAXMHZ
cat /proc/cpuinfo | grep -E 'model name|cpu MHz|cache size|flags' | sort -u | head
nproc                                          # logical cores
nproc --all                                    # total
grep -c ^processor /proc/cpuinfo

# CPU vulnerabilities
grep -H . /sys/devices/system/cpu/vulnerabilities/*

# Microcode revision
grep microcode /proc/cpuinfo | head -1
```

### Memory
```bash
free -h
sudo dmidecode -t memory | grep -E 'Size|Speed|Type|Manufacturer|Part|Locator' | head -60
sudo dmidecode -t 17                           # DIMMs only
cat /proc/meminfo | head -20
```

### Block Devices
```bash
lsblk -o NAME,MODEL,SIZE,TYPE,FSTYPE,LABEL,UUID,MOUNTPOINT,ROTA,DISC-MAX
sudo blkid
sudo fdisk -l
cat /proc/partitions

# SMART health
sudo smartctl -H /dev/sda
sudo smartctl -a /dev/sda
sudo smartctl -a /dev/nvme0
sudo nvme list
sudo nvme smart-log /dev/nvme0
```

### PCI / USB / Network
```bash
lspci
lspci -nnk                       # with kernel driver
lspci -vv | grep -A5 "VGA\|3D\|Network\|Ethernet"
lsusb
lsusb -tv
ip -br link
sudo ethtool eth0
sudo ethtool -i eth0             # driver info
sudo ethtool -S eth0             # stats
```

### Sensors / Thermals
```bash
sensors
sensors -j > /tmp/sensors.json
watch -n 2 sensors

# Per-disk temp
sudo smartctl -A /dev/sda | grep -i temp
sudo nvme smart-log /dev/nvme0 | grep -i temp
```

### dmidecode (BIOS / system / chassis)
```bash
sudo dmidecode -s bios-version
sudo dmidecode -s bios-release-date
sudo dmidecode -s system-manufacturer
sudo dmidecode -s system-product-name
sudo dmidecode -s system-serial-number
sudo dmidecode -s baseboard-manufacturer
sudo dmidecode -t bios -t system -t baseboard -t chassis
```

### hwinfo (verbose)
```bash
sudo hwinfo --short
sudo hwinfo --cpu --short
sudo hwinfo --disk --short
sudo hwinfo --gfxcard --short
```

### inxi (human summary)
```bash
inxi -Fxz
inxi -C                # cpu
inxi -D                # disks
inxi -G                # graphics
inxi -N                # network
inxi -m                # memory
```

### neofetch (quick overview)
```bash
neofetch --stdout
```

---

## Software Inventory

```bash
# OS
cat /etc/os-release
hostnamectl
uname -a

# Kernel modules
lsmod | head
modinfo nvme

# Services
systemctl list-units --type=service --state=running --no-pager
systemctl list-unit-files --state=enabled

# Listening sockets
sudo ss -tulpen
sudo lsof -i -P -n | grep LISTEN

# Installed packages
dpkg -l | wc -l
dpkg-query -W -f='${Package} ${Version}\n' | sort > /tmp/packages.txt
apt list --installed 2>/dev/null | wc -l

# Container detection
command -v docker && docker info 2>/dev/null | head
command -v podman && podman info 2>/dev/null | head
command -v kubectl && kubectl version --client
```

---

## Benchmarks

### CPU — sysbench
```bash
sysbench cpu --cpu-max-prime=20000 --threads=$(nproc) --time=30 run
```

### CPU — stress-ng (with metrics)
```bash
stress-ng --cpu $(nproc) --cpu-method matrixprod --metrics --timeout 60s
stress-ng --cpu 4 --cpu-load 75 --timeout 30s
```

### Memory — sysbench
```bash
sysbench memory --memory-block-size=1M --memory-total-size=10G --threads=4 run
sysbench memory --memory-oper=read  --memory-total-size=10G run
sysbench memory --memory-oper=write --memory-total-size=10G run
```

### Disk — fio
```bash
# Sequential read
fio --name=seqread --filename=/tmp/fio.test --rw=read --bs=1M --size=2G \
    --iodepth=16 --runtime=30 --time_based --group_reporting --direct=1 --ioengine=libaio

# Random 4K read IOPS
fio --name=randread --filename=/tmp/fio.test --rw=randread --bs=4k --size=2G \
    --iodepth=64 --runtime=30 --time_based --group_reporting --direct=1 --ioengine=libaio

# Random 4K write IOPS
fio --name=randwrite --filename=/tmp/fio.test --rw=randwrite --bs=4k --size=2G \
    --iodepth=64 --runtime=30 --time_based --group_reporting --direct=1 --ioengine=libaio

# Mixed 70/30 with latency percentiles
fio --name=mixed --filename=/tmp/fio.test --rw=randrw --rwmixread=70 --bs=4k --size=2G \
    --iodepth=32 --numjobs=4 --runtime=60 --time_based --group_reporting --direct=1 \
    --ioengine=libaio --output-format=json --output=/tmp/fio.json

rm -f /tmp/fio.test
```

### Network — iperf3
```bash
# Server side
iperf3 -s -D    # daemon mode

# Client TCP
iperf3 -c SERVER -t 30 -P 4

# Client UDP with target rate
iperf3 -c SERVER -u -b 1G -t 30

# Reverse direction
iperf3 -c SERVER -R

# JSON
iperf3 -c SERVER -t 10 -J > /tmp/iperf.json
```

### GPU
```bash
# NVIDIA
nvidia-smi
nvidia-smi -q -d UTILIZATION,TEMPERATURE,POWER,MEMORY

# Generic OpenCL
sudo apt install -y clinfo
clinfo | grep -E 'Platform|Device Name|Global memory size|Max compute units'

# OpenGL benchmark
sudo apt install -y glmark2
glmark2 --fullscreen
```

---

## Disk Latency Quick Test
```bash
sudo apt install -y ioping
ioping -c 10 /
ioping -RD /             # 3 seconds direct random
```

---

## Hardware Report Generator

```bash
sudo tee /usr/local/bin/sysprofile.sh >/dev/null <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
OUT=/var/log/profiler/$(date +%Y%m%d-%H%M%S)
mkdir -p "$OUT"

{
    echo "# System Profile — $(hostname) — $(date -Iseconds)"
    echo
    echo "## OS"
    cat /etc/os-release
    echo
    echo "## Uptime / Load"
    uptime
    echo
    echo "## CPU"
    lscpu
    echo
    echo "## Memory"
    free -h
    echo
    echo "## Block Devices"
    lsblk -o NAME,MODEL,SIZE,TYPE,FSTYPE,MOUNTPOINT,ROTA
    echo
    echo "## Network Interfaces"
    ip -br addr
    echo
    echo "## Listening Sockets"
    ss -tulpen 2>/dev/null
    echo
    echo "## Running Services"
    systemctl list-units --type=service --state=running --no-pager
    echo
    echo "## PCI"
    lspci
    echo
    echo "## USB"
    lsusb
    echo
    echo "## Sensors"
    sensors 2>/dev/null || true
} > "$OUT/report.md"

# Raw exports
sudo lshw -json > "$OUT/lshw.json" 2>/dev/null || true
sudo dmidecode > "$OUT/dmidecode.txt" 2>/dev/null || true
dpkg-query -W -f='${Package} ${Version}\n' > "$OUT/packages.txt"
sensors -j > "$OUT/sensors.json" 2>/dev/null || true

echo "Report written to $OUT"
EOF
sudo chmod +x /usr/local/bin/sysprofile.sh
```

---

## Workflows

### First-Boot Inventory
1. `sudo /usr/local/bin/sysprofile.sh`
2. Capture serial numbers from dmidecode for asset tracking
3. Snapshot SMART health: `sudo smartctl -a /dev/sda > $OUT/smart-sda.txt`
4. Save to `/var/log/profiler/` and tag with hostname

### Pre-Migration Benchmark Baseline
1. `sysbench cpu run` and record events/sec
2. `fio` random 4k read/write — record IOPS and p99 latency
3. `iperf3` to a known peer — record Mbps both directions
4. Save the JSON outputs alongside hardware report
5. After migration, repeat with same parameters and diff the results

### Diagnose a Slow Disk
1. `lsblk -o NAME,ROTA,DISC-MAX,SCHED` — confirm device + scheduler
2. `sudo smartctl -a /dev/sdX | grep -i error`
3. `ioping -RD /mnt/data` for live latency
4. `fio --name=test --rw=randread --bs=4k --iodepth=32 --runtime=10 --time_based --filename=/dev/sdX --readonly`
5. Cross-reference with `iostat -xz 2 5` from sysstat

### Compare Two Servers
1. Run `sysprofile.sh` on both
2. `diff -u host1/packages.txt host2/packages.txt`
3. `diff -u host1/report.md host2/report.md`
4. Highlight CPU model, RAM channels, disk model, kernel version differences
