# Network Mapper Agent

Network topology discovery and open port inventory. Maps network infrastructure, discovers hosts, identifies services, and creates network inventories.

## Safety Rules

- NEVER scan networks you do not own or have authorization to scan
- NEVER use aggressive scan techniques that could cause denial of service
- NEVER exploit discovered services or vulnerabilities
- NEVER modify network configurations
- Always use appropriate scan rates to avoid network disruption
- Log all scanning activities for audit trail
- Respect network segmentation boundaries

---

## 1. Nmap Network Discovery

### Install Nmap

```bash
sudo apt-get install -y nmap
```

### Host Discovery

```bash
# Ping sweep — discover live hosts on a subnet
sudo nmap -sn 192.168.1.0/24

# ARP discovery (local network only, more reliable)
sudo nmap -PR -sn 192.168.1.0/24

# TCP SYN ping (useful when ICMP is blocked)
sudo nmap -PS22,80,443 -sn 192.168.1.0/24

# TCP ACK ping
sudo nmap -PA80,443 -sn 192.168.1.0/24

# UDP ping
sudo nmap -PU53,161 -sn 192.168.1.0/24

# ICMP echo + timestamp + netmask
sudo nmap -PE -PP -PM -sn 192.168.1.0/24

# Discover hosts without port scanning (list scan)
nmap -sL 192.168.1.0/24

# Discover hosts on multiple subnets
sudo nmap -sn 192.168.1.0/24 192.168.2.0/24 10.0.0.0/24

# Discover hosts from file
sudo nmap -sn -iL /tmp/target-networks.txt

# Exclude specific hosts
sudo nmap -sn 192.168.1.0/24 --exclude 192.168.1.1,192.168.1.2

# Output live hosts to file
sudo nmap -sn 192.168.1.0/24 -oG - | awk '/Up$/{print $2}' > /tmp/live-hosts.txt
```

### Port Scanning

```bash
# Quick scan — top 1000 ports
sudo nmap 192.168.1.1

# Scan all 65535 ports
sudo nmap -p- 192.168.1.1

# Scan specific ports
sudo nmap -p 22,80,443,3306,5432,6379,8080 192.168.1.1

# Scan port ranges
sudo nmap -p 1-1024 192.168.1.1

# Fast scan — top 100 ports
sudo nmap -F 192.168.1.1

# TCP SYN scan (stealth)
sudo nmap -sS 192.168.1.1

# TCP connect scan (no root needed)
nmap -sT 192.168.1.1

# UDP scan
sudo nmap -sU --top-ports 100 192.168.1.1

# Combined TCP and UDP
sudo nmap -sS -sU -p T:22,80,443,U:53,161,500 192.168.1.1

# Version detection
sudo nmap -sV 192.168.1.1

# Version detection with intensity
sudo nmap -sV --version-intensity 5 192.168.1.1

# OS detection
sudo nmap -O 192.168.1.1

# Aggressive scan (OS, version, scripts, traceroute)
sudo nmap -A 192.168.1.1

# Scan an entire subnet with service detection
sudo nmap -sV -p 22,80,443,3306,5432,8080,8443 192.168.1.0/24

# Rate-limited scan (to avoid disruption)
sudo nmap -sV --max-rate 100 -p- 192.168.1.1
```

### Output Formats

```bash
# Normal output
sudo nmap -sV 192.168.1.0/24 -oN /tmp/nmap-scan.txt

# Grepable output
sudo nmap -sV 192.168.1.0/24 -oG /tmp/nmap-scan.gnmap

# XML output
sudo nmap -sV 192.168.1.0/24 -oX /tmp/nmap-scan.xml

# All formats
sudo nmap -sV 192.168.1.0/24 -oA /tmp/nmap-scan

# Parse grepable output — list open ports per host
grep "Ports:" /tmp/nmap-scan.gnmap | awk -F'\t' '{print $1, $2}'

# Extract open port list
grep -oP '\d+/open' /tmp/nmap-scan.gnmap | sort -u
```

---

## 2. Masscan — Fast Port Scanning

### Install Masscan

```bash
sudo apt-get install -y masscan
```

### Run Scans

```bash
# Scan top ports at high speed
sudo masscan 192.168.1.0/24 -p 22,80,443,3306,5432,8080 --rate=1000

# Scan all ports (fast but aggressive)
sudo masscan 192.168.1.0/24 -p 0-65535 --rate=10000

# Scan with rate limiting
sudo masscan 192.168.1.0/24 -p 1-65535 --rate=500

# Output to file
sudo masscan 192.168.1.0/24 -p 22,80,443 --rate=1000 -oL /tmp/masscan-results.txt

# XML output (compatible with nmap)
sudo masscan 192.168.1.0/24 -p 22,80,443 --rate=1000 -oX /tmp/masscan-results.xml

# JSON output
sudo masscan 192.168.1.0/24 -p 22,80,443 --rate=1000 -oJ /tmp/masscan-results.json

# Scan and feed results to nmap for service detection
sudo masscan 192.168.1.0/24 -p 1-65535 --rate=1000 -oL /tmp/masscan-open.txt
awk '/^open/ {print $4}' /tmp/masscan-open.txt | sort -u > /tmp/hosts-with-ports.txt
```

---

## 3. ARP Scanning

### arp-scan

```bash
# Install arp-scan
sudo apt-get install -y arp-scan

# Scan local network
sudo arp-scan --localnet

# Scan specific interface
sudo arp-scan --interface=eth0 --localnet

# Scan specific subnet
sudo arp-scan 192.168.1.0/24

# Verbose with MAC vendor lookup
sudo arp-scan --localnet --resolve

# Output to file
sudo arp-scan --localnet > /tmp/arp-scan.txt

# Detect duplicate IPs
sudo arp-scan --localnet | awk '{print $1}' | sort | uniq -d
```

### Netdiscover

```bash
# Install netdiscover
sudo apt-get install -y netdiscover

# Passive ARP discovery (listen only)
sudo netdiscover -p -i eth0

# Active scan
sudo netdiscover -r 192.168.1.0/24

# Fast scan
sudo netdiscover -f -r 192.168.1.0/24

# Output to file
sudo netdiscover -r 192.168.1.0/24 -P > /tmp/netdiscover.txt
```

---

## 4. Traceroute and Path Discovery

```bash
# Standard traceroute
traceroute target.com

# TCP traceroute (bypasses ICMP filtering)
sudo traceroute -T target.com

# UDP traceroute
traceroute -U target.com

# Traceroute to specific port
sudo traceroute -T -p 443 target.com

# MTR — combines ping and traceroute
mtr --report target.com

# MTR with TCP
mtr --report --tcp --port 443 target.com

# Paris traceroute (more accurate for load-balanced paths)
sudo apt-get install -y paris-traceroute
paris-traceroute target.com 2>/dev/null

# Map route between two points
traceroute -n target.com | awk '{print $2}' | grep -v '*' | grep -v 'traceroute'
```

---

## 5. Network Interface and Routing Discovery

### Local Network Configuration

```bash
# Show all network interfaces
ip addr show

# Show routing table
ip route show

# Show default gateway
ip route | grep default

# Show ARP table
ip neigh show

# Show listening ports
sudo ss -tlnp
sudo ss -ulnp

# Show all connections
sudo ss -tnp

# Show network statistics
ss -s

# Show interface statistics
ip -s link show

# Show DNS configuration
cat /etc/resolv.conf
resolvectl status 2>/dev/null

# Show network namespaces
ip netns list 2>/dev/null

# Show bridge interfaces
bridge link show 2>/dev/null

# Show VLAN interfaces
cat /proc/net/vlan/config 2>/dev/null
```

---

## 6. Service Identification

```bash
# Identify services on open ports
sudo nmap -sV -sC -p- --open 192.168.1.1

# Banner grabbing with netcat
echo "" | nc -w 3 192.168.1.1 22
echo "" | nc -w 3 192.168.1.1 80
echo "" | nc -w 3 192.168.1.1 3306

# HTTP banner grab
curl -sI http://192.168.1.1

# SSL service identification
echo | openssl s_client -connect 192.168.1.1:443 2>/dev/null | head -5

# Identify all HTTP services on a network
sudo nmap -sV -p 80,443,8080,8443,8000,3000,5000,9090 --open 192.168.1.0/24

# Identify database services
sudo nmap -sV -p 3306,5432,27017,6379,1433,1521,9200 --open 192.168.1.0/24

# Identify SSH services
sudo nmap -sV -p 22,2222 --open 192.168.1.0/24
```

---

## 7. Network Inventory Generation

```bash
#!/bin/bash
# Generate comprehensive network inventory
NETWORK="${1:-192.168.1.0/24}"
REPORT_DIR="/var/log/network-maps"
DATE=$(date +%Y%m%d-%H%M%S)
REPORT="${REPORT_DIR}/inventory-${DATE}"
mkdir -p "$REPORT_DIR"

echo "=== Network Inventory Report ===" | tee "${REPORT}.txt"
echo "Network: $NETWORK" | tee -a "${REPORT}.txt"
echo "Date: $(date)" | tee -a "${REPORT}.txt"
echo "" | tee -a "${REPORT}.txt"

# Phase 1: Host discovery
echo "--- Phase 1: Host Discovery ---" | tee -a "${REPORT}.txt"
sudo nmap -sn "$NETWORK" -oG "${REPORT}-hosts.gnmap" 2>/dev/null
LIVE_HOSTS=$(grep "Up" "${REPORT}-hosts.gnmap" | awk '{print $2}')
echo "$LIVE_HOSTS" | tee -a "${REPORT}.txt"
HOST_COUNT=$(echo "$LIVE_HOSTS" | grep -c '.')
echo "Live hosts: $HOST_COUNT" | tee -a "${REPORT}.txt"
echo "" | tee -a "${REPORT}.txt"

# Phase 2: Port scanning
echo "--- Phase 2: Port Scanning ---" | tee -a "${REPORT}.txt"
echo "$LIVE_HOSTS" | while read -r host; do
  [ -z "$host" ] && continue
  echo "Scanning: $host" | tee -a "${REPORT}.txt"
  sudo nmap -sV --top-ports 100 --open "$host" 2>/dev/null | grep "open" | tee -a "${REPORT}.txt"
  echo "" | tee -a "${REPORT}.txt"
done

# Phase 3: OS detection
echo "--- Phase 3: OS Detection ---" | tee -a "${REPORT}.txt"
echo "$LIVE_HOSTS" | while read -r host; do
  [ -z "$host" ] && continue
  os=$(sudo nmap -O --osscan-guess "$host" 2>/dev/null | grep "Running:" | head -1)
  [ -n "$os" ] && echo "$host: $os" | tee -a "${REPORT}.txt"
done

echo "" | tee -a "${REPORT}.txt"
echo "=== Inventory Complete ===" | tee -a "${REPORT}.txt"

# Generate CSV inventory
echo "IP,Hostname,Open_Ports,OS" > "${REPORT}.csv"
echo "$LIVE_HOSTS" | while read -r host; do
  [ -z "$host" ] && continue
  hostname=$(dig -x "$host" +short 2>/dev/null | head -1)
  ports=$(sudo nmap --open -p- "$host" 2>/dev/null | grep "open" | awk '{print $1}' | tr '\n' '|')
  os=$(sudo nmap -O --osscan-guess "$host" 2>/dev/null | grep "Running:" | head -1 | sed 's/Running: //')
  echo "${host},${hostname},${ports},${os}" >> "${REPORT}.csv"
done

echo "Reports saved: ${REPORT}.txt and ${REPORT}.csv"
```

---

## 8. Network Comparison and Change Detection

```bash
# Compare two scans to detect changes
ndiff /tmp/nmap-scan-old.xml /tmp/nmap-scan-new.xml

# Automated change detection
#!/bin/bash
NETWORK="192.168.1.0/24"
BASELINE="/var/log/network-maps/baseline.xml"
CURRENT="/tmp/current-scan.xml"

sudo nmap -sV --top-ports 100 "$NETWORK" -oX "$CURRENT" 2>/dev/null

if [ -f "$BASELINE" ]; then
  CHANGES=$(ndiff "$BASELINE" "$CURRENT" 2>/dev/null)
  if [ -n "$CHANGES" ]; then
    echo "NETWORK CHANGES DETECTED:"
    echo "$CHANGES"
    echo "$CHANGES" | mail -s "Network Change Alert - $(hostname)" admin@example.com
  fi
fi

cp "$CURRENT" "$BASELINE"
```

---

## 9. DNS Enumeration

```bash
# Forward DNS lookup
dig target.com A
dig target.com AAAA
dig target.com MX
dig target.com NS
dig target.com TXT
dig target.com SOA

# Reverse DNS lookup for a subnet
for ip in $(seq 1 254); do
  result=$(dig -x "192.168.1.${ip}" +short 2>/dev/null)
  [ -n "$result" ] && echo "192.168.1.${ip}: $result"
done

# DNS zone transfer attempt
dig axfr target.com @ns1.target.com

# Enumerate subdomains with nmap
nmap --script dns-brute target.com

# Check for DNS recursion
dig @192.168.1.1 google.com +short
```

---

## 10. Network Visualization Data

```bash
# Generate DOT format for Graphviz
#!/bin/bash
NETWORK="${1:-192.168.1.0/24}"
echo "graph network {"
echo "  rankdir=LR;"
echo "  gateway [shape=diamond];"

sudo nmap -sn "$NETWORK" -oG - 2>/dev/null | grep "Up" | awk '{print $2}' | while read -r host; do
  hostname=$(dig -x "$host" +short 2>/dev/null | head -1)
  label="${host}"
  [ -n "$hostname" ] && label="${hostname}\n${host}"
  echo "  \"$host\" [label=\"$label\"];"
  echo "  gateway -- \"$host\";"
done

echo "}"

# Convert to image (if graphviz installed)
# dot -Tpng /tmp/network.dot -o /tmp/network.png
```

---

## 11. Scheduled Network Mapping

```bash
# Cron job for weekly network inventory
# /etc/cron.d/network-map
0 4 * * 0 root /opt/claudeos/scripts/network-inventory.sh 192.168.1.0/24 >> /var/log/network-maps/cron.log 2>&1

# Daily port change detection
0 5 * * * root /opt/claudeos/scripts/network-diff.sh >> /var/log/network-maps/changes.log 2>&1
```
