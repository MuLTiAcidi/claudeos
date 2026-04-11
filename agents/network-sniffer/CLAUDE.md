# Network Sniffer

Automated traffic analysis agent for packet capture, deep packet inspection, protocol dissection, anomaly detection, and bandwidth monitoring across network interfaces.

## Safety Rules

- Only capture traffic on networks you own or have explicit written authorization to monitor
- Never intentionally capture or store authentication credentials, passwords, or session tokens
- Minimize capture scope — use targeted filters instead of full promiscuous captures
- Auto-delete raw capture files after analysis is complete; never retain pcaps longer than necessary
- Comply with all applicable privacy laws (GDPR, HIPAA, ECPA, etc.) before capturing traffic
- Encrypt stored capture files and restrict access to authorized personnel only
- Never capture traffic on production networks without change management approval
- Redact or mask PII (personally identifiable information) in any exported reports
- Use BPF filters to exclude sensitive services (e.g., HR portals, health systems) from captures
- Log all capture sessions with start time, end time, interface, filter, and operator identity

---

## 1. Packet Capture

### 1.1 Basic tcpdump Captures

```bash
# Capture all traffic on an interface (limit to 1000 packets)
sudo tcpdump -i eth0 -c 1000 -w /tmp/capture_$(date +%Y%m%d_%H%M%S).pcap

# Capture traffic for a specific host
TARGET_HOST="192.168.1.100"
sudo tcpdump -i eth0 host "$TARGET_HOST" -c 500 -w /tmp/host_capture.pcap

# Capture traffic on a specific port
sudo tcpdump -i eth0 port 443 -c 500 -w /tmp/tls_capture.pcap

# Capture traffic on a port range
sudo tcpdump -i eth0 portrange 8000-9000 -c 500 -w /tmp/portrange_capture.pcap

# Capture only TCP SYN packets (connection initiation)
sudo tcpdump -i eth0 'tcp[tcpflags] & (tcp-syn) != 0' -c 200 -w /tmp/syn_capture.pcap

# Capture DNS traffic only
sudo tcpdump -i eth0 port 53 -c 500 -w /tmp/dns_capture.pcap

# Capture traffic between two specific hosts
sudo tcpdump -i eth0 'host 192.168.1.10 and host 192.168.1.20' -c 500 -w /tmp/pair_capture.pcap

# Capture traffic on a subnet
sudo tcpdump -i eth0 net 10.0.0.0/24 -c 1000 -w /tmp/subnet_capture.pcap

# Capture only ICMP traffic (ping, traceroute)
sudo tcpdump -i eth0 icmp -c 200 -w /tmp/icmp_capture.pcap

# Capture with verbose output to terminal (no file)
sudo tcpdump -i eth0 -nn -vv -c 50 port 80

# Capture non-standard ports (potential C2 communication)
sudo tcpdump -i eth0 'tcp and not port 80 and not port 443 and not port 22 and not port 53' \
  -c 500 -w /tmp/unusual_ports.pcap

# Time-limited capture (30 seconds)
timeout 30 sudo tcpdump -i eth0 -w /tmp/timed_capture.pcap
```

### 1.2 Advanced BPF Filters

```bash
# Capture only packets larger than 1000 bytes (potential data exfil)
sudo tcpdump -i eth0 'greater 1000' -c 200 -w /tmp/large_packets.pcap

# Capture HTTP GET requests specifically
sudo tcpdump -i eth0 'tcp dst port 80 and tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420' \
  -c 100 -w /tmp/http_get.pcap

# Capture TCP RST packets (connection resets — potential scanning)
sudo tcpdump -i eth0 'tcp[tcpflags] & (tcp-rst) != 0' -c 200 -w /tmp/resets.pcap

# Capture only incoming traffic (not originated by this host)
MY_IP="192.168.1.5"
sudo tcpdump -i eth0 "dst host ${MY_IP} and not src host ${MY_IP}" \
  -c 500 -w /tmp/inbound_only.pcap

# Capture fragmented packets (potential evasion technique)
sudo tcpdump -i eth0 '((ip[6:2] > 0) and (not ip[6] = 64))' \
  -c 100 -w /tmp/fragmented.pcap

# Capture ARP traffic (ARP spoofing detection)
sudo tcpdump -i eth0 arp -c 200 -w /tmp/arp_capture.pcap

# Rotate capture files every 100MB, keep last 5 files
sudo tcpdump -i eth0 -w /tmp/rotating_capture.pcap -C 100 -W 5
```

---

## 2. Traffic Analysis

### 2.1 tshark Protocol Statistics

```bash
# Display protocol hierarchy statistics from a capture file
tshark -r /tmp/capture.pcap -q -z io,phs

# Show conversation statistics (IPv4)
tshark -r /tmp/capture.pcap -q -z conv,ip

# Show endpoint stats and expert info (errors, warnings)
tshark -r /tmp/capture.pcap -q -z endpoints,ip
tshark -r /tmp/capture.pcap -q -z expert

# Show HTTP, DNS, and TLS statistics
tshark -r /tmp/capture.pcap -q -z http,tree
tshark -r /tmp/capture.pcap -q -z dns,tree
tshark -r /tmp/capture.pcap -q -z tls,tree 2>/dev/null

# Display top talkers by bytes
tshark -r /tmp/capture.pcap -q -z conv,ip | sort -t'|' -k5 -rn | head -20
```

### 2.2 Live Traffic Analysis

```bash
# Live protocol statistics (5-second refresh)
sudo tshark -i eth0 -q -z io,stat,5

# Live capture displaying only source, destination, protocol, info
sudo tshark -i eth0 -c 100 -T fields \
  -e frame.time_relative \
  -e ip.src \
  -e ip.dst \
  -e _ws.col.Protocol \
  -e _ws.col.Info

# Live capture of HTTP requests with URLs
sudo tshark -i eth0 -c 100 -Y "http.request" -T fields \
  -e ip.src \
  -e http.host \
  -e http.request.method \
  -e http.request.uri

# Live capture of DNS queries
sudo tshark -i eth0 -c 200 -Y "dns.flags.response == 0" -T fields \
  -e ip.src \
  -e dns.qry.name \
  -e dns.qry.type

# Live capture showing TLS SNI (Server Name Indication)
sudo tshark -i eth0 -c 100 -Y "tls.handshake.extensions_server_name" -T fields \
  -e ip.src \
  -e ip.dst \
  -e tls.handshake.extensions_server_name

# Count packets per protocol (live, 30 seconds)
timeout 30 sudo tshark -i eth0 -q -z io,phs
```

---

## 3. Deep Packet Inspection

### 3.1 String Matching with ngrep

```bash
# Search for a specific string in HTTP traffic
sudo ngrep -d eth0 -q "password" port 80

# Search for HTTP POST data
sudo ngrep -d eth0 -q "POST" port 80

# Search for a specific User-Agent string
sudo ngrep -d eth0 -qi "user-agent:.*curl" port 80

# Search for Base64-encoded data in HTTP (potential data exfil)
sudo ngrep -d eth0 -q '[A-Za-z0-9+/]{50,}={0,2}' port 80

# Search for SQL injection patterns
sudo ngrep -d eth0 -qi "union.*select\|drop.*table\|insert.*into" port 80

# Search for specific strings in any protocol
sudo ngrep -d eth0 -q "confidential" -c 100

# Search within a pcap file
ngrep -I /tmp/capture.pcap -q "password"

# Match patterns in DNS queries
sudo ngrep -d eth0 -q '.' port 53 | head -50
```

### 3.2 HTTP Content Inspection

```bash
# Extract all HTTP request headers from capture
tshark -r /tmp/capture.pcap -Y "http.request" -T fields \
  -e http.host \
  -e http.request.method \
  -e http.request.uri \
  -e http.user_agent \
  -e http.content_type \
  -E header=y -E separator="|"

# Extract HTTP response codes and sizes
tshark -r /tmp/capture.pcap -Y "http.response" -T fields \
  -e ip.src \
  -e http.response.code \
  -e http.content_length \
  -e http.content_type \
  -E header=y -E separator="|"

# Extract POST request bodies (be careful with sensitive data)
tshark -r /tmp/capture.pcap -Y "http.request.method == POST" -T fields \
  -e ip.src \
  -e http.host \
  -e http.request.uri \
  -e http.file_data

# Find all unique User-Agent strings
tshark -r /tmp/capture.pcap -Y "http.user_agent" -T fields \
  -e http.user_agent \
  | sort -u

# Detect suspicious file downloads by content type
tshark -r /tmp/capture.pcap -Y 'http.content_type contains "application/x-executable" or http.content_type contains "application/x-dosexec" or http.content_type contains "application/octet-stream"' \
  -T fields -e ip.src -e ip.dst -e http.request.uri -e http.content_type

# Export HTTP objects (files transferred over HTTP)
mkdir -p /tmp/http_objects
tshark -r /tmp/capture.pcap --export-objects http,/tmp/http_objects
echo "Exported $(ls /tmp/http_objects | wc -l) HTTP objects"
ls -lhS /tmp/http_objects | head -20
```

---

## 4. Anomaly Detection

### 4.1 Unusual Port Activity

```bash
# Find connections to non-standard ports
tshark -r /tmp/capture.pcap -Y "tcp.dstport > 1024 and tcp.dstport != 3306 and tcp.dstport != 5432 and tcp.dstport != 8080 and tcp.dstport != 8443" \
  -T fields -e ip.src -e ip.dst -e tcp.dstport \
  | sort | uniq -c | sort -rn | head -30

# Detect potential port scanning (many SYN packets from single source)
tshark -r /tmp/capture.pcap -Y "tcp.flags.syn == 1 and tcp.flags.ack == 0" \
  -T fields -e ip.src -e tcp.dstport \
  | awk '{print $1}' | sort | uniq -c | sort -rn | head -20

# Find sources with connections to many different ports (horizontal scan)
tshark -r /tmp/capture.pcap -Y "tcp.flags.syn == 1 and tcp.flags.ack == 0" \
  -T fields -e ip.src -e tcp.dstport \
  | sort -u | awk '{print $1}' | sort | uniq -c | sort -rn \
  | awk '$1 > 20 {print "[SCAN DETECTED] " $2 " connected to " $1 " unique ports"}'

# Detect high-frequency connections from single source
tshark -r /tmp/capture.pcap -Y "tcp.flags.syn == 1" \
  -T fields -e frame.time_epoch -e ip.src \
  | awk '{
    src=$2; t=int($1);
    count[src":"t]++;
  }
  END {
    for (k in count) {
      if (count[k] > 50) {
        split(k, a, ":");
        print "[ALERT] " a[1] " made " count[k] " connections in 1 second"
      }
    }
  }'
```

### 4.2 DNS Tunneling Detection

```bash
# Find unusually long DNS queries (potential DNS tunneling)
tshark -r /tmp/capture.pcap -Y "dns.flags.response == 0" \
  -T fields -e ip.src -e dns.qry.name \
  | awk '{if (length($2) > 50) print "[SUSPICIOUS] " $1 " queried: " $2}'

# Count DNS queries per source (high volume = suspicious)
tshark -r /tmp/capture.pcap -Y "dns.flags.response == 0" \
  -T fields -e ip.src \
  | sort | uniq -c | sort -rn | head -20

# Find DNS queries with many subdomains (tunneling signature)
tshark -r /tmp/capture.pcap -Y "dns.flags.response == 0" \
  -T fields -e ip.src -e dns.qry.name \
  | awk -F'[.\t]' '{
    dots=0; for(i=2;i<=NF;i++) dots++;
    if (dots > 5) print "[DNS TUNNEL?] " $1 " -> " $0
  }'

# Detect TXT record queries (commonly used in DNS tunneling)
tshark -r /tmp/capture.pcap -Y "dns.qry.type == 16" \
  -T fields -e ip.src -e dns.qry.name \
  | sort | uniq -c | sort -rn | head -20

# Find DNS queries to unusual TLDs
tshark -r /tmp/capture.pcap -Y "dns.flags.response == 0" \
  -T fields -e dns.qry.name \
  | awk -F. '{print $NF}' | sort | uniq -c | sort -rn | head -30

# Detect DNS responses with large payloads (data exfiltration)
tshark -r /tmp/capture.pcap -Y "dns.flags.response == 1" \
  -T fields -e ip.dst -e dns.qry.name -e frame.len \
  | awk '$3 > 512 {print "[LARGE DNS RESPONSE] " $0}'
```

### 4.3 Excessive Connection Detection

```bash
# Find hosts with the most active connections
ss -tn | awk 'NR>1 {print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -20

# Detect SYN flood (many half-open connections)
ss -tn state syn-recv | wc -l

# Show all connections in SYN-RECEIVED state
ss -tn state syn-recv | head -30

# Detect hosts with abnormally many ESTABLISHED connections
ss -tn state established | awk '{print $5}' | cut -d: -f1 \
  | sort | uniq -c | sort -rn \
  | awk '$1 > 100 {print "[ALERT] " $2 " has " $1 " established connections"}'

# Check for TIME_WAIT accumulation (potential DoS)
ss -tn state time-wait | wc -l
```

---

## 5. Bandwidth Analysis

### 5.1 Real-Time Bandwidth Monitoring

```bash
# Monitor bandwidth per interface with iftop (interactive)
sudo iftop -i eth0 -n -N -t -s 10 2>/dev/null | head -40

# Monitor bandwidth per process with nethogs
sudo nethogs -t -c 5 eth0 2>/dev/null | head -30

# Quick bandwidth test with vnstat
vnstat -i eth0 -l 10  # Live monitor for 10 seconds

# Show daily traffic summary
vnstat -i eth0 -d

# Show monthly traffic summary
vnstat -i eth0 -m

# Show hourly traffic for today
vnstat -i eth0 -h

# Show top traffic consumers
vnstat -i eth0 --top10

# Real-time bytes per second using /proc (Linux)
IFACE="eth0"
RX1=$(cat /sys/class/net/${IFACE}/statistics/rx_bytes)
TX1=$(cat /sys/class/net/${IFACE}/statistics/tx_bytes)
sleep 5
RX2=$(cat /sys/class/net/${IFACE}/statistics/rx_bytes)
TX2=$(cat /sys/class/net/${IFACE}/statistics/tx_bytes)
RX_RATE=$(( (RX2 - RX1) / 5 ))
TX_RATE=$(( (TX2 - TX1) / 5 ))
echo "Interface: ${IFACE}"
echo "RX rate: $(numfmt --to=iec ${RX_RATE})/s"
echo "TX rate: $(numfmt --to=iec ${TX_RATE})/s"
```

### 5.2 Traffic Accounting

```bash
# Calculate total bytes per source and destination IP
tshark -r /tmp/capture.pcap -T fields -e ip.src -e frame.len \
  | awk '{bytes[$1]+=$2} END {for (ip in bytes) print bytes[ip], ip}' \
  | sort -rn | head -20

tshark -r /tmp/capture.pcap -T fields -e ip.dst -e frame.len \
  | awk '{bytes[$1]+=$2} END {for (ip in bytes) print bytes[ip], ip}' \
  | sort -rn | head -20

# Show traffic volume per destination port
tshark -r /tmp/capture.pcap -T fields -e tcp.dstport -e frame.len \
  | awk 'NF==2 {bytes[$1]+=$2; count[$1]++} END {for (p in bytes) printf "%s\t%d pkts\t%d bytes\n", p, count[p], bytes[p]}' \
  | sort -t$'\t' -k3 -rn | head -20
```

---

## 6. Protocol Analysis

### 6.1 HTTP Analysis

```bash
# List all HTTP methods used
tshark -r /tmp/capture.pcap -Y "http.request" -T fields \
  -e http.request.method | sort | uniq -c | sort -rn

# List all requested URLs
tshark -r /tmp/capture.pcap -Y "http.request" -T fields \
  -e http.host -e http.request.uri | sort -u | head -50

# Find HTTP 4xx and 5xx errors
tshark -r /tmp/capture.pcap -Y "http.response.code >= 400" -T fields \
  -e ip.dst -e http.response.code -e http.request.uri \
  | sort | uniq -c | sort -rn | head -20

# Detect HTTP traffic on non-standard ports
tshark -r /tmp/capture.pcap -Y "http and tcp.port != 80 and tcp.port != 443 and tcp.port != 8080" \
  -T fields -e ip.src -e ip.dst -e tcp.dstport -e http.host
```

### 6.2 DNS Analysis

```bash
# List all DNS queries and response codes
tshark -r /tmp/capture.pcap -Y "dns.flags.response == 1" -T fields \
  -e dns.qry.name -e dns.flags.rcode \
  | sort | uniq -c | sort -rn | head -30

# Find NXDOMAIN responses (domain does not exist)
tshark -r /tmp/capture.pcap -Y "dns.flags.rcode == 3" -T fields \
  -e ip.src -e dns.qry.name \
  | sort | uniq -c | sort -rn | head -20

# Show DNS query types distribution
tshark -r /tmp/capture.pcap -Y "dns.flags.response == 0" -T fields \
  -e dns.qry.type \
  | sort | uniq -c | sort -rn

# Find DNS queries going to non-standard DNS servers
tshark -r /tmp/capture.pcap -Y "dns and udp.dstport == 53 and not ip.dst == 8.8.8.8 and not ip.dst == 8.8.4.4 and not ip.dst == 1.1.1.1" \
  -T fields -e ip.src -e ip.dst -e dns.qry.name \
  | sort -u | head -30

# Extract all resolved domain-to-IP mappings
tshark -r /tmp/capture.pcap -Y "dns.a" -T fields \
  -e dns.qry.name -e dns.a \
  | sort -u | head -50
```

### 6.3 TLS Handshake Inspection

```bash
# Extract TLS Client Hello details (SNI, cipher suites)
tshark -r /tmp/capture.pcap -Y "tls.handshake.type == 1" -T fields \
  -e ip.src -e ip.dst \
  -e tls.handshake.extensions_server_name \
  -e tls.handshake.version \
  | head -30

# List TLS versions in use
tshark -r /tmp/capture.pcap -Y "tls.handshake.type == 2" -T fields \
  -e tls.handshake.version \
  | sort | uniq -c | sort -rn

# Detect deprecated TLS versions (TLS 1.0 = 0x0301, TLS 1.1 = 0x0302)
tshark -r /tmp/capture.pcap -Y "tls.handshake.version == 0x0301 or tls.handshake.version == 0x0302" \
  -T fields -e ip.src -e ip.dst -e tls.handshake.version \
  -e tls.handshake.extensions_server_name \
  | sort -u

# List TLS certificate subjects
tshark -r /tmp/capture.pcap -Y "tls.handshake.type == 11" -T fields \
  -e ip.src \
  -e x509af.rdnSequence \
  | head -20

# Detect expired or self-signed certificates
tshark -r /tmp/capture.pcap -Y "tls.handshake.type == 11" -T fields \
  -e ip.src \
  -e x509af.rdnSequence \
  -e x509af.notBefore \
  -e x509af.notAfter \
  | head -20

# Find JA3 fingerprints (TLS client fingerprinting)
tshark -r /tmp/capture.pcap -Y "tls.handshake.type == 1" -T fields \
  -e ip.src \
  -e tls.handshake.ja3 \
  | sort | uniq -c | sort -rn | head -20
```

---

## 7. Capture File Analysis

```bash
# Get basic capture file statistics
capinfos /tmp/capture.pcap

# Show detailed packet count and time range
capinfos -acedTmS /tmp/capture.pcap

# Merge multiple capture files
mergecap -w /tmp/merged_capture.pcap /tmp/capture1.pcap /tmp/capture2.pcap

# Split a large capture file by time (300 seconds per file)
editcap -i 300 /tmp/large_capture.pcap /tmp/split_capture.pcap

# Split by packet count (10000 packets per file)
editcap -c 10000 /tmp/large_capture.pcap /tmp/split_capture.pcap

# Filter a pcap to keep only specific traffic
tshark -r /tmp/capture.pcap -Y "ip.addr == 192.168.1.100" \
  -w /tmp/filtered_capture.pcap

# Remove duplicate packets from capture
editcap -d /tmp/capture.pcap /tmp/deduped_capture.pcap

# Extract specific time window from capture
editcap -A "2025-01-15 10:00:00" -B "2025-01-15 10:15:00" \
  /tmp/capture.pcap /tmp/timewindow_capture.pcap

# Convert pcap format (pcap to pcapng)
editcap -F pcapng /tmp/capture.pcap /tmp/capture.pcapng

# Generate a summary report from capture file
{
  echo "============================="
  echo " CAPTURE FILE ANALYSIS REPORT"
  echo " Generated: $(date -Iseconds)"
  echo "============================="
  echo ""
  echo "--- File Info ---"
  capinfos -acedTmS /tmp/capture.pcap 2>/dev/null
  echo ""
  echo "--- Protocol Hierarchy ---"
  tshark -r /tmp/capture.pcap -q -z io,phs 2>/dev/null
  echo ""
  echo "--- Top 10 Conversations ---"
  tshark -r /tmp/capture.pcap -q -z conv,ip 2>/dev/null | head -15
  echo ""
  echo "--- Expert Info (Errors) ---"
  tshark -r /tmp/capture.pcap -q -z expert,error 2>/dev/null | head -20
  echo ""
  echo "============================="
} > /tmp/capture_analysis_report.txt

echo "Report saved to /tmp/capture_analysis_report.txt"
cat /tmp/capture_analysis_report.txt

# Zeek/Bro analysis of pcap file
ZEEK_LOG_DIR="/tmp/zeek_logs_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$ZEEK_LOG_DIR"
cd "$ZEEK_LOG_DIR" && zeek -r /tmp/capture.pcap local

# Review Zeek connection log
cat "$ZEEK_LOG_DIR/conn.log" | zeek-cut ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service duration orig_bytes resp_bytes \
  | sort -t$'\t' -k11 -rn | head -20

# Review Zeek DNS log
cat "$ZEEK_LOG_DIR/dns.log" | zeek-cut ts uid id.orig_h query qtype_name answers \
  | head -30

# Review Zeek HTTP log
cat "$ZEEK_LOG_DIR/http.log" | zeek-cut ts uid id.orig_h method host uri status_code response_body_len user_agent \
  | head -30

# Review Zeek SSL/TLS log
cat "$ZEEK_LOG_DIR/ssl.log" | zeek-cut ts uid id.orig_h id.resp_h server_name version cipher \
  | head -30

# Review Zeek notice log (anomalies and alerts)
if [ -f "$ZEEK_LOG_DIR/notice.log" ]; then
  cat "$ZEEK_LOG_DIR/notice.log" | zeek-cut ts note msg
fi

# Auto-cleanup capture files older than 24 hours
find /tmp -name "*.pcap" -mmin +1440 -delete 2>/dev/null
echo "Cleaned up pcap files older than 24 hours from /tmp"
```

---

## Quick Reference

| Task | Tool | Command |
|------|------|---------|
| Capture by host | tcpdump | `sudo tcpdump -i eth0 host IP -c 500 -w file.pcap` |
| Capture by port | tcpdump | `sudo tcpdump -i eth0 port PORT -c 500 -w file.pcap` |
| Capture SYN only | tcpdump | `sudo tcpdump -i eth0 'tcp[tcpflags] & (tcp-syn) != 0' -w file.pcap` |
| Protocol stats | tshark | `tshark -r file.pcap -q -z io,phs` |
| Conversation stats | tshark | `tshark -r file.pcap -q -z conv,ip` |
| Expert info | tshark | `tshark -r file.pcap -q -z expert` |
| HTTP requests | tshark | `tshark -r file.pcap -Y "http.request" -T fields -e http.host -e http.request.uri` |
| DNS queries | tshark | `tshark -r file.pcap -Y "dns.flags.response==0" -T fields -e dns.qry.name` |
| TLS SNI | tshark | `tshark -r file.pcap -Y "tls.handshake.type==1" -T fields -e tls.handshake.extensions_server_name` |
| String search | ngrep | `sudo ngrep -d eth0 -q "pattern" port 80` |
| Export HTTP objects | tshark | `tshark -r file.pcap --export-objects http,/tmp/objects` |
| Bandwidth by process | nethogs | `sudo nethogs -t eth0` |
| Bandwidth by host | iftop | `sudo iftop -i eth0 -n` |
| Daily traffic | vnstat | `vnstat -i eth0 -d` |
| Merge captures | mergecap | `mergecap -w merged.pcap file1.pcap file2.pcap` |
| File info | capinfos | `capinfos file.pcap` |
| Zeek analysis | zeek | `zeek -r file.pcap local` |
| Detect port scan | tshark | `tshark -r file.pcap -Y "tcp.flags.syn==1 and tcp.flags.ack==0" -T fields -e ip.src` |
| DNS tunneling | tshark | `tshark -r file.pcap -Y "dns" -T fields -e dns.qry.name \| awk 'length>50'` |
| Cleanup old pcaps | find | `find /tmp -name "*.pcap" -mmin +1440 -delete` |
