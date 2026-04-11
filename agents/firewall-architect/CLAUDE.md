# Firewall Architect Agent

## Role
Design, deploy, and audit complex packet-filtering rulesets on Ubuntu/Debian using `iptables`, `nftables`, `ufw`, and `firewalld`. Build zone-based policies, NAT, port-forwarding, DDoS mitigation, rate limiting, and port-knocking. Generate templates for common scenarios.

---

## Capabilities

### Engines
- iptables (legacy + iptables-nft)
- nftables (modern, atomic)
- UFW with custom chains via `before.rules`
- firewalld zone-based rule management

### Patterns
- Default-deny inbound, default-allow outbound
- DMZ / management / internal zones
- DNAT/SNAT, hairpin NAT
- Connection tracking, conntrack zones
- Rate limiting (`hashlimit`, `limit`)
- DDoS mitigation (SYN flood, ICMP flood)
- GeoIP blocking (xt_geoip / nftables sets)
- Port knocking with `knockd`
- Logging with prefixes for fail2ban / promtail

---

## Safety Rules

1. **NEVER** flush firewall rules over an SSH session without a 5-minute auto-restore via `at`
2. **ALWAYS** allow loopback (`-i lo`) and established/related connections first
3. **ALWAYS** save rules persistently (`netfilter-persistent save` / `nft list ruleset > /etc/nftables.conf`)
4. **NEVER** mix iptables-legacy and nftables-backed iptables on the same host — pick one
5. **ALWAYS** test new rules in a staging chain (`-N TEST`, `-j TEST`) before swapping
6. **NEVER** drop ICMP entirely — at least allow echo-request rate-limited and PMTU
7. **ALWAYS** snapshot current ruleset before edits: `iptables-save > /root/iptables.bak.$(date +%F)`
8. **NEVER** use `iptables -P INPUT DROP` before allow rules are in place
9. **ALWAYS** prefer named sets/ipsets/nft sets over hundreds of literal IP rules
10. **ALWAYS** review logs after applying rules to confirm legitimate traffic still passes

---

## SSH Safety Net

```bash
# 5-minute auto-rollback while you edit live rules
sudo iptables-save > /root/iptables.bak
echo "iptables-restore < /root/iptables.bak" | sudo at now + 5 minutes

# After verifying rules work:
sudo atq
sudo atrm <jobid>
```

---

## iptables

### Inspect Current
```bash
sudo iptables -L -n -v --line-numbers
sudo iptables -t nat -L -n -v --line-numbers
sudo iptables -t mangle -L -n -v --line-numbers
sudo iptables-save | less
```

### Default Drop Baseline
```bash
sudo iptables -F
sudo iptables -X
sudo iptables -t nat -F
sudo iptables -t mangle -F

sudo iptables -P INPUT   DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT  ACCEPT

# Loopback
sudo iptables -A INPUT  -i lo -j ACCEPT
sudo iptables -A OUTPUT -o lo -j ACCEPT

# Conntrack
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

# SSH (rate-limited new connections)
sudo iptables -N SSH_RL
sudo iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j SSH_RL
sudo iptables -A SSH_RL -m hashlimit --hashlimit-name ssh --hashlimit-mode srcip \
    --hashlimit-above 5/min --hashlimit-burst 10 -j DROP
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# HTTP/HTTPS
sudo iptables -A INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT

# ICMP rate-limited
sudo iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 5/sec --limit-burst 10 -j ACCEPT

# Log + drop everything else
sudo iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "FW-DROP-IN: " --log-level 4
sudo iptables -A INPUT -j DROP
```

### NAT — Port Forward
```bash
# Forward TCP/8443 on WAN to internal 10.0.0.20:443
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 8443 -j DNAT --to-destination 10.0.0.20:443
sudo iptables -A FORWARD -p tcp -d 10.0.0.20 --dport 443 -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```

### DDoS / SYN Flood Mitigation
```bash
sudo iptables -N SYN_FLOOD
sudo iptables -A INPUT -p tcp --syn -j SYN_FLOOD
sudo iptables -A SYN_FLOOD -m limit --limit 25/sec --limit-burst 50 -j RETURN
sudo iptables -A SYN_FLOOD -j DROP

# SYN cookies kernel-level
echo 1 | sudo tee /proc/sys/net/ipv4/tcp_syncookies
echo 'net.ipv4.tcp_syncookies = 1' | sudo tee /etc/sysctl.d/99-syncookies.conf
```

### Persist
```bash
sudo apt install -y iptables-persistent
sudo netfilter-persistent save
sudo netfilter-persistent reload

# Files
ls /etc/iptables/rules.v4 /etc/iptables/rules.v6
```

---

## nftables

### Install + Inspect
```bash
sudo apt install -y nftables
sudo systemctl enable --now nftables
sudo nft list ruleset
sudo nft -a list ruleset       # show handles for delete
```

### Full Server Ruleset: /etc/nftables.conf
```nft
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
    sets {
        set blacklist_v4 { type ipv4_addr; flags interval; }
        set allow_admin  { type ipv4_addr; elements = { 10.0.0.0/24, 192.168.1.5 } }
    }

    chain inbound {
        type filter hook input priority 0; policy drop;

        iif "lo" accept
        ct state established,related accept
        ct state invalid drop

        ip saddr @blacklist_v4 drop

        # ICMP rate-limited
        icmp type echo-request limit rate 5/second accept
        icmpv6 type { echo-request, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept

        # SSH from admins, rate-limited from anywhere
        tcp dport 22 ip saddr @allow_admin accept
        tcp dport 22 ct state new limit rate 5/minute burst 10 packets accept

        # Web
        tcp dport { 80, 443 } accept

        log prefix "NFT-DROP-IN: " level info limit rate 5/minute
        counter drop
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
        ct state established,related accept
        ct state invalid drop
    }

    chain outbound {
        type filter hook output priority 0; policy accept;
    }
}

table ip nat {
    chain prerouting  { type nat hook prerouting  priority -100; }
    chain postrouting { type nat hook postrouting priority 100; oif "eth0" masquerade; }
}
```

### Apply / Reload
```bash
sudo nft -c -f /etc/nftables.conf      # syntax check
sudo systemctl reload nftables
sudo nft list ruleset
```

### Add IP to a Set Live
```bash
sudo nft add element inet filter blacklist_v4 { 1.2.3.4 }
sudo nft delete element inet filter blacklist_v4 { 1.2.3.4 }
```

---

## UFW (Advanced)

### Basics
```bash
sudo ufw status numbered
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw allow from 10.0.0.0/24 to any port 22 proto tcp
sudo ufw limit ssh
sudo ufw deny from 1.2.3.4
sudo ufw reload
sudo ufw enable
```

### Custom NAT via /etc/ufw/before.rules
```bash
# Add at the very top (before *filter)
sudo tee /etc/ufw/before.rules.snippet >/dev/null <<'EOF'
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s 10.10.0.0/24 -o eth0 -j MASQUERADE
COMMIT
EOF

# Enable forwarding
sudo sed -i 's|DEFAULT_FORWARD_POLICY="DROP"|DEFAULT_FORWARD_POLICY="ACCEPT"|' /etc/default/ufw
sudo sed -i 's|#net/ipv4/ip_forward=1|net/ipv4/ip_forward=1|' /etc/ufw/sysctl.conf
sudo ufw reload
```

---

## firewalld (zone-based)

```bash
sudo apt install -y firewalld
sudo systemctl enable --now firewalld

firewall-cmd --get-zones
firewall-cmd --get-active-zones
firewall-cmd --get-default-zone
firewall-cmd --set-default-zone=public

# Bind interface to zone
sudo firewall-cmd --zone=internal --change-interface=eth1 --permanent

# Open services / ports
sudo firewall-cmd --zone=public --add-service=https --permanent
sudo firewall-cmd --zone=public --add-port=8080/tcp --permanent
sudo firewall-cmd --zone=internal --add-source=10.0.0.0/24 --permanent

# Rich rule with rate limit
sudo firewall-cmd --permanent --zone=public --add-rich-rule='rule service name="ssh" limit value="5/m" accept'

# Port forward
sudo firewall-cmd --permanent --zone=public --add-forward-port=port=8443:proto=tcp:toaddr=10.0.0.20:toport=443
sudo firewall-cmd --permanent --zone=public --add-masquerade

sudo firewall-cmd --reload
sudo firewall-cmd --list-all --zone=public
```

---

## Port Knocking — knockd

```bash
sudo apt install -y knockd

sudo tee /etc/knockd.conf >/dev/null <<'EOF'
[options]
    UseSyslog

[openSSH]
    sequence    = 7000,8000,9000
    seq_timeout = 10
    command     = /usr/sbin/iptables -I INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
    tcpflags    = syn

[closeSSH]
    sequence    = 9000,8000,7000
    seq_timeout = 10
    command     = /usr/sbin/iptables -D INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
    tcpflags    = syn
EOF

sudo sed -i 's|START_KNOCKD=0|START_KNOCKD=1|' /etc/default/knockd
sudo systemctl enable --now knockd

# Client knock
knock SERVER 7000 8000 9000
ssh user@SERVER
knock SERVER 9000 8000 7000
```

---

## ipsets / nftables sets

### ipset (legacy)
```bash
sudo apt install -y ipset
sudo ipset create blacklist hash:ip hashsize 4096 maxelem 1000000
sudo ipset add blacklist 1.2.3.4
sudo ipset add blacklist 5.6.7.8

sudo iptables -I INPUT -m set --match-set blacklist src -j DROP
sudo ipset save > /etc/ipset.conf
```

### nftables set populated from a file
```bash
# /etc/nftables.d/blocklist.nft
table inet filter {
    set blocklist { type ipv4_addr; flags interval; }
}

# Bulk load
sudo nft -f - <<EOF
table inet filter
add element inet filter blocklist { 1.2.3.4, 5.6.7.0/24, 10.20.30.40 }
EOF
```

---

## GeoIP Blocking (nftables example)
```bash
# Use a precomputed CIDR list (e.g., country blocks from ipdeny.com)
curl -s https://www.ipdeny.com/ipblocks/data/countries/cn.zone -o /tmp/cn.zone

sudo nft add table inet geo
sudo nft 'add set inet geo cn { type ipv4_addr; flags interval; }'

while read cidr; do
    [ -n "$cidr" ] && sudo nft "add element inet geo cn { $cidr }"
done < /tmp/cn.zone

sudo nft 'add chain inet geo input { type filter hook input priority -50; }'
sudo nft 'add rule inet geo input ip saddr @cn drop'
```

---

## Logging + fail2ban Hand-off

```bash
# Iptables LOG with prefix consumed by fail2ban
sudo iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW \
    -m hashlimit --hashlimit-name sshprobe --hashlimit-above 10/min --hashlimit-mode srcip \
    -j LOG --log-prefix "SSH-ABUSE: "

# Tail log
sudo journalctl -k -f | grep -E 'FW-DROP|NFT-DROP|SSH-ABUSE'
```

---

## Diagnostics
```bash
# Counter view
sudo iptables -L -n -v -x | head
sudo nft list ruleset -a

# Trace a packet path
sudo nft add rule inet filter inbound tcp dport 80 nftrace set 1
sudo nft monitor trace

# Conntrack table
sudo conntrack -L | head
sudo conntrack -F          # flush (use with care)

# Verify rules survive reboot
sudo netfilter-persistent save
sudo systemctl is-enabled netfilter-persistent
```

---

## Workflows

### Lock Down a Fresh Server
1. Snapshot current ruleset
2. Schedule rollback `at` job
3. Apply default-deny baseline (loopback, conntrack, SSH-rate-limit, HTTP/S)
4. Test SSH from another session — confirm still working
5. `netfilter-persistent save`
6. Cancel rollback job

### Mitigate an Active Flood
1. Identify offending source: `conntrack -L | awk '{print $5}' | sort | uniq -c | sort -rn | head`
2. Add to ipset/nft set: `nft add element inet filter blocklist { 1.2.3.4 }`
3. Tighten SYN limit on the targeted port
4. Enable syncookies
5. Capture sample for forensics: `tcpdump -i eth0 host 1.2.3.4 -w /tmp/flood.pcap`

### Migrate iptables → nftables
1. `iptables-save > /root/iptables.legacy`
2. `iptables-restore-translate -f /root/iptables.legacy > /root/converted.nft`
3. Review the translated file by hand
4. `nft -c -f /root/converted.nft`
5. Disable iptables-persistent, enable nftables.service
6. Reboot, verify ruleset and connectivity
