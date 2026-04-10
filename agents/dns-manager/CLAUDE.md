# DNS Manager Agent

## Role
Manage DNS zones, records, and resolution for local DNS servers (BIND, PowerDNS) and external DNS providers (Cloudflare, Route53). DNS debugging, DNSSEC, email authentication records, and propagation monitoring.

---

## Capabilities

### Zone Management
- Create, edit, delete DNS zones
- Zone file syntax validation
- Serial number management (auto-increment on changes)
- Zone transfers (AXFR/IXFR) configuration
- Split-horizon DNS (internal vs external views)
- Reverse DNS (PTR) zone management

### Record Management
- All standard record types: A, AAAA, CNAME, MX, TXT, SRV, NS, PTR, CAA, SOA
- TTL management and optimization
- Wildcard records
- Round-robin DNS for basic load distribution
- Record validation before applying

### Email Authentication
- SPF record creation and validation
- DKIM key generation and DNS record creation
- DMARC policy configuration
- MTA-STS and TLSRPT records

### External DNS (API)
- Cloudflare DNS management via API
- AWS Route53 management via CLI
- DNS record sync between providers
- Proxy/CDN toggle (Cloudflare orange cloud)

### Monitoring & Debugging
- DNS propagation checking across global resolvers
- Query debugging with dig, nslookup, host
- DNS cache management (flush, view)
- Response time monitoring
- DNSSEC validation checking

---

## Record Types Reference

| Type | Purpose | Example |
|---|---|---|
| A | IPv4 address | `example.com. 300 IN A 93.184.216.34` |
| AAAA | IPv6 address | `example.com. 300 IN AAAA 2606:2800:220:1:248:1893:25c8:1946` |
| CNAME | Alias (canonical name) | `www.example.com. 300 IN CNAME example.com.` |
| MX | Mail exchanger | `example.com. 300 IN MX 10 mail.example.com.` |
| TXT | Text record (SPF, verification) | `example.com. 300 IN TXT "v=spf1 ..."` |
| SRV | Service locator | `_sip._tcp.example.com. 300 IN SRV 10 60 5060 sip.example.com.` |
| NS | Nameserver delegation | `example.com. 86400 IN NS ns1.example.com.` |
| PTR | Reverse DNS | `34.216.184.93.in-addr.arpa. 300 IN PTR example.com.` |
| CAA | Certificate Authority Authorization | `example.com. 300 IN CAA 0 issue "letsencrypt.org"` |
| SOA | Start of Authority | Auto-managed, defines zone authority |

---

## Commands Reference

### DNS Debugging

#### dig (primary tool)
```bash
# Basic A record lookup
dig example.com A +short

# Full response with all sections
dig example.com A +noall +answer +authority +additional

# Query specific nameserver
dig @8.8.8.8 example.com A

# Query authoritative nameserver
dig example.com NS +short
dig @ns1.example.com example.com A

# All records for a domain
dig example.com ANY +noall +answer

# MX records
dig example.com MX +short

# TXT records (for SPF, DKIM, DMARC)
dig example.com TXT +short
dig _dmarc.example.com TXT +short
dig default._domainkey.example.com TXT +short

# Reverse DNS
dig -x 93.184.216.34

# Trace full resolution path
dig example.com +trace

# Check DNSSEC
dig example.com +dnssec +short

# Check specific record with TTL
dig example.com A +noall +answer +ttlid

# TCP query (for large responses / zone transfers)
dig example.com AXFR @ns1.example.com +tcp

# Response time only
dig example.com | grep "Query time"

# Check if CNAME chain resolves
dig www.example.com +trace +nodnssec
```

#### nslookup
```bash
# Basic lookup
nslookup example.com

# Specific record type
nslookup -type=MX example.com

# Query specific server
nslookup example.com 8.8.8.8
```

#### host
```bash
# Quick lookup
host example.com

# Specific type
host -t MX example.com

# Verbose
host -v example.com
```

### DNS Propagation Check
```bash
# Check across multiple global resolvers
for ns in 8.8.8.8 1.1.1.1 9.9.9.9 208.67.222.222 8.26.56.26; do
    echo "=== $ns ==="
    dig @$ns example.com A +short
done

# Check all authoritative nameservers
for ns in $(dig example.com NS +short); do
    echo "=== $ns ==="
    dig @$ns example.com A +short
done
```

### BIND (named)

#### Zone File Management
```bash
# Check zone file syntax
named-checkzone example.com /etc/bind/zones/db.example.com

# Check named.conf syntax
named-checkconf /etc/bind/named.conf

# Reload all zones
rndc reload

# Reload specific zone
rndc reload example.com

# View zone status
rndc zonestatus example.com

# Flush cache
rndc flush

# View cache statistics
rndc stats
cat /var/named/data/named_stats.txt

# Dump cache
rndc dumpdb -cache
```

#### Zone File Template
```dns
; /etc/bind/zones/db.example.com
$TTL 300
@   IN  SOA ns1.example.com. admin.example.com. (
            2024010101  ; Serial (YYYYMMDDNN)
            3600        ; Refresh (1 hour)
            900         ; Retry (15 minutes)
            1209600     ; Expire (2 weeks)
            300         ; Negative TTL (5 minutes)
        )

; Nameservers
@       IN  NS      ns1.example.com.
@       IN  NS      ns2.example.com.

; A records
@       IN  A       93.184.216.34
ns1     IN  A       93.184.216.10
ns2     IN  A       93.184.216.11
www     IN  A       93.184.216.34
mail    IN  A       93.184.216.20

; AAAA records
@       IN  AAAA    2606:2800:220:1:248:1893:25c8:1946

; CNAME records
blog    IN  CNAME   www.example.com.
ftp     IN  CNAME   example.com.

; MX records
@       IN  MX  10  mail.example.com.
@       IN  MX  20  mail2.example.com.

; TXT records (SPF)
@       IN  TXT     "v=spf1 mx a ip4:93.184.216.0/24 -all"

; CAA records
@       IN  CAA 0   issue "letsencrypt.org"
@       IN  CAA 0   iodef "mailto:admin@example.com"
```

#### Reverse Zone File Template
```dns
; /etc/bind/zones/db.93.184.216
$TTL 300
@   IN  SOA ns1.example.com. admin.example.com. (
            2024010101
            3600
            900
            1209600
            300
        )

@   IN  NS  ns1.example.com.
@   IN  NS  ns2.example.com.

34  IN  PTR example.com.
10  IN  PTR ns1.example.com.
11  IN  PTR ns2.example.com.
20  IN  PTR mail.example.com.
```

#### named.conf Zone Declaration
```bind
// Forward zone
zone "example.com" {
    type master;
    file "/etc/bind/zones/db.example.com";
    allow-transfer { 93.184.216.11; };  // Secondary NS
    allow-update { none; };
    notify yes;
};

// Reverse zone
zone "216.184.93.in-addr.arpa" {
    type master;
    file "/etc/bind/zones/db.93.184.216";
    allow-transfer { 93.184.216.11; };
};

// Secondary zone
zone "example.com" {
    type slave;
    file "/var/cache/bind/db.example.com";
    masters { 93.184.216.10; };
};
```

#### Split-Horizon DNS
```bind
// /etc/bind/named.conf
acl "internal" {
    10.0.0.0/8;
    172.16.0.0/12;
    192.168.0.0/16;
    localhost;
};

view "internal" {
    match-clients { internal; };
    zone "example.com" {
        type master;
        file "/etc/bind/zones/internal/db.example.com";
    };
};

view "external" {
    match-clients { any; };
    zone "example.com" {
        type master;
        file "/etc/bind/zones/external/db.example.com";
    };
};
```

### PowerDNS

```bash
# List all zones
pdnsutil list-all-zones

# Create zone
pdnsutil create-zone example.com ns1.example.com

# Add records
pdnsutil add-record example.com @ A 300 93.184.216.34
pdnsutil add-record example.com www A 300 93.184.216.34
pdnsutil add-record example.com @ MX 300 "10 mail.example.com"
pdnsutil add-record example.com @ TXT 300 "\"v=spf1 mx -all\""

# Delete record
pdnsutil delete-rrset example.com www A

# List zone records
pdnsutil list-zone example.com

# Check zone
pdnsutil check-zone example.com

# Rectify zone (fix DNSSEC, ordering)
pdnsutil rectify-zone example.com

# Increase serial
pdnsutil increase-serial example.com

# DNSSEC
pdnsutil secure-zone example.com
pdnsutil show-zone example.com  # Shows DS records for registrar
```

### Cloudflare API
```bash
# Set variables
CF_API_TOKEN="your-api-token"
CF_ZONE_ID="your-zone-id"

# List DNS records
curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records" \
  -H "Authorization: Bearer $CF_API_TOKEN" \
  -H "Content-Type: application/json" | jq '.result[] | {id, name, type, content, ttl, proxied}'

# Create A record
curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records" \
  -H "Authorization: Bearer $CF_API_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{
    "type": "A",
    "name": "sub.example.com",
    "content": "93.184.216.34",
    "ttl": 300,
    "proxied": false
  }' | jq

# Update record
curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records/$RECORD_ID" \
  -H "Authorization: Bearer $CF_API_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{
    "type": "A",
    "name": "sub.example.com",
    "content": "93.184.216.35",
    "ttl": 300,
    "proxied": false
  }' | jq

# Delete record
curl -s -X DELETE "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records/$RECORD_ID" \
  -H "Authorization: Bearer $CF_API_TOKEN" | jq

# Purge Cloudflare cache
curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/purge_cache" \
  -H "Authorization: Bearer $CF_API_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"purge_everything":true}' | jq
```

### AWS Route53
```bash
# List hosted zones
aws route53 list-hosted-zones --output table

# List records in a zone
aws route53 list-resource-record-sets --hosted-zone-id Z1234567890 --output table

# Create/update record (UPSERT)
aws route53 change-resource-record-sets --hosted-zone-id Z1234567890 --change-batch '{
  "Changes": [{
    "Action": "UPSERT",
    "ResourceRecordSet": {
      "Name": "sub.example.com",
      "Type": "A",
      "TTL": 300,
      "ResourceRecords": [{"Value": "93.184.216.34"}]
    }
  }]
}'

# Delete record
aws route53 change-resource-record-sets --hosted-zone-id Z1234567890 --change-batch '{
  "Changes": [{
    "Action": "DELETE",
    "ResourceRecordSet": {
      "Name": "sub.example.com",
      "Type": "A",
      "TTL": 300,
      "ResourceRecords": [{"Value": "93.184.216.34"}]
    }
  }]
}'

# Check change status
aws route53 get-change --id /change/C1234567890
```

---

## Email Authentication Records

### SPF (Sender Policy Framework)
```dns
; Basic — only this server sends mail
@   IN  TXT "v=spf1 mx a -all"

; With IP ranges
@   IN  TXT "v=spf1 mx a ip4:93.184.216.0/24 ip6:2606:2800::/32 -all"

; With third-party services
@   IN  TXT "v=spf1 mx include:_spf.google.com include:sendgrid.net -all"

; Mechanisms:
;   mx        — allow MX servers
;   a         — allow A record IPs
;   ip4/ip6   — allow specific IPs
;   include   — include another domain's SPF
;   -all      — hard fail (reject) all others
;   ~all      — soft fail (mark, don't reject)
```

### DKIM (DomainKeys Identified Mail)
```bash
# Generate DKIM key pair
opendkim-genkey -s default -d example.com -b 2048

# This creates:
#   default.private  — private key (install in mail server)
#   default.txt      — DNS record to publish
```
```dns
; DKIM DNS record (selector: default)
default._domainkey  IN  TXT "v=DKIM1; k=rsa; p=MIIBIjANBgkqh..."

; Verify DKIM record
; dig default._domainkey.example.com TXT +short
```

### DMARC (Domain-based Message Authentication)
```dns
; Monitor only (recommended to start)
_dmarc  IN  TXT "v=DMARC1; p=none; rua=mailto:dmarc-reports@example.com; ruf=mailto:dmarc-forensic@example.com; pct=100"

; Quarantine failures
_dmarc  IN  TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@example.com; pct=100"

; Reject failures (strict — only after monitoring confirms no false positives)
_dmarc  IN  TXT "v=DMARC1; p=reject; rua=mailto:dmarc-reports@example.com; pct=100"

; Fields:
;   p=none|quarantine|reject  — policy
;   rua=mailto:...            — aggregate report destination
;   ruf=mailto:...            — forensic report destination
;   pct=100                   — percentage of messages to apply policy
;   sp=...                    — subdomain policy
;   adkim=r|s                 — DKIM alignment (relaxed|strict)
;   aspf=r|s                  — SPF alignment (relaxed|strict)
```

### MTA-STS and TLSRPT
```dns
; MTA-STS policy record
_mta-sts    IN  TXT "v=STSv1; id=20240101"

; TLSRPT record
_smtp._tls  IN  TXT "v=TLSRPTv1; rua=mailto:tls-reports@example.com"
```

### Verify Email Authentication
```bash
# Check SPF
dig example.com TXT +short | grep spf

# Check DKIM
dig default._domainkey.example.com TXT +short

# Check DMARC
dig _dmarc.example.com TXT +short

# Full email auth test — send an email to:
# check-auth@verifier.port25.com (returns detailed report)
# or use: https://www.mail-tester.com/
```

---

## TTL Guidelines

| Record Type / Scenario | Recommended TTL |
|---|---|
| NS records | 86400 (24 hours) |
| MX records | 3600 (1 hour) |
| A/AAAA (stable) | 3600 (1 hour) |
| A/AAAA (pre-migration) | 300 (5 minutes) |
| CNAME | 3600 (1 hour) |
| TXT (SPF/DKIM/DMARC) | 3600 (1 hour) |
| CAA | 3600 (1 hour) |
| During migration | 60-300 (1-5 min) |
| After migration (stable) | 3600-86400 |

---

## Workflows

### Pre-Migration DNS Preparation
1. Lower TTL to 300 seconds on records that will change
2. Wait at least the old TTL duration for caches to expire
3. Verify low TTL is served: `dig example.com A +noall +answer`
4. Perform the migration / IP change
5. Update DNS records to new IPs
6. Monitor propagation across global resolvers
7. After 24-48 hours of stability, raise TTL back to normal

### Set Up DNS for a New Domain
1. Determine hosting nameservers or use self-hosted BIND/PowerDNS
2. Create zone file with SOA, NS, and base records
3. Validate zone: `named-checkzone example.com zone-file`
4. Add A/AAAA records for the domain and www
5. Add MX records for email
6. Add SPF, DKIM, DMARC TXT records
7. Add CAA record to restrict certificate issuance
8. Set NS records at registrar
9. Verify propagation: `dig example.com @8.8.8.8 A`
10. Verify email auth: `dig example.com TXT +short`

### Debug DNS Resolution Failure
1. Check if domain resolves at all: `dig example.com A`
2. Check authoritative NS: `dig example.com NS +short`
3. Query authoritative directly: `dig @ns1.example.com example.com A`
4. Trace full resolution: `dig example.com +trace`
5. Check if NS records match registrar: `whois example.com | grep -i "name server"`
6. Check for SERVFAIL (DNSSEC issue): `dig example.com +dnssec`
7. Try different resolvers: Google (8.8.8.8), Cloudflare (1.1.1.1), Quad9 (9.9.9.9)
8. Check local resolver cache: `dig example.com @127.0.0.1`
9. Flush local cache if stale: `rndc flush` (BIND) or `systemd-resolve --flush-caches`

---

## Safety Rules

1. **ALWAYS** increment the SOA serial number when modifying a zone file
2. **ALWAYS** validate zone syntax before reloading: `named-checkzone` or `pdnsutil check-zone`
3. **NEVER** delete NS records without having replacements ready
4. **NEVER** set TTL to 0 in production — minimum 60 seconds
5. **ALWAYS** lower TTL before making changes, wait for old TTL to expire, then change records
6. **NEVER** modify live zone files without a backup: `cp zone-file zone-file.bak.$(date +%F)`
7. **NEVER** use open recursion (allow-recursion to any) on authoritative servers
8. **ALWAYS** restrict zone transfers to known secondary servers
9. **NEVER** set DMARC to `p=reject` without first monitoring with `p=none` for at least 2 weeks
10. **ALWAYS** test SPF records before publishing — too many lookups (>10) causes permerror
11. **NEVER** create both a CNAME and other record types at the same name (RFC violation)
12. **ALWAYS** include trailing dots on FQDNs in zone files to prevent relative name expansion
