# SSL Tester Agent

Deep SSL/TLS configuration analysis for all services. Tests certificate validity, cipher suites, protocol versions, and known vulnerabilities.

## Safety Rules

- NEVER modify SSL/TLS configurations — test and report only
- NEVER install or replace certificates without explicit authorization
- NEVER expose private keys or certificate data
- NEVER perform SSL tests against systems you do not own
- Always use non-destructive testing methods
- Log all testing activities

---

## 1. OpenSSL Client Testing

### Basic Connection Test

```bash
# Test SSL connection to a host
echo | openssl s_client -connect target.com:443 -servername target.com 2>/dev/null

# Show certificate details
echo | openssl s_client -connect target.com:443 -servername target.com 2>/dev/null | openssl x509 -noout -text

# Show certificate dates
echo | openssl s_client -connect target.com:443 -servername target.com 2>/dev/null | openssl x509 -noout -dates

# Show certificate subject and issuer
echo | openssl s_client -connect target.com:443 -servername target.com 2>/dev/null | openssl x509 -noout -subject -issuer

# Show certificate fingerprint
echo | openssl s_client -connect target.com:443 -servername target.com 2>/dev/null | openssl x509 -noout -fingerprint -sha256

# Show certificate serial number
echo | openssl s_client -connect target.com:443 -servername target.com 2>/dev/null | openssl x509 -noout -serial

# Check certificate expiration
echo | openssl s_client -connect target.com:443 -servername target.com 2>/dev/null | openssl x509 -noout -checkend 0
echo $?  # 0=valid, 1=expired

# Check if certificate expires within 30 days
echo | openssl s_client -connect target.com:443 -servername target.com 2>/dev/null | openssl x509 -noout -checkend 2592000
```

### Certificate Chain Validation

```bash
# Show full certificate chain
echo | openssl s_client -connect target.com:443 -servername target.com -showcerts 2>/dev/null

# Verify certificate chain
echo | openssl s_client -connect target.com:443 -servername target.com -verify 5 -verify_return_error 2>&1

# Check certificate against specific CA bundle
echo | openssl s_client -connect target.com:443 -servername target.com -CAfile /etc/ssl/certs/ca-certificates.crt 2>&1

# Extract each certificate in the chain
echo | openssl s_client -connect target.com:443 -servername target.com -showcerts 2>/dev/null | \
  awk '/BEGIN CERT/,/END CERT/ {print}' | \
  csplit -z -f /tmp/cert- - '/-----BEGIN CERTIFICATE-----/' '{*}' 2>/dev/null
for cert in /tmp/cert-*; do
  echo "=== $(basename $cert) ==="
  openssl x509 -in "$cert" -noout -subject -issuer -dates
done

# Check OCSP stapling
echo | openssl s_client -connect target.com:443 -servername target.com -status 2>/dev/null | grep -A 5 "OCSP Response"

# Check OCSP responder
OCSP_URI=$(echo | openssl s_client -connect target.com:443 -servername target.com 2>/dev/null | openssl x509 -noout -ocsp_uri)
echo "OCSP URI: $OCSP_URI"
```

### Subject Alternative Names (SAN)

```bash
# List all SANs
echo | openssl s_client -connect target.com:443 -servername target.com 2>/dev/null | \
  openssl x509 -noout -ext subjectAltName

# Check if specific domain is covered
echo | openssl s_client -connect target.com:443 -servername target.com 2>/dev/null | \
  openssl x509 -noout -ext subjectAltName | grep -i "specific-domain.com"
```

---

## 2. Protocol Version Testing

### Test Specific TLS Versions

```bash
# Test TLS 1.3
echo | openssl s_client -connect target.com:443 -servername target.com -tls1_3 2>&1 | head -5

# Test TLS 1.2
echo | openssl s_client -connect target.com:443 -servername target.com -tls1_2 2>&1 | head -5

# Test TLS 1.1 (should be disabled)
echo | openssl s_client -connect target.com:443 -servername target.com -tls1_1 2>&1 | head -5

# Test TLS 1.0 (should be disabled)
echo | openssl s_client -connect target.com:443 -servername target.com -tls1 2>&1 | head -5

# Test SSLv3 (must be disabled)
echo | openssl s_client -connect target.com:443 -servername target.com -ssl3 2>&1 | head -5

# Automated protocol version check
echo "=== Protocol Version Support ==="
for proto in -tls1_3 -tls1_2 -tls1_1 -tls1 -ssl3; do
  result=$(echo | openssl s_client -connect target.com:443 -servername target.com $proto 2>&1)
  if echo "$result" | grep -q "CONNECTED"; then
    version=$(echo "$result" | grep "Protocol" | awk '{print $NF}')
    echo "$proto: SUPPORTED ($version)"
  else
    echo "$proto: NOT SUPPORTED (good if deprecated)"
  fi
done
```

---

## 3. Cipher Suite Analysis

### Enumerate Supported Ciphers

```bash
# Show negotiated cipher
echo | openssl s_client -connect target.com:443 -servername target.com 2>/dev/null | grep "Cipher is"

# Test all ciphers supported by OpenSSL
for cipher in $(openssl ciphers 'ALL:eNULL' | tr ':' ' '); do
  result=$(echo | openssl s_client -connect target.com:443 -servername target.com -cipher "$cipher" 2>&1)
  if echo "$result" | grep -q "CONNECTED" && ! echo "$result" | grep -q "error"; then
    echo "ACCEPTED: $cipher"
  fi
done

# Test TLS 1.3 cipher suites
echo | openssl s_client -connect target.com:443 -servername target.com -tls1_3 -ciphersuites "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256" 2>/dev/null | grep "Cipher is"

# Check for weak ciphers
WEAK_CIPHERS="NULL:EXPORT:LOW:DES:RC4:MD5:aNULL:eNULL"
for cipher in $(echo "$WEAK_CIPHERS" | tr ':' ' '); do
  result=$(echo | openssl s_client -connect target.com:443 -servername target.com -cipher "$cipher" 2>&1)
  echo "$result" | grep -q "Cipher is" && echo "WEAK CIPHER ACCEPTED: $cipher"
done

# Check for forward secrecy
echo | openssl s_client -connect target.com:443 -servername target.com 2>/dev/null | grep -E "(ECDHE|DHE)"
```

### Nmap Cipher Enumeration

```bash
# Enumerate all ciphers with nmap
nmap --script ssl-enum-ciphers -p 443 target.com

# Check specific ports
nmap --script ssl-enum-ciphers -p 443,8443,993,995,587 target.com

# Get cipher strength rating
nmap --script ssl-enum-ciphers -p 443 target.com | grep -E "(TLS|SSL|cipher|strength)"
```

---

## 4. testssl.sh Comprehensive Testing

### Install testssl.sh

```bash
# Install testssl.sh
cd /opt
sudo git clone --depth 1 https://github.com/drwetter/testssl.sh.git
sudo ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl
```

### Run Tests

```bash
# Full test
testssl target.com

# Quick test
testssl --fast target.com

# Test specific checks
testssl --protocols target.com
testssl --ciphers target.com
testssl --vulnerabilities target.com
testssl --headers target.com
testssl --server-defaults target.com

# Test specific port
testssl target.com:8443

# Test STARTTLS services
testssl --starttls smtp target.com:587
testssl --starttls imap target.com:143
testssl --starttls pop3 target.com:110
testssl --starttls ftp target.com:21

# JSON output
testssl --json /tmp/testssl-results.json target.com

# CSV output
testssl --csv /tmp/testssl-results.csv target.com

# HTML output
testssl --html /tmp/testssl-report.html target.com

# Test multiple hosts
testssl --file /tmp/ssl-hosts.txt

# Test with specific IP (bypass DNS)
testssl --ip 1.2.3.4 target.com

# Show certificate info only
testssl --server-defaults target.com

# Check for specific vulnerabilities
testssl --heartbleed target.com
testssl --ccs-injection target.com
testssl --ticketbleed target.com
testssl --robot target.com
testssl --poodle target.com
testssl --drown target.com
testssl --logjam target.com
testssl --beast target.com
testssl --freak target.com
testssl --sweet32 target.com
```

---

## 5. SSL Vulnerability Checks

### Heartbleed (CVE-2014-0160)

```bash
# Nmap check
nmap --script ssl-heartbleed -p 443 target.com

# OpenSSL check
echo | openssl s_client -connect target.com:443 -tlsextdebug 2>&1 | grep -i "heartbeat"
```

### POODLE (CVE-2014-3566)

```bash
# Check SSLv3 support
echo | openssl s_client -connect target.com:443 -ssl3 2>&1 | grep -E "(CONNECTED|error)"

# Nmap check
nmap --script ssl-poodle -p 443 target.com
```

### DROWN (CVE-2016-0800)

```bash
# Check SSLv2 support
echo | openssl s_client -connect target.com:443 -ssl2 2>&1 | grep -E "(CONNECTED|error)"

# Nmap check
nmap --script sslv2-drown -p 443 target.com
```

### ROBOT Attack

```bash
# Check with nmap
nmap --script ssl-robot -p 443 target.com
```

### CCS Injection (CVE-2014-0224)

```bash
nmap --script ssl-ccs-injection -p 443 target.com
```

### CRIME/BREACH

```bash
# Check for TLS compression (CRIME)
echo | openssl s_client -connect target.com:443 -servername target.com 2>/dev/null | grep "Compression"

# Check for HTTP compression on sensitive pages (BREACH)
curl -sI -H "Accept-Encoding: gzip,deflate" "https://target.com/login" | grep -i "content-encoding"
```

---

## 6. Certificate Monitoring

### Check Multiple Certificates

```bash
# Check certificates across all services
HOSTS="
target.com:443
mail.target.com:993
mail.target.com:587
target.com:8443
"

echo "=== Certificate Expiration Report ==="
echo "$HOSTS" | while read -r host; do
  [ -z "$host" ] && continue
  expiry=$(echo | openssl s_client -connect "$host" -servername "${host%%:*}" 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
  if [ -n "$expiry" ]; then
    days=$(( ($(date -d "$expiry" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$expiry" +%s 2>/dev/null) - $(date +%s)) / 86400 ))
    if [ "$days" -lt 0 ]; then
      echo "EXPIRED: $host (expired $expiry)"
    elif [ "$days" -lt 30 ]; then
      echo "WARNING: $host expires in $days days ($expiry)"
    else
      echo "OK: $host expires in $days days ($expiry)"
    fi
  else
    echo "ERROR: Cannot connect to $host"
  fi
done
```

### Certificate Transparency Log Check

```bash
# Query Certificate Transparency logs via crt.sh
curl -s "https://crt.sh/?q=%25.target.com&output=json" | python3 -m json.tool | head -100

# Find all issued certificates for a domain
curl -s "https://crt.sh/?q=target.com&output=json" | python3 -c "
import sys, json
certs = json.load(sys.stdin)
for cert in certs[:20]:
    print(f\"{cert.get('id')}: {cert.get('name_value')} (Issuer: {cert.get('issuer_name')}, Not After: {cert.get('not_after')})\")"
```

---

## 7. Local Certificate Store Audit

```bash
# List all installed CA certificates
ls /etc/ssl/certs/ | head -50

# Check system CA bundle
openssl crl2pkcs7 -nocrl -certfile /etc/ssl/certs/ca-certificates.crt | openssl pkcs7 -print_certs -noout | grep "subject="

# Find all certificates on the system
find / -name "*.pem" -o -name "*.crt" -o -name "*.cert" -o -name "*.key" 2>/dev/null | head -50

# Check for expired local certificates
find /etc/ssl /etc/pki -name "*.crt" -o -name "*.pem" 2>/dev/null | while read cert; do
  if openssl x509 -in "$cert" -noout -checkend 0 2>/dev/null; then
    : # valid
  else
    echo "EXPIRED: $cert"
    openssl x509 -in "$cert" -noout -subject -enddate 2>/dev/null
  fi
done

# Check certificate file permissions (private keys should be 0600)
find /etc/ssl/private /etc/pki/tls/private -type f 2>/dev/null | while read key; do
  perms=$(stat -c '%a' "$key" 2>/dev/null)
  [ "$perms" != "600" ] && echo "BAD PERMISSIONS: $key ($perms, should be 600)"
done
```

---

## 8. HSTS and HPKP Checks

```bash
# Check HSTS header
curl -sI "https://target.com" | grep -i "strict-transport-security"

# Check HSTS preload eligibility
echo "=== HSTS Preload Checks ==="
HSTS=$(curl -sI "https://target.com" | grep -i "strict-transport-security" | tr -d '\r')
echo "$HSTS"
echo "$HSTS" | grep -qi "includeSubDomains" && echo "[PASS] includeSubDomains" || echo "[FAIL] Missing includeSubDomains"
echo "$HSTS" | grep -qi "preload" && echo "[PASS] preload" || echo "[FAIL] Missing preload directive"
MAX_AGE=$(echo "$HSTS" | grep -oP 'max-age=\K\d+')
[ -n "$MAX_AGE" ] && [ "$MAX_AGE" -ge 31536000 ] && echo "[PASS] max-age >= 1 year ($MAX_AGE)" || echo "[FAIL] max-age too short ($MAX_AGE)"

# Check if HTTP redirects to HTTPS
HTTP_STATUS=$(curl -sI -o /dev/null -w "%{http_code}" "http://target.com")
HTTP_LOCATION=$(curl -sI "http://target.com" | grep -i "location:" | tr -d '\r')
echo "HTTP -> HTTPS redirect: $HTTP_STATUS $HTTP_LOCATION"
```

---

## 9. Comprehensive SSL Audit Workflow

```bash
#!/bin/bash
# Full SSL/TLS audit
TARGET="${1:-localhost}"
PORT="${2:-443}"
REPORT_DIR="/var/log/ssl-audits"
DATE=$(date +%Y%m%d-%H%M%S)
REPORT="${REPORT_DIR}/ssl-audit-${TARGET}-${DATE}.txt"
mkdir -p "$REPORT_DIR"

echo "=== SSL/TLS Audit Report ===" | tee "$REPORT"
echo "Target: ${TARGET}:${PORT}" | tee -a "$REPORT"
echo "Date: $(date)" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# Certificate info
echo "--- Certificate Details ---" | tee -a "$REPORT"
echo | openssl s_client -connect "${TARGET}:${PORT}" -servername "$TARGET" 2>/dev/null | \
  openssl x509 -noout -subject -issuer -dates -fingerprint -sha256 -ext subjectAltName 2>/dev/null | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# Protocol versions
echo "--- Protocol Support ---" | tee -a "$REPORT"
for proto in -tls1_3 -tls1_2 -tls1_1 -tls1; do
  result=$(echo | openssl s_client -connect "${TARGET}:${PORT}" -servername "$TARGET" $proto 2>&1)
  if echo "$result" | grep -q "Cipher is" && ! echo "$result" | grep -q "Cipher is (NONE)"; then
    echo "$proto: SUPPORTED" | tee -a "$REPORT"
  else
    echo "$proto: NOT SUPPORTED" | tee -a "$REPORT"
  fi
done
echo "" | tee -a "$REPORT"

# Cipher suite
echo "--- Negotiated Cipher ---" | tee -a "$REPORT"
echo | openssl s_client -connect "${TARGET}:${PORT}" -servername "$TARGET" 2>/dev/null | grep -E "(Cipher|Protocol)" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# Compression
echo "--- Compression ---" | tee -a "$REPORT"
echo | openssl s_client -connect "${TARGET}:${PORT}" -servername "$TARGET" 2>/dev/null | grep "Compression" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# Expiration check
echo "--- Expiration Status ---" | tee -a "$REPORT"
if echo | openssl s_client -connect "${TARGET}:${PORT}" -servername "$TARGET" 2>/dev/null | openssl x509 -noout -checkend 2592000 2>/dev/null; then
  echo "Certificate valid for > 30 days" | tee -a "$REPORT"
else
  echo "WARNING: Certificate expires within 30 days or is expired" | tee -a "$REPORT"
fi
echo "" | tee -a "$REPORT"

# HSTS
echo "--- HSTS ---" | tee -a "$REPORT"
curl -sI "https://${TARGET}" 2>/dev/null | grep -i "strict-transport-security" | tee -a "$REPORT"

echo "" | tee -a "$REPORT"
echo "=== Audit Complete ===" | tee -a "$REPORT"
echo "Report: $REPORT"
```

---

## 10. Automated Certificate Expiration Monitoring

```bash
# Cron job for daily certificate monitoring
# /etc/cron.d/cert-monitor
0 8 * * * root /opt/claudeos/scripts/cert-check.sh >> /var/log/ssl-audits/cert-monitor.log 2>&1

# Alert script
#!/bin/bash
HOSTS_FILE="/etc/claudeos/ssl-hosts.txt"
WARN_DAYS=30

while read -r host; do
  [ -z "$host" ] || [[ "$host" == \#* ]] && continue
  expiry=$(echo | openssl s_client -connect "$host" -servername "${host%%:*}" 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
  if [ -n "$expiry" ]; then
    if ! echo | openssl s_client -connect "$host" -servername "${host%%:*}" 2>/dev/null | openssl x509 -noout -checkend $((WARN_DAYS * 86400)) 2>/dev/null; then
      echo "ALERT: Certificate for $host expires soon ($expiry)" | \
        mail -s "Certificate Expiration Warning" admin@example.com
    fi
  fi
done < "$HOSTS_FILE"
```
