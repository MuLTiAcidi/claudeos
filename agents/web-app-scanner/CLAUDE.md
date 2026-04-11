# Web App Scanner Agent

OWASP Top 10 testing for hosted web applications. Performs automated and manual security testing using industry-standard tools.

## Safety Rules

- NEVER run scans against applications you do not own or have authorization to test
- NEVER use destructive payloads that could corrupt data or cause denial of service
- NEVER store or expose discovered credentials or sensitive data
- NEVER use sqlmap with --risk=3 or --level=5 in production without approval
- Always use rate limiting to avoid impacting application availability
- Log all scan activities for accountability
- Scope testing to authorized targets only

---

## 1. Nikto Web Server Scanner

### Install Nikto

```bash
sudo apt-get install -y nikto
# Or from source
cd /tmp && git clone https://github.com/sullo/nikto.git
```

### Run Scans

```bash
# Basic scan
nikto -h http://target.com

# Scan with SSL
nikto -h https://target.com -ssl

# Scan specific port
nikto -h http://target.com -p 8080

# Save output
nikto -h http://target.com -o /tmp/nikto-report.html -Format html

# Scan with authentication
nikto -h http://target.com -id admin:password

# Tuning options (select specific tests)
# 1=Files, 2=Misconfig, 3=Info, 4=Injection, 5=Fetch, 6=Deny, 7=Remote
nikto -h http://target.com -Tuning 1234

# Scan multiple hosts
nikto -h /tmp/hosts.txt

# Use specific user agent
nikto -h http://target.com -useragent "Mozilla/5.0"

# Evasion techniques
nikto -h http://target.com -evasion 1
```

---

## 2. SQL Injection Testing (sqlmap)

### Install sqlmap

```bash
sudo apt-get install -y sqlmap
# Or from source
cd /tmp && git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git
```

### Run SQL Injection Tests

```bash
# Test a URL parameter
sqlmap -u "http://target.com/page?id=1" --batch

# Test with POST data
sqlmap -u "http://target.com/login" --data="user=admin&pass=test" --batch

# Test with cookies
sqlmap -u "http://target.com/page?id=1" --cookie="session=abc123" --batch

# Enumerate databases (after finding injection)
sqlmap -u "http://target.com/page?id=1" --dbs --batch

# Test all parameters
sqlmap -u "http://target.com/page?id=1&name=test" -p "id,name" --batch

# Use specific injection technique
# B=Boolean, E=Error, U=Union, S=Stacked, T=Time, Q=Inline
sqlmap -u "http://target.com/page?id=1" --technique=BEU --batch

# Test with request file (from Burp/ZAP)
sqlmap -r /tmp/request.txt --batch

# Test with custom headers
sqlmap -u "http://target.com/api/data" --headers="Authorization: Bearer token123" --batch

# Risk and level (careful in production)
sqlmap -u "http://target.com/page?id=1" --risk=2 --level=3 --batch

# Output results
sqlmap -u "http://target.com/page?id=1" --batch --output-dir=/tmp/sqlmap-results
```

---

## 3. Directory and File Discovery

### Gobuster

```bash
# Install gobuster
sudo apt-get install -y gobuster

# Directory brute force
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt

# With file extensions
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt -x php,html,txt,bak,old

# Subdomain enumeration
gobuster dns -d target.com -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Virtual host discovery
gobuster vhost -u http://target.com -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# With authentication
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt -U admin -P password

# Filter by status code
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt -s "200,204,301,302,307"

# With custom headers
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt -H "Authorization: Bearer token"

# Rate limiting
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt --delay 100ms

# Output to file
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt -o /tmp/gobuster-results.txt
```

### Dirb

```bash
# Install dirb
sudo apt-get install -y dirb

# Basic directory scan
dirb http://target.com

# With custom wordlist
dirb http://target.com /usr/share/wordlists/dirb/big.txt

# With file extensions
dirb http://target.com -X .php,.html,.txt,.bak

# Save output
dirb http://target.com -o /tmp/dirb-results.txt

# With authentication
dirb http://target.com -u admin:password

# Non-recursive
dirb http://target.com -r
```

---

## 4. Fuzzing (wfuzz)

### Install and Use wfuzz

```bash
# Install wfuzz
sudo apt-get install -y wfuzz
# Or via pip
pip3 install wfuzz

# Fuzz URL parameters
wfuzz -c -z file,/usr/share/wordlists/dirb/common.txt --hc 404 http://target.com/FUZZ

# Fuzz POST parameters
wfuzz -c -z file,/usr/share/wordlists/rockyou.txt -d "user=admin&pass=FUZZ" --hc 401 http://target.com/login

# Fuzz with multiple payloads
wfuzz -c -z file,users.txt -z file,passwords.txt -d "user=FUZZ&pass=FUZ2Z" --hc 401 http://target.com/login

# Fuzz headers
wfuzz -c -z file,/usr/share/wordlists/dirb/common.txt -H "X-Custom: FUZZ" --hc 404 http://target.com/

# Fuzz subdomains
wfuzz -c -z file,/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.target.com" --hc 404 http://target.com/

# Filter results
wfuzz -c -z file,wordlist.txt --hc 404 --hl 0 --hw 10 http://target.com/FUZZ

# Rate limiting
wfuzz -c -z file,wordlist.txt -t 10 -s 0.1 http://target.com/FUZZ
```

---

## 5. HTTP Security Header Analysis

### Check Security Headers

```bash
# Check all security headers
check_headers() {
  local url="$1"
  echo "=== Security Headers for $url ==="
  
  headers=$(curl -sI -L "$url")
  
  # Required headers
  for header in "Strict-Transport-Security" "Content-Security-Policy" "X-Content-Type-Options" \
    "X-Frame-Options" "X-XSS-Protection" "Referrer-Policy" "Permissions-Policy" \
    "Cross-Origin-Opener-Policy" "Cross-Origin-Resource-Policy"; do
    value=$(echo "$headers" | grep -i "^${header}:" | head -1)
    if [ -n "$value" ]; then
      echo "[PASS] $value"
    else
      echo "[FAIL] $header: MISSING"
    fi
  done
  
  # Check for information disclosure headers
  for header in "Server" "X-Powered-By" "X-AspNet-Version" "X-AspNetMvc-Version"; do
    value=$(echo "$headers" | grep -i "^${header}:" | head -1)
    if [ -n "$value" ]; then
      echo "[WARN] Information disclosure: $value"
    fi
  done
}

check_headers "https://target.com"
```

### Check Cookie Security

```bash
# Check cookie attributes
curl -sI -L "https://target.com" | grep -i "^set-cookie:" | while read -r line; do
  echo "Cookie: $line"
  echo "$line" | grep -qi "secure" || echo "  [FAIL] Missing Secure flag"
  echo "$line" | grep -qi "httponly" || echo "  [FAIL] Missing HttpOnly flag"
  echo "$line" | grep -qi "samesite" || echo "  [WARN] Missing SameSite attribute"
done
```

---

## 6. SSL/TLS Quick Checks

```bash
# Check SSL certificate
echo | openssl s_client -connect target.com:443 -servername target.com 2>/dev/null | openssl x509 -noout -dates -subject -issuer

# Check for weak ciphers
nmap --script ssl-enum-ciphers -p 443 target.com

# Check for SSL vulnerabilities
nmap --script ssl-heartbleed,ssl-poodle,ssl-ccs-injection -p 443 target.com

# Check HSTS preload status
curl -sI "https://target.com" | grep -i "strict-transport-security"
```

---

## 7. OWASP Top 10 Manual Tests

### A01 - Broken Access Control

```bash
# Test IDOR (Insecure Direct Object Reference)
for id in $(seq 1 100); do
  status=$(curl -s -o /dev/null -w "%{http_code}" "http://target.com/api/user/$id" -H "Cookie: session=USER_SESSION")
  [ "$status" = "200" ] && echo "Accessible: /api/user/$id"
done

# Test path traversal
for payload in "../etc/passwd" "....//etc/passwd" "..%2f..%2fetc%2fpasswd" "%2e%2e%2fetc%2fpasswd"; do
  response=$(curl -s "http://target.com/file?name=$payload")
  echo "$response" | grep -q "root:" && echo "VULNERABLE: Path traversal with $payload"
done

# Test forced browsing
for path in admin administrator backup config database debug test; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "http://target.com/$path")
  [ "$status" != "404" ] && echo "Found: /$path (HTTP $status)"
done
```

### A02 - Cryptographic Failures

```bash
# Check for sensitive data in responses
curl -s "http://target.com/api/users" | python3 -c "
import sys,json,re
data = sys.stdin.read()
patterns = {
  'SSN': r'\b\d{3}-\d{2}-\d{4}\b',
  'Credit Card': r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
  'Email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
  'API Key': r'(?i)(api[_-]?key|apikey|api_secret)\s*[:=]\s*\S+'
}
for name, pattern in patterns.items():
  matches = re.findall(pattern, data)
  if matches: print(f'FOUND {name}: {len(matches)} instances')
"

# Check if HTTP is redirected to HTTPS
curl -sI "http://target.com" | head -5
```

### A03 - Injection

```bash
# XSS testing payloads
XSS_PAYLOADS=(
  '<script>alert(1)</script>'
  '"><img src=x onerror=alert(1)>'
  "javascript:alert(1)"
  '<svg onload=alert(1)>'
)
for payload in "${XSS_PAYLOADS[@]}"; do
  encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))")
  response=$(curl -s "http://target.com/search?q=$encoded")
  echo "$response" | grep -q "$payload" && echo "POTENTIAL XSS: $payload reflected"
done

# Command injection testing
CMD_PAYLOADS=(
  "; id"
  "| id"
  "\$(id)"
  "\`id\`"
)
for payload in "${CMD_PAYLOADS[@]}"; do
  response=$(curl -s "http://target.com/ping?host=127.0.0.1${payload}")
  echo "$response" | grep -q "uid=" && echo "COMMAND INJECTION: $payload"
done
```

### A05 - Security Misconfiguration

```bash
# Check for default pages/configs
for path in ".env" ".git/config" "wp-config.php.bak" "config.php.bak" ".htaccess" \
  "robots.txt" "sitemap.xml" "server-status" "server-info" "phpinfo.php" \
  ".DS_Store" "web.config" "crossdomain.xml"; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "http://target.com/$path")
  [ "$status" = "200" ] && echo "EXPOSED: /$path"
done

# Check for directory listing
for dir in images uploads files css js assets backup; do
  response=$(curl -s "http://target.com/$dir/")
  echo "$response" | grep -qi "index of\|directory listing" && echo "DIR LISTING: /$dir/"
done

# Check HTTP methods
curl -s -X OPTIONS "http://target.com/" -I | grep -i "allow:"

# Check for CORS misconfiguration
curl -s -H "Origin: https://evil.com" -I "http://target.com/api/" | grep -i "access-control"
```

### A07 - Identification and Authentication Failures

```bash
# Test for username enumeration
for user in admin administrator root test user guest; do
  response=$(curl -s -d "username=$user&password=wrong" "http://target.com/login")
  echo "$user: $(echo $response | grep -oP '(invalid|incorrect|not found|unknown)[^"<]*' | head -1)"
done

# Test account lockout
for i in $(seq 1 20); do
  status=$(curl -s -o /dev/null -w "%{http_code}" -d "username=admin&password=wrong$i" "http://target.com/login")
  echo "Attempt $i: HTTP $status"
done

# Check for default credentials
DEFAULT_CREDS=("admin:admin" "admin:password" "admin:123456" "root:root" "test:test" "guest:guest")
for cred in "${DEFAULT_CREDS[@]}"; do
  user="${cred%%:*}"
  pass="${cred#*:}"
  status=$(curl -s -o /dev/null -w "%{http_code}" -d "username=$user&password=$pass" "http://target.com/login")
  [ "$status" = "302" ] || [ "$status" = "200" ] && echo "POSSIBLE DEFAULT CRED: $cred (HTTP $status)"
done
```

---

## 8. API Security Testing

```bash
# Test API without authentication
curl -s "http://target.com/api/v1/users" | head -20

# Test API with method tampering
for method in GET POST PUT DELETE PATCH OPTIONS; do
  status=$(curl -s -o /dev/null -w "%{http_code}" -X "$method" "http://target.com/api/v1/users")
  echo "$method: HTTP $status"
done

# Test for mass assignment
curl -s -X POST "http://target.com/api/v1/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"test123","role":"admin","is_admin":true}'

# Test rate limiting
for i in $(seq 1 50); do
  status=$(curl -s -o /dev/null -w "%{http_code}" "http://target.com/api/v1/data")
  echo "Request $i: HTTP $status"
done | sort | uniq -c | sort -rn

# Test for JSON injection
curl -s -X POST "http://target.com/api/v1/search" \
  -H "Content-Type: application/json" \
  -d '{"query":{"$gt":""}}'
```

---

## 9. Comprehensive Web App Scan Workflow

```bash
#!/bin/bash
# Full OWASP web application scan
TARGET="$1"
REPORT_DIR="/var/log/webapp-scans"
DATE=$(date +%Y%m%d-%H%M%S)
mkdir -p "$REPORT_DIR"

if [ -z "$TARGET" ]; then
  echo "Usage: $0 <target-url>"
  exit 1
fi

echo "=== Web Application Security Scan ===" | tee "${REPORT_DIR}/scan-${DATE}.txt"
echo "Target: $TARGET" | tee -a "${REPORT_DIR}/scan-${DATE}.txt"
echo "Date: $(date)" | tee -a "${REPORT_DIR}/scan-${DATE}.txt"
echo "" | tee -a "${REPORT_DIR}/scan-${DATE}.txt"

# 1. Security headers
echo "--- Security Headers ---" | tee -a "${REPORT_DIR}/scan-${DATE}.txt"
curl -sI -L "$TARGET" | tee -a "${REPORT_DIR}/scan-${DATE}.txt"
echo "" | tee -a "${REPORT_DIR}/scan-${DATE}.txt"

# 2. Nikto scan
echo "--- Nikto Scan ---" | tee -a "${REPORT_DIR}/scan-${DATE}.txt"
nikto -h "$TARGET" -maxtime 300 2>/dev/null | tee -a "${REPORT_DIR}/scan-${DATE}.txt"
echo "" | tee -a "${REPORT_DIR}/scan-${DATE}.txt"

# 3. Directory discovery
echo "--- Directory Discovery ---" | tee -a "${REPORT_DIR}/scan-${DATE}.txt"
gobuster dir -u "$TARGET" -w /usr/share/wordlists/dirb/common.txt -q 2>/dev/null | tee -a "${REPORT_DIR}/scan-${DATE}.txt"
echo "" | tee -a "${REPORT_DIR}/scan-${DATE}.txt"

# 4. Sensitive file check
echo "--- Sensitive Files ---" | tee -a "${REPORT_DIR}/scan-${DATE}.txt"
for path in .env .git/config robots.txt sitemap.xml phpinfo.php wp-config.php.bak; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}/${path}")
  [ "$status" = "200" ] && echo "FOUND: /${path}" | tee -a "${REPORT_DIR}/scan-${DATE}.txt"
done

echo "" | tee -a "${REPORT_DIR}/scan-${DATE}.txt"
echo "=== Scan Complete ===" | tee -a "${REPORT_DIR}/scan-${DATE}.txt"
echo "Report: ${REPORT_DIR}/scan-${DATE}.txt"
```
