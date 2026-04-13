# API Parameter Bruter Agent

Brute force hidden API parameters on endpoints. When an API endpoint exists but returns errors for missing params, systematically discover parameter names using wordlists, error message analysis, framework fingerprinting, and content-type switching.

## Prerequisites

```bash
which curl || apt install -y curl
which jq || apt install -y jq
which ffuf || go install github.com/ffuf/ffuf/v2@latest
which arjun || pip3 install arjun
which python3 || apt install -y python3
```

## Phase 1: Endpoint Baseline

```bash
TARGET="https://target.com"
ENDPOINT="/api/v1/resource"

# Get baseline responses for comparison
# Empty request
curl -sk -X POST "$TARGET$ENDPOINT" -D- -o /tmp/baseline_empty.txt \
  -H "X-HackerOne-Research: $H1USER"

# With empty JSON
curl -sk -X POST "$TARGET$ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{}' -D- -o /tmp/baseline_json.txt

# With empty form
curl -sk -X POST "$TARGET$ENDPOINT" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d '' -D- -o /tmp/baseline_form.txt

# Record baseline status code and response size
BASELINE_CODE=$(head -1 /tmp/baseline_json.txt | awk '{print $2}')
BASELINE_SIZE=$(wc -c < /tmp/baseline_json.txt)
echo "Baseline: $BASELINE_CODE ($BASELINE_SIZE bytes)"
```

## Phase 2: Error Message Mining

```bash
# Extract parameter names from error messages
# Many frameworks leak expected parameter names in errors

# Common error patterns to grep for:
curl -sk -X POST "$TARGET$ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{}' | grep -oiP \
  '(?:missing|required|expected|invalid|unknown)\s+(?:parameter|field|property|key|value|argument)[:\s]+["'"'"']?(\w+)' \
  | sort -u

# Spring Boot pattern
curl -sk -X POST "$TARGET$ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{}' | grep -oP '"field"\s*:\s*"([^"]+)"' | sort -u

# Django/DRF pattern
curl -sk -X POST "$TARGET$ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{}' | jq 'keys[]' 2>/dev/null

# Rails pattern
curl -sk -X POST "$TARGET$ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{}' | grep -oP 'param is missing or the value is empty: (\w+)'

# GraphQL introspection for field names
curl -sk -X POST "$TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name fields { name } } } }"}' | \
  jq '.data.__schema.types[] | select(.fields != null) | .fields[].name' 2>/dev/null | sort -u

# Swagger/OpenAPI for parameter names
for DOC in "/swagger.json" "/api-docs" "/openapi.json" "/v2/api-docs" "/v3/api-docs"; do
  curl -sk "$TARGET$DOC" | jq '.paths' 2>/dev/null | head -50 && echo "FOUND: $DOC"
done
```

## Phase 3: Automated Parameter Discovery with Arjun

```bash
# Arjun — purpose-built parameter finder
# GET parameters
arjun -u "$TARGET$ENDPOINT" -m GET -t 10 --stable

# POST JSON parameters
arjun -u "$TARGET$ENDPOINT" -m POST -t 10 --stable -c "application/json"

# POST form parameters
arjun -u "$TARGET$ENDPOINT" -m POST -t 10 --stable

# With authentication
arjun -u "$TARGET$ENDPOINT" -m POST \
  --headers "Authorization: Bearer $TOKEN" \
  --headers "X-HackerOne-Research: $H1USER" \
  -t 10 --stable
```

## Phase 4: Wordlist-Based Brute Force

```bash
# Build a targeted wordlist based on framework
# Common parameter names across all frameworks
cat > /tmp/params_common.txt << 'WORDLIST'
id
user_id
userId
username
email
password
name
token
key
secret
api_key
apiKey
callback
redirect
url
next
return
ref
page
limit
offset
sort
order
filter
search
query
q
type
status
role
admin
debug
test
verbose
format
action
method
command
cmd
file
path
data
value
code
state
nonce
timestamp
signature
hash
WORDLIST

# Framework-specific additions
# Spring (Java) — camelCase
cat >> /tmp/params_common.txt << 'SPRING'
firstName
lastName
phoneNumber
accessToken
refreshToken
clientId
clientSecret
grantType
responseType
redirectUri
SPRING

# Django/Rails — snake_case
cat >> /tmp/params_common.txt << 'SNAKE'
first_name
last_name
phone_number
access_token
refresh_token
client_id
client_secret
grant_type
response_type
redirect_uri
created_at
updated_at
is_active
is_admin
SNAKE

# Brute force with curl
while read PARAM; do
  # JSON body
  CODE=$(curl -sk -X POST "$TARGET$ENDPOINT" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{\"$PARAM\":\"test\"}" \
    -o /dev/null -w "%{http_code}")
  SIZE=$(curl -sk -X POST "$TARGET$ENDPOINT" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{\"$PARAM\":\"test\"}" | wc -c)
  # Flag responses that differ from baseline
  [ "$CODE" != "$BASELINE_CODE" ] || [ "$SIZE" -ne "$BASELINE_SIZE" ] && \
    echo "HIT: $PARAM -> $CODE ($SIZE bytes)"
done < /tmp/params_common.txt
```

## Phase 5: ffuf-Based Parameter Fuzzing

```bash
# GET parameter fuzzing
ffuf -u "$TARGET${ENDPOINT}?FUZZ=test" \
  -w /tmp/params_common.txt \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-HackerOne-Research: $H1USER" \
  -mc all -fc 404 \
  -fs "$BASELINE_SIZE" \
  -o /tmp/ffuf_get.json

# POST JSON parameter fuzzing (using ffuf with raw body)
ffuf -u "$TARGET$ENDPOINT" \
  -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"FUZZ":"test"}' \
  -w /tmp/params_common.txt \
  -mc all -fc 404 \
  -fs "$BASELINE_SIZE" \
  -o /tmp/ffuf_post.json

# POST form parameter fuzzing
ffuf -u "$TARGET$ENDPOINT" \
  -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Bearer $TOKEN" \
  -d 'FUZZ=test' \
  -w /tmp/params_common.txt \
  -mc all -fc 404 \
  -fs "$BASELINE_SIZE" \
  -o /tmp/ffuf_form.json
```

## Phase 6: Content-Type Switching

```bash
# Some endpoints accept multiple content types and expose different params

PARAM="admin"
VALUE="true"

# JSON
curl -sk -X POST "$TARGET$ENDPOINT" \
  -H "Content-Type: application/json" \
  -d "{\"$PARAM\":\"$VALUE\"}" -D-

# URL-encoded form
curl -sk -X POST "$TARGET$ENDPOINT" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "$PARAM=$VALUE" -D-

# Multipart form
curl -sk -X POST "$TARGET$ENDPOINT" \
  -H "Content-Type: multipart/form-data" \
  -F "$PARAM=$VALUE" -D-

# XML
curl -sk -X POST "$TARGET$ENDPOINT" \
  -H "Content-Type: application/xml" \
  -d "<root><$PARAM>$VALUE</$PARAM></root>" -D-

# XML with JSON Content-Type header (parser confusion)
curl -sk -X POST "$TARGET$ENDPOINT" \
  -H "Content-Type: application/json" \
  -d "<root><$PARAM>$VALUE</$PARAM></root>" -D-
```

## Phase 7: Parameter Type Guessing

```bash
# Once a valid parameter is found, determine its type
PARAM="discovered_param"

# String
curl -sk -X POST "$TARGET$ENDPOINT" \
  -H "Content-Type: application/json" \
  -d "{\"$PARAM\":\"test\"}" | jq .

# Integer
curl -sk -X POST "$TARGET$ENDPOINT" \
  -H "Content-Type: application/json" \
  -d "{\"$PARAM\":1}" | jq .

# Boolean
curl -sk -X POST "$TARGET$ENDPOINT" \
  -H "Content-Type: application/json" \
  -d "{\"$PARAM\":true}" | jq .

# Array
curl -sk -X POST "$TARGET$ENDPOINT" \
  -H "Content-Type: application/json" \
  -d "{\"$PARAM\":[\"test\"]}" | jq .

# Null
curl -sk -X POST "$TARGET$ENDPOINT" \
  -H "Content-Type: application/json" \
  -d "{\"$PARAM\":null}" | jq .

# Object (nested)
curl -sk -X POST "$TARGET$ENDPOINT" \
  -H "Content-Type: application/json" \
  -d "{\"$PARAM\":{\"id\":1}}" | jq .

# Compare error messages to determine expected type
```

## Phase 8: Mass Assignment Detection

```bash
# Once you know valid params, try adding privileged ones
KNOWN_PARAMS='{"name":"test","email":"test@test.com"}'

# Add role/admin params alongside known ones
for PRIV in '"role":"admin"' '"is_admin":true' '"admin":true' \
  '"role":"superadmin"' '"permissions":["*"]' '"verified":true' \
  '"email_verified":true' '"active":true' '"approved":true'; do

  PAYLOAD=$(echo "$KNOWN_PARAMS" | sed "s/}/, $PRIV}/")
  RESPONSE=$(curl -sk -X POST "$TARGET$ENDPOINT" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "$PAYLOAD")
  echo "Tried: $PRIV"
  echo "Response: $RESPONSE" | head -3
  echo "---"
done
```

## Severity Classification

| Finding | Severity |
|---------|----------|
| Hidden admin/role parameter accepted (mass assignment) | Critical |
| Hidden debug/verbose parameter exposes internals | High |
| Undocumented parameters bypass access controls | High |
| Hidden filter/search params enable data enumeration | Medium |
| Undocumented pagination params expose extra records | Medium |
| Parameter names leaked in error messages | Low |
| Swagger/API docs publicly accessible | Low |

## Output Format

For each discovered parameter:
1. **Parameter Name**: The discovered parameter
2. **Endpoint**: URL and HTTP method
3. **Content-Type**: Which content type works
4. **Expected Type**: string/int/bool/array/object
5. **Discovery Method**: How it was found (error mining, brute force, Arjun)
6. **Behavior Change**: How the response differs when param is included
7. **Security Impact**: Does it bypass auth, expose data, or enable mass assignment?

## Rules

- Start with error message mining before brute forcing — it's faster and quieter
- Use authenticated requests when testing authenticated endpoints
- Keep request rate reasonable to avoid triggering WAF/bans
- Include X-HackerOne-Research header on all requests
- Document baseline responses for accurate comparison
- Test all content types — JSON-only endpoints often accept form data too
