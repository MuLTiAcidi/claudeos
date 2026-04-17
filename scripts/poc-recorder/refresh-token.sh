#!/bin/bash
# Refresh Cognito token using refresh_token
REFRESH_TOKEN="$1"
CLIENT_ID="${2:-11bj9db2kd9sfoi5c17riopfis}"

RESP=$(curl -s -X POST "https://cognito-idp.sa-east-1.amazonaws.com/" \
    -H "X-Amz-Target: AWSCognitoIdentityProviderService.InitiateAuth" \
    -H "Content-Type: application/x-amz-json-1.1" \
    -d "{\"AuthFlow\":\"REFRESH_TOKEN_AUTH\",\"ClientId\":\"$CLIENT_ID\",\"AuthParameters\":{\"REFRESH_TOKEN\":\"$REFRESH_TOKEN\"}}")

TOKEN=$(echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('AuthenticationResult',{}).get('AccessToken','FAILED'))" 2>/dev/null)

if [ "$TOKEN" != "FAILED" ] && [ -n "$TOKEN" ]; then
    echo "$TOKEN" > /opt/claudeos-hunt/tokens/current.txt
    echo "Token refreshed: $(echo $TOKEN | head -c 30)..."
else
    echo "REFRESH FAILED: $RESP"
fi
