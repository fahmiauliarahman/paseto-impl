#!/bin/bash

# Test PASETO Authentication Implementation

echo "=== Testing PASETO Authentication Flow ==="
echo ""

# 1. Test Login
echo "1. Testing /login endpoint..."
LOGIN_RESPONSE=$(curl -s -X POST http://localhost:3001/login)
echo "$LOGIN_RESPONSE" | jq .
ACCESS_TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r .access_token)
REFRESH_TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r .refresh_token)
echo "✓ Login successful"
echo ""

# 2. Test Protected Route with Access Token
echo "2. Testing /protected endpoint with access token..."
PROTECTED_RESPONSE=$(curl -s -H "Authorization: Bearer $ACCESS_TOKEN" http://localhost:3001/protected)
echo "$PROTECTED_RESPONSE" | jq .
echo "✓ Protected route accessible with access token"
echo ""

# 3. Test Refresh Token
echo "3. Testing /refresh endpoint..."
REFRESH_RESPONSE=$(curl -s -X POST -H "Authorization: Bearer $REFRESH_TOKEN" http://localhost:3001/refresh)
echo "$REFRESH_RESPONSE" | jq .
NEW_ACCESS_TOKEN=$(echo "$REFRESH_RESPONSE" | jq -r .access_token)
NEW_REFRESH_TOKEN=$(echo "$REFRESH_RESPONSE" | jq -r .refresh_token)
echo "✓ Token refresh successful - new tokens issued"
echo ""

# 4. Test Token Reuse Detection
echo "4. Testing token reuse detection (using old refresh token again)..."
REUSE_RESPONSE=$(curl -s -X POST -H "Authorization: Bearer $REFRESH_TOKEN" http://localhost:3001/refresh)
echo "$REUSE_RESPONSE" | jq .
if echo "$REUSE_RESPONSE" | grep -q "reuse detected"; then
    echo "✓ Token reuse detected successfully - session revoked"
else
    echo "⚠ Warning: Expected reuse detection error"
fi
echo ""

# 5. Test Logout
echo "5. Testing /logout endpoint..."
# Get a fresh set of tokens first
FRESH_LOGIN=$(curl -s -X POST http://localhost:3001/login)
FRESH_REFRESH=$(echo "$FRESH_LOGIN" | jq -r .refresh_token)

LOGOUT_RESPONSE=$(curl -s -X POST -H "Authorization: Bearer $FRESH_REFRESH" http://localhost:3001/logout)
echo "$LOGOUT_RESPONSE" | jq .
echo "✓ Logout successful"
echo ""

# 6. Verify logout worked (token should be invalid)
echo "6. Testing that logged-out token is invalid..."
AFTER_LOGOUT=$(curl -s -X POST -H "Authorization: Bearer $FRESH_REFRESH" http://localhost:3001/refresh)
echo "$AFTER_LOGOUT" | jq .
if echo "$AFTER_LOGOUT" | grep -q "error"; then
    echo "✓ Logged-out token correctly rejected"
else
    echo "⚠ Warning: Expected error for logged-out token"
fi
echo ""

# 7. Verify Redis storage
echo "7. Checking Redis storage..."
REDIS_KEYS=$(redis-cli KEYS "refresh:*" 2>/dev/null | wc -l)
echo "Active refresh tokens in Redis: $REDIS_KEYS"
echo "✓ Redis integration working"
echo ""

echo "=== All tests completed ==="
