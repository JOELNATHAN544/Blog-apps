#!/bin/bash

echo "🔐 Getting JWT Token from Keycloak"
echo "==================================="

KEYCLOAK_URL="http://localhost:8080"
REALM="blog-realm"
CLIENT_ID="blog-backend"
USERNAME="admin"
PASSWORD="admin123"
KEYCLOAK
echo ""
echo "1. Checking if Keycloak is running..."
if curl -s "$KEYCLOAK_URL/realms/master" > /dev/null 2>&1; then
    echo "✅ Keycloak is running"
else
    echo "❌ Keycloak is not running"
    echo "Please start Keycloak first:"
    echo "  docker-compose up keycloak -d"
    echo "  ./setup-keycloak.sh"
    exit 1
fi

echo ""
echo "2. Getting JWT token..."
TOKEN_RESPONSE=$(curl -s -X POST "$KEYCLOAK_URL/realms/$REALM/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=$USERNAME&password=$PASSWORD&grant_type=password&client_id=$CLIENT_ID")

echo "Token Response:"
echo "$TOKEN_RESPONSE" | jq .

echo ""
echo "3. Extracting access token..."
ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token')

if [ "$ACCESS_TOKEN" = "null" ] || [ -z "$ACCESS_TOKEN" ]; then
    echo "❌ Failed to get access token"
    echo "Response: $TOKEN_RESPONSE"
    exit 1
fi

echo "✅ Access token obtained!"
echo ""
echo "4. Testing token with backend..."
curl -s -X POST "http://localhost:8000/admin/new" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -d '{
    "title": "Test with Real Token",
    "content": "# Test with Real Token\n\nThis post was created with a real JWT token from Keycloak!"
  }' | jq .

echo ""
echo "🎉 Token is working!"
echo ""
echo "📝 Use this token for testing:"
echo "Authorization: Bearer $ACCESS_TOKEN"

