#!/bin/bash

# Keycloak Setup Script for Blog Application
# This script automates the setup of Keycloak for the blog application

set -e

echo "🔐 Setting up Keycloak for Blog Application..."

# Wait for Keycloak to be ready
echo "⏳ Waiting for Keycloak to be ready..."
until curl -s http://localhost:8080/realms/master > /dev/null 2>&1; do
    echo "Waiting for Keycloak..."
    sleep 5
done

echo "✅ Keycloak is ready!"

# Get admin token
echo "🔑 Getting admin token..."
ADMIN_TOKEN=$(curl -s -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=admin&password=admin&grant_type=password&client_id=admin-cli" \
    http://localhost:8080/realms/master/protocol/openid-connect/token | \
    jq -r '.access_token')

if [ "$ADMIN_TOKEN" = "null" ] || [ -z "$ADMIN_TOKEN" ]; then
    echo "❌ Failed to get admin token"
    exit 1
fi

echo "✅ Admin token obtained"

# Create realm
echo "🏰 Creating blog-realm..."
curl -s -X POST \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "realm": "blog-realm",
        "enabled": true,
        "displayName": "Blog Realm"
    }' \
    http://localhost:8080/admin/realms

echo "✅ Realm created"

# Create client
echo "🔧 Creating blog-client..."

# First, check if client exists
CLIENT_ID=$(curl -s \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    http://localhost:8080/admin/realms/blog-realm/clients | \
    jq -r '.[] | select(.clientId == "blog-client") | .id')

if [ -z "$CLIENT_ID" ]; then
    # Client doesn't exist, create it
    CLIENT_ID=$(curl -s -X POST \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "clientId": "blog-client",
            "enabled": true,
            "publicClient": false,
            "standardFlowEnabled": true,
            "directAccessGrantsEnabled": true,
            "serviceAccountsEnabled": true,
            "redirectUris": [
                "http://10.216.68.222/*",
                "http://10.216.68.222/auth/callback"
            ],
            "webOrigins": ["http://10.216.68.222"],
            "baseUrl": "http://10.216.68.222",
            "adminUrl": "http://10.216.68.222",
            "bearerOnly": false,
            "consentRequired": false,
            "fullScopeAllowed": true
        }' \
        http://localhost:8080/admin/realms/blog-realm/clients | \
        jq -r '.id')
    
    echo "✅ Client created"
else
    echo "ℹ️  Client already exists, updating configuration..."
    
    # Update existing client configuration
    curl -s -X PUT \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "clientId": "blog-client",
            "enabled": true,
            "publicClient": false,
            "standardFlowEnabled": true,
            "directAccessGrantsEnabled": true,
            "serviceAccountsEnabled": true,
            "redirectUris": [
                "http://10.216.68.222/*",
                "http://10.216.68.222/auth/callback"
            ],
            "webOrigins": ["http://10.216.68.222"],
            "baseUrl": "http://10.216.68.222",
            "adminUrl": "http://10.216.68.222",
            "bearerOnly": false,
            "consentRequired": false,
            "fullScopeAllowed": true
        }' \
        http://localhost:8080/admin/realms/blog-realm/clients/$CLIENT_ID
    
    echo "✅ Client updated"
fi

echo "🔑 Client ID: $CLIENT_ID"

# Set the client secret to the provided value
echo "🔐 Setting client secret..."
curl -s -X PUT \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"type\": \"secret\", \"value\": \"BUzzw9pHNqFnPqPSwcIn1C9SzpZR5e90\"}" \
    http://localhost:8080/admin/realms/blog-realm/clients/$CLIENT_ID/client-secret

# Get the client secret (should match what we just set)
CLIENT_SECRET="BUzzw9pHNqFnPqPSwcIn1C9SzpZR5e90"

# Set the client authentication to client secret
curl -s -X PUT \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"clientAuthenticatorType": "client-secret"}' \
    http://localhost:8080/admin/realms/blog-realm/clients/$CLIENT_ID/client-secret/client-authenticator

echo "✅ Client secret created"

# Create roles
echo "👥 Creating roles..."
curl -s -X POST \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "author",
        "description": "Blog author"
    }' \
    http://localhost:8080/admin/realms/blog-realm/roles

curl -s -X POST \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "user",
        "description": "Blog user"
    }' \
    http://localhost:8080/admin/realms/blog-realm/roles

echo "✅ Roles created"

# Create user
echo "👤 Creating admin user..."
curl -s -X POST \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "username": "admin",
        "enabled": true,
        "email": "admin@blog.com",
        "firstName": "Admin",
        "lastName": "User",
        "credentials": [{
            "type": "password",
            "value": "admin123",
            "temporary": false
        }]
    }' \
    http://localhost:8080/admin/realms/blog-realm/users

echo "✅ Admin user created"

# Get user ID
USER_ID=$(curl -s \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    http://localhost:8080/admin/realms/blog-realm/users | \
    jq -r '.[] | select(.username == "admin") | .id')

# Get author role ID
AUTHOR_ROLE_ID=$(curl -s \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    http://localhost:8080/admin/realms/blog-realm/roles | \
    jq -r '.[] | select(.name == "author") | .id')

# Assign author role to user
echo "🔗 Assigning author role to user..."
curl -s -X POST \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d "[{\"id\":\"$AUTHOR_ROLE_ID\",\"name\":\"author\"}]" \
    http://localhost:8080/admin/realms/blog-realm/users/$USER_ID/role-mappings/realm

echo "✅ Author role assigned"

echo ""
echo "🎉 Keycloak setup completed!"
echo ""
echo "📋 Configuration Summary:"
echo "   Realm: blog-realm"
echo "   Client ID: blog-backend"
echo "   Client Secret: $CLIENT_SECRET"
echo "   Author User: admin"
echo "   Author Password: admin123"
echo ""
echo "🔗 Keycloak Admin Console: http://localhost:8080/admin"
echo "   Username: admin"
echo "   Password: admin"
echo ""
echo "🔗 Keycloak Login: http://localhost:8080/realms/blog-realm/protocol/openid-connect/auth"
echo "   Client ID: blog-backend"
echo "   Username: admin"
echo "   Password: admin123"
