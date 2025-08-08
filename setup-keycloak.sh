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
echo "🔧 Creating blog-backend client..."
curl -s -X POST \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "clientId": "blog-backend",
        "enabled": true,
        "publicClient": false,
        "standardFlowEnabled": true,
        "directAccessGrantsEnabled": true,
        "serviceAccountsEnabled": true,
        "redirectUris": ["http://localhost/*"],
        "webOrigins": ["http://localhost"]
    }' \
    http://localhost:8080/admin/realms/blog-realm/clients

echo "✅ Client created"

# Get client ID
CLIENT_ID=$(curl -s \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    http://localhost:8080/admin/realms/blog-realm/clients | \
    jq -r '.[] | select(.clientId == "blog-backend") | .id')

echo "🔑 Client ID: $CLIENT_ID"

# Create client secret
echo "🔐 Creating client secret..."
CLIENT_SECRET=$(curl -s -X POST \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    http://localhost:8080/admin/realms/blog-realm/clients/$CLIENT_ID/client-secret | \
    jq -r '.value')

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
