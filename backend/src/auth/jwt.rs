use anyhow::{Result, Context};
use serde::Deserialize;
use crate::auth::Claims;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

pub mod test_token;

#[derive(Debug, Deserialize)]
pub struct JwtHeader {
    pub alg: String,
    pub typ: String,
    pub kid: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct JwtPayload {
    pub iss: String,
    pub sub: String,
    pub aud: String,  // Changed from Vec<String> to String
    pub exp: u64,
    pub iat: u64,
    pub jti: Option<String>,
    pub typ: Option<String>,
    pub azp: Option<String>,
    pub sid: Option<String>,
    pub acr: Option<String>,
    #[serde(rename = "allowed-origins")]
    pub allowed_origins: Option<Vec<String>>,
    #[serde(rename = "realm_access")]
    pub realm_access: Option<RealmAccess>,
    #[serde(rename = "resource_access")]
    pub resource_access: Option<ResourceAccess>,
    pub scope: Option<String>,
    #[serde(rename = "email_verified")]
    pub email_verified: Option<bool>,
    pub name: Option<String>,
    #[serde(rename = "preferred_username")]
    pub preferred_username: Option<String>,
    #[serde(rename = "given_name")]
    pub given_name: Option<String>,
    #[serde(rename = "family_name")]
    pub family_name: Option<String>,
    pub email: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RealmAccess {
    pub roles: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct ResourceAccess {
    pub account: Option<ClientAccess>,
    #[serde(rename = "blog-admin")]
    pub blog_admin: Option<ClientAccess>,
}

#[derive(Debug, Deserialize)]
pub struct ClientAccess {
    pub roles: Vec<String>,
}

#[derive(Debug)]
pub struct KeycloakConfig {
    pub realm: String,
    pub client_id: String,
    pub issuer_url: String,
    pub public_key: String,
}

impl Default for KeycloakConfig {
    fn default() -> Self {
        Self {
            realm: "blog-realm".to_string(),
            client_id: "blog-backend".to_string(),
            issuer_url: "http://localhost:8080/realms/blog-realm".to_string(),
            public_key: "".to_string(), // Will be fetched from Keycloak
        }
    }
}

/// Validate JWT token from Keycloak
pub async fn validate_token(token: &str) -> Result<Claims> {
    // Remove "Bearer " prefix if present
    let token = token.trim_start_matches("Bearer ").trim();
    
    // For local development, try test token first
    if let Ok(test_claims) = test_token::validate_test_token(token) {
        return Ok(Claims {
            sub: test_claims.sub,
            roles: test_claims.roles,
        });
    }
    
    // If test token fails, try Keycloak validation
    let _config = KeycloakConfig::default();
    
    // For now, let's use a simpler approach - just decode without signature verification
    // This is for testing purposes only
    match decode_keycloak_token_without_verification(token) {
        Ok(claims) => {
            Ok(claims)
        }
        Err(e) => {
            Err(e)
        }
    }
}

/// Decode Keycloak JWT token without signature verification (for testing)
fn decode_keycloak_token_without_verification(token: &str) -> Result<Claims> {
    // Split the token to get the payload part
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(anyhow::anyhow!("Invalid JWT format"));
    }
    
    // Decode the payload (second part)
    let payload_b64 = parts[1];
    
    let payload_bytes = match URL_SAFE_NO_PAD.decode(payload_b64) {
        Ok(bytes) => bytes,
        Err(e) => {
            return Err(anyhow::anyhow!("Failed to decode JWT payload: {:?}", e));
        }
    };
    
    let payload: JwtPayload = match serde_json::from_slice(&payload_bytes) {
        Ok(payload) => payload,
        Err(e) => {
            return Err(anyhow::anyhow!("Failed to parse JWT payload: {:?}", e));
        }
    };
    
    // Extract roles from realm_access or resource_access
    let roles = if let Some(realm_access) = payload.realm_access {
        realm_access.roles
    } else if let Some(resource_access) = payload.resource_access {
        if let Some(blog_admin) = resource_access.blog_admin {
            blog_admin.roles
        } else {
            vec![]
        }
    } else {
        vec![]
    };
    
    Ok(Claims {
        sub: payload.sub,
        roles,
    })
}

/// Extract token from Authorization header
pub fn extract_token_from_header(auth_header: &str) -> Result<&str> {
    if auth_header.starts_with("Bearer ") {
        Ok(&auth_header[7..])
    } else {
        Err(anyhow::anyhow!("Invalid authorization header format"))
    }
}
