use anyhow::{Result, Context, anyhow};
use jsonwebtoken::{decode, decode_header, encode, Algorithm, EncodingKey, Header, Validation, DecodingKey};
use serde::{Deserialize, Serialize};
use crate::auth::test_token;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub roles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: String,
    pub exp: usize,
    pub iat: usize,
    pub iss: String,
    pub aud: String,
    #[serde(rename = "realm_access")]
    pub realm_access: Option<RealmAccess>,
    #[serde(rename = "resource_access")]
    pub resource_access: Option<ResourceAccess>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealmAccess {
    pub roles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceAccess {
    #[serde(rename = "blog-client")]
    pub blog_client: Option<ClientAccess>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientAccess {
    pub roles: Vec<String>,
}


#[derive(Debug, Deserialize, Serialize)]
pub struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Jwk {
    kty: String,
    use_: Option<String>,
    kid: String,
    alg: String,
    n: String,
    e: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct JwtHeader {
    pub typ: String,
    pub alg: String,
    pub kid: Option<String>,
}

#[derive(Debug, Clone)]
pub struct KeycloakConfig {
    pub realm: String,
    pub client_id: String,
    pub issuer_url: String,
    pub jwks_uri: String,
}

impl Default for KeycloakConfig {
    fn default() -> Self {
        let issuer_url = "http://10.216.68.222:8080/realms/blog-realm".to_string();
        let jwks_uri = format!("{}/protocol/openid-connect/certs", issuer_url);
        
        Self {
            realm: "blog-realm".to_string(),
            client_id: "blog-client".to_string(),
            issuer_url,
            jwks_uri,
        }
    }
}

/// Validate JWT token from Keycloak
/// Create a new JWT token with the given claims
pub fn create_jwt(claims: &Claims) -> Result<String> {
    let secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| "your-256-bit-secret".to_string());
    let encoding_key = EncodingKey::from_secret(secret.as_bytes());
    
    let token = encode(&Header::default(), &claims, &encoding_key)
        .context("Failed to create JWT token")?;
    
    Ok(token)
}

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
    
    // Get Keycloak configuration
    let config = KeycloakConfig::default();
    
    // Decode and validate the token
    match decode_and_validate_token(token, &config).await {
        Ok(claims) => Ok(claims),
        Err(e) => Err(e)
    }
}

/// Decode and validate Keycloak JWT token
async fn decode_and_validate_token(token: &str, config: &KeycloakConfig) -> Result<Claims> {
    // Get the JWKS from Keycloak
    let client = reqwest::Client::new();
    let jwks: Jwks = client
        .get(&config.jwks_uri)
        .send()
        .await
        .context("Failed to fetch JWKS from Keycloak")?
        .json()
        .await
        .context("Failed to parse JWKS response")?;

    // Get the header to find the key ID (kid)
    let header = decode_header(token).context("Failed to decode token header")?;
    let kid = header.kid.ok_or_else(|| anyhow!("No 'kid' in token header"))?;

    // Find the matching key
    let jwk = jwks.keys
        .iter()
        .find(|k| k.kid == kid)
        .ok_or_else(|| anyhow!("No matching key found in JWKS for kid: {}", kid))?;

    // Create the decoding key
    let decoding_key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
        .context("Failed to create decoding key")?;

    // Configure validation
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[&config.issuer_url]);
    validation.set_audience(&[&config.client_id]);
    validation.validate_exp = true;
    validation.validate_nbf = true;

    // Decode and validate the token
    let token_data = decode::<TokenClaims>(token, &decoding_key, &validation)
        .context("Failed to decode token")?;

    // Extract roles from the token
    let roles = token_data.claims.realm_access
        .map(|ra| ra.roles)
        .unwrap_or_default();

    Ok(Claims {
        sub: token_data.claims.sub,
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
