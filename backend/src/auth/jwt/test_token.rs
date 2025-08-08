use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use chrono::{Utc, Duration};

#[derive(Debug, Serialize, Deserialize)]
pub struct TestClaims {
    pub sub: String,
    pub roles: Vec<String>,
    pub exp: i64,
    pub iat: i64,
}

/// Generate a test JWT token for local development
pub fn generate_test_token() -> String {
    let now = Utc::now();
    let exp = now + Duration::hours(1);
    
    let claims = TestClaims {
        sub: "admin".to_string(),
        roles: vec!["author".to_string()],
        exp: exp.timestamp(),
        iat: now.timestamp(),
    };
    
    let secret = "test-secret-key-for-local-development";
    let encoding_key = EncodingKey::from_secret(secret.as_ref());
    
    encode(&Header::default(), &claims, &encoding_key)
        .expect("Failed to generate test token")
}

/// Validate test token (for local development only)
pub fn validate_test_token(token: &str) -> Result<TestClaims, jsonwebtoken::errors::Error> {
    use jsonwebtoken::{decode, DecodingKey, Validation};
    
    let secret = "test-secret-key-for-local-development";
    let decoding_key = DecodingKey::from_secret(secret.as_ref());
    
    let token_data = decode::<TestClaims>(
        token,
        &decoding_key,
        &Validation::default(),
    )?;
    
    Ok(token_data.claims)
}

