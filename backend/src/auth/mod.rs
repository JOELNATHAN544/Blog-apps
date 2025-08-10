#![allow(warnings)]
use axum::{
    extract::Request,
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{Response, Json},
};
use serde::{Deserialize, Serialize};
use anyhow::Result;
use serde_json::json;

pub mod oauth;
pub mod jwt;
pub mod test_token;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub roles: Vec<String>,
}

/// Authentication middleware for Axum
pub async fn auth_middleware(
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    println!("Auth middleware called");
    
    // Extract Authorization header
    let auth_header = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "Missing Authorization header",
                "message": "Please provide a valid Bearer token"
            }))
        ))?;

    println!("Auth header found: {}", auth_header);

    // Extract and validate token
    let token = jwt::extract_token_from_header(auth_header)
        .map_err(|_| (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "Invalid Authorization header format",
                "message": "Please provide a valid Bearer token"
            }))
        ))?;

    println!("Token extracted successfully");

    let claims = jwt::validate_token(token)
        .await
        .map_err(|_| (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "Invalid or expired token",
                "message": "Please provide a valid Bearer token"
            }))
        ))?;

    println!("Token validated successfully. Roles: {:?}", claims.roles);

    // Check if user has author role
    if !claims.roles.contains(&"author".to_string()) {
        println!("User does not have author role");
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "Insufficient permissions",
                "message": "You need the 'author' role to access this endpoint"
            }))
        ));
    }

    println!("User has author role, proceeding with request");

    // Add claims to request extensions for use in handlers
    let mut request = request;
    request.extensions_mut().insert(claims);

    Ok(next.run(request).await)
}

/// Extract claims from request extensions
pub fn extract_claims(request: &Request) -> Option<&Claims> {
    let claims = request.extensions().get::<Claims>();
    if claims.is_some() {
        println!("Claims found in request extensions");
    } else {
        println!("No claims found in request extensions");
    }
    claims
}

/// Check if user has specific role
pub fn has_role(claims: &Claims, role: &str) -> bool {
    claims.roles.contains(&role.to_string())
}
