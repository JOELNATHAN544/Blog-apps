use axum::{
    routing::{get, post, put, delete},
    http::StatusCode,
    Json, Router, extract::Path,
    response::Html,
    http::Method,
    middleware,
};
use serde_json::json;
use std::net::SocketAddr;
use tower_http::cors::{CorsLayer, Any};
use tower_http::trace::TraceLayer;
use std::env;

mod auth;
mod routes;
mod markdown;
mod utils;

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    println!("🚀 Starting blog backend server with Axum and Keycloak auth...");

    // Get port from environment or use default
    let port = env::var("BLOG_SERVICE_PORT")
        .unwrap_or_else(|_| "8000".to_string())
        .parse::<u16>()
        .unwrap_or(8000);

    // Create CORS layer
    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::PUT])
        .allow_headers(Any)
        .allow_origin(Any);

    // Build our application with routes
    let app = Router::new()
        .route("/health", get(health_check))
        .route("/test-token", get(get_test_token))
        .route("/posts", get(list_posts))
        .route("/posts/:slug", get(get_post))
        .route("/preview", post(preview_markdown))
        .nest("/admin", Router::new()
            .route("/new", post(create_post))
            .route("/edit/:slug", put(edit_post))
            .route("/delete/:slug", delete(delete_post))
            .layer(middleware::from_fn(auth::auth_middleware))
        )
        .layer(TraceLayer::new_for_http())
        .layer(cors);

    // Run it
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    println!("🌐 Listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn health_check() -> Json<serde_json::Value> {
    Json(json!({
        "status": "ok",
        "message": "Blog backend is running with Axum and Keycloak auth",
        "port": env::var("BLOG_SERVICE_PORT").unwrap_or_else(|_| "8000".to_string())
    }))
}

async fn get_test_token() -> Json<serde_json::Value> {
    let token = crate::auth::jwt::test_token::generate_test_token();
    Json(json!({
        "token": token,
        "message": "Use this token for testing protected endpoints"
    }))
}

async fn list_posts() -> Json<serde_json::Value> {
    match std::fs::read_to_string("posts.json") {
        Ok(content) => {
            match serde_json::from_str::<Vec<crate::markdown::Post>>(&content) {
                Ok(posts) => {
                    let post_summaries: Vec<serde_json::Value> = posts
                        .iter()
                        .map(|post| json!({
                            "slug": post.slug,
                            "title": post.title,
                            "author": post.author,
                            "created_at": post.created_at,
                            "updated_at": post.updated_at
                        }))
                        .collect();
                    
                    Json(json!({
                        "success": true,
                        "posts": post_summaries
                    }))
                }
                Err(_) => Json(json!({
                    "success": false,
                    "error": "Failed to parse posts.json"
                }))
            }
        }
        Err(_) => Json(json!({
            "success": false,
            "error": "Failed to read posts.json"
        }))
    }
}

async fn get_post(Path(slug): Path<String>) -> Result<Html<String>, StatusCode> {
    println!("🔍 Attempting to get post with slug: {}", slug);
    
    match crate::markdown::reader::read_and_render_markdown(&slug) {
        Ok(html_content) => {
            println!("✅ Successfully rendered post: {}", slug);
            Ok(Html(html_content))
        }
        Err(e) => {
            println!("❌ Failed to render post {}: {:?}", slug, e);
            Ok(Html("<h1>Post not found</h1><p>The requested post could not be found.</p>".to_string()))
        }
    }
}

#[derive(serde::Deserialize)]
struct PreviewRequest {
    content: String,
}

async fn preview_markdown(Json(payload): Json<PreviewRequest>) -> Html<String> {
    let html_content = crate::markdown::reader::markdown_to_html(&payload.content);
    Html(html_content)
}

#[derive(serde::Deserialize)]
struct CreatePostRequest {
    title: String,
    content: String,
}

#[derive(serde::Serialize)]
struct AdminResponse {
    success: bool,
    message: String,
    slug: Option<String>,
}

async fn create_post(Json(payload): Json<CreatePostRequest>) -> Result<Json<AdminResponse>, StatusCode> {
    // Authentication is handled by middleware
    let slug = crate::utils::generate_unique_slug(&payload.title);
    
    // Get author from JWT claims - for now use a fallback
    // TODO: Extract from JWT claims when middleware is properly configured
    let author = "admin".to_string();
    
    // Create the post
    let post = crate::markdown::Post {
        slug: slug.clone(),
        title: payload.title,
        author,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        content: payload.content,
    };
    
    // Save the post
    match crate::markdown::writer::create_post(&post) {
        Ok(_) => {
            println!("✅ Post created successfully: {}", slug);
            Ok(Json(AdminResponse {
                success: true,
                message: "Post created successfully".to_string(),
                slug: Some(slug),
            }))
        }
        Err(e) => {
            println!("❌ Failed to create post: {:?}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[derive(serde::Deserialize)]
struct UpdatePostRequest {
    title: String,
    content: String,
}

async fn edit_post(
    Path(slug): Path<String>,
    Json(payload): Json<UpdatePostRequest>,
) -> Result<Json<AdminResponse>, StatusCode> {
    // Authentication is handled by middleware
    
    // Get author from JWT claims - for now use a fallback
    // TODO: Extract from JWT claims when middleware is properly configured
    let author = "admin".to_string();
    
    // Create the updated post
    let post = crate::markdown::Post {
        slug: slug.clone(),
        title: payload.title,
        author,
        created_at: chrono::Utc::now(), // TODO: Get from existing post
        updated_at: chrono::Utc::now(),
        content: payload.content,
    };
    
    // Update the post
    match crate::markdown::writer::update_post(&post) {
        Ok(_) => {
            println!("✅ Post updated successfully: {}", slug);
            Ok(Json(AdminResponse {
                success: true,
                message: "Post updated successfully".to_string(),
                slug: Some(slug),
            }))
        }
        Err(e) => {
            println!("❌ Failed to update post: {:?}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn delete_post(
    Path(slug): Path<String>,
) -> Result<Json<AdminResponse>, StatusCode> {
    // Authentication is handled by middleware
    
    match crate::markdown::writer::delete_post(&slug) {
        Ok(_) => {
            println!("✅ Post deleted successfully: {}", slug);
            Ok(Json(AdminResponse {
                success: true,
                message: "Post deleted successfully".to_string(),
                slug: Some(slug),
            }))
        }
        Err(e) => {
            println!("❌ Failed to delete post: {:?}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}
