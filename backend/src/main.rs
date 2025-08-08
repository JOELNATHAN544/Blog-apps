use axum::{
    routing::{get, post, put, delete},
    http::StatusCode,
    Json, Router, extract::{Path, Query},
    response::Html,
    http::Method,
    middleware,
    response::Response,
    http::Uri,
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
        .route("/", get(serve_index))
        .route("/admin/new", get(serve_new_post))
        .route("/admin/edit/:slug", get(serve_edit_post))
        .route("/static/:file", get(serve_static))
        .route("/auth/callback", get(handle_oauth_callback))
        .route("/posts/html", get(serve_posts_html))
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
    
    // Try to get post data first
    match crate::markdown::reader::read_post(&slug) {
        Ok(post) => {
            // Read the post template
            match std::fs::read_to_string("../frontend/templates/post.html") {
                Ok(mut template) => {
                    // Simple template replacement
                    template = template.replace("{{ title }}", &post.title);
                    template = template.replace("{{ author }}", &post.author);
                    template = template.replace("{{ created_at }}", &post.created_at.format("%B %d, %Y").to_string());
                    template = template.replace("{{ updated_at }}", &post.updated_at.format("%B %d, %Y").to_string());
                    
                    // Get the rendered content
                    match crate::markdown::reader::read_and_render_markdown(&slug) {
                        Ok(html_content) => {
                            template = template.replace("{{ content | safe }}", &html_content);
                            println!("✅ Successfully rendered post: {}", slug);
                            Ok(Html(template))
                        }
                        Err(_) => {
                            template = template.replace("{{ content | safe }}", "<p>Error loading content.</p>");
                            Ok(Html(template))
                        }
                    }
                }
                Err(_) => {
                    // Fallback to simple HTML if template not found
                    match crate::markdown::reader::read_and_render_markdown(&slug) {
                        Ok(html_content) => {
                            let simple_html = format!(
                                "<!DOCTYPE html><html><head><title>{}</title></head><body><h1>{}</h1><div>{}</div></body></html>",
                                post.title, post.title, html_content
                            );
                            Ok(Html(simple_html))
                        }
                        Err(_) => {
                            Ok(Html("<h1>Post not found</h1><p>The requested post could not be found.</p>".to_string()))
                        }
                    }
                }
            }
        }
        Err(_) => {
            println!("❌ Failed to find post: {}", slug);
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

// Template serving functions
async fn serve_index() -> Html<String> {
    match std::fs::read_to_string("../frontend/templates/index.html") {
        Ok(content) => Html(content),
        Err(_) => Html("<h1>Error</h1><p>Could not load index template.</p>".to_string())
    }
}

async fn serve_new_post() -> Html<String> {
    match std::fs::read_to_string("../frontend/templates/admin/new.html") {
        Ok(content) => Html(content),
        Err(_) => Html("<h1>Error</h1><p>Could not load new post template.</p>".to_string())
    }
}

async fn serve_edit_post(Path(slug): Path<String>) -> Html<String> {
    // First try to get the existing post data
    match crate::markdown::reader::read_post(&slug) {
        Ok(post) => {
            // Read the template
            match std::fs::read_to_string("../frontend/templates/admin/edit.html") {
                Ok(mut template) => {
                    // Simple template replacement (in a real app, use a proper templating engine)
                    template = template.replace("{{ slug }}", &slug);
                    template = template.replace("{{ title }}", &post.title);
                    template = template.replace("{{ content }}", &post.content);
                    Html(template)
                }
                Err(_) => Html("<h1>Error</h1><p>Could not load edit template.</p>".to_string())
            }
        }
        Err(_) => Html("<h1>Error</h1><p>Post not found.</p>".to_string())
    }
}

async fn serve_static(Path(file): Path<String>) -> Result<Response, StatusCode> {
    let file_path = format!("../frontend/static/{}", file);
    
    match std::fs::read(&file_path) {
        Ok(content) => {
            let content_type = if file.ends_with(".css") {
                "text/css"
            } else if file.ends_with(".js") {
                "application/javascript"
            } else {
                "text/plain"
            };
            
            let response = Response::builder()
                .header("Content-Type", content_type)
                .body(axum::body::Body::from(content))
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            
            Ok(response)
        }
        Err(_) => Err(StatusCode::NOT_FOUND)
    }
}

// OAuth callback handler
async fn handle_oauth_callback(
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Result<Response, StatusCode> {
    let code = params.get("code").ok_or(StatusCode::BAD_REQUEST)?;
    let state = params.get("state").ok_or(StatusCode::BAD_REQUEST)?;
    
    // For now, we'll use a test token since we don't have the full OAuth flow implemented
    // In a real implementation, you would exchange the code for a token with Keycloak
    let test_token = crate::auth::jwt::test_token::generate_test_token();
    
    // Create a simple HTML page that sets the token and redirects
    let html = format!(
        r#"
<!DOCTYPE html>
<html>
<head>
    <title>Authentication Success</title>
</head>
<body>
    <script>
        // Store the token
        localStorage.setItem('auth_token', '{}');
        localStorage.setItem('user_info', JSON.stringify({{
            sub: 'keycloak-user',
            roles: ['author']
        }}));
        
        // Redirect back to the main page
        window.location.href = '/';
    </script>
    <p>Authentication successful! Redirecting...</p>
</body>
</html>
        "#,
        test_token
    );
    
    let response = Response::builder()
        .header("Content-Type", "text/html")
        .body(axum::body::Body::from(html))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    Ok(response)
}

// Serve posts as HTML for HTMX
async fn serve_posts_html() -> Html<String> {
    match std::fs::read_to_string("posts.json") {
        Ok(content) => {
            match serde_json::from_str::<Vec<crate::markdown::Post>>(&content) {
                Ok(posts) => {
                    let mut html = String::new();
                    
                    if posts.is_empty() {
                        html.push_str("<p class='no-posts'>No posts available yet.</p>");
                    } else {
                        for post in posts {
                            let date = post.created_at.format("%B %d, %Y").to_string();
                            
                            html.push_str(&format!(
                                r#"
<article class="post-card">
    <div class="post-header">
        <h3 class="post-title">
            <a href="/posts/{}" class="post-link">{}</a>
        </h3>
        <div class="post-meta">
            <span class="post-author">By {}</span>
            <span class="post-date">{}</span>
        </div>
    </div>
    <div class="post-actions">
        <a href="/posts/{}" class="btn btn-primary">Read More</a>
        <button onclick="editPost('{}')" class="btn btn-secondary">Edit</button>
    </div>
</article>
                                "#,
                                post.slug, post.title, post.author, date, post.slug, post.slug
                            ));
                        }
                    }
                    
                    Html(html)
                }
                Err(_) => Html("<p class='no-posts'>Error loading posts.</p>".to_string())
            }
        }
        Err(_) => Html("<p class='no-posts'>Error loading posts.</p>".to_string())
    }
}
