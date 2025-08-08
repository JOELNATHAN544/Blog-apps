use slug::slugify;
use std::fs;
use std::path::Path;

/// Generate a URL-friendly slug from a title
pub fn generate_slug(title: &str) -> String {
    slugify(title)
}

/// Check if a slug already exists
pub fn slug_exists(slug: &str) -> bool {
    let posts_file = Path::new("posts.json");
    if !posts_file.exists() {
        return false;
    }
    
    if let Ok(content) = fs::read_to_string(posts_file) {
        if let Ok(posts) = serde_json::from_str::<Vec<crate::markdown::Post>>(&content) {
            return posts.iter().any(|post| post.slug == slug);
        }
    }
    false
}

/// Generate a unique slug from a title
pub fn generate_unique_slug(title: &str) -> String {
    let mut slug = generate_slug(title);
    let mut counter = 1;
    
    while slug_exists(&slug) {
        slug = format!("{}-{}", generate_slug(title), counter);
        counter += 1;
    }
    
    slug
}
