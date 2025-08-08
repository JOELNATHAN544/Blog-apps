use std::fs;
use std::path::Path;
use anyhow::{Result, Context};
// Removed unused import
use crate::markdown::Post;

const POSTS_DIR: &str = "posts";

/// Write markdown content to a file
pub fn write_markdown_file(slug: &str, content: &str) -> Result<()> {
    let posts_dir = Path::new(POSTS_DIR);
    
    // Create posts directory if it doesn't exist
    if !posts_dir.exists() {
        fs::create_dir_all(posts_dir)
            .context("Failed to create posts directory")?;
    }
    
    let file_path = posts_dir.join(format!("{}.md", slug));
    
    fs::write(&file_path, content)
        .context(format!("Failed to write markdown file: {}", file_path.display()))?;
    
    Ok(())
}

/// Create a new post
pub fn create_post(post: &Post) -> Result<()> {
    // Write markdown file
    write_markdown_file(&post.slug, &post.content)?;
    
    // Update posts.json
    update_posts_json(post, true)?;
    
    Ok(())
}

/// Update an existing post
pub fn update_post(post: &Post) -> Result<()> {
    // Write markdown file
    write_markdown_file(&post.slug, &post.content)?;
    
    // Update posts.json
    update_posts_json(post, false)?;
    
    Ok(())
}

/// Update posts.json with new or updated post
fn update_posts_json(post: &Post, is_new: bool) -> Result<()> {
    let posts_file = Path::new("posts.json");
    
    // Read existing posts
    let mut posts: Vec<Post> = if posts_file.exists() {
        let content = fs::read_to_string(posts_file)
            .context("Failed to read posts.json")?;
        serde_json::from_str(&content)
            .context("Failed to parse posts.json")?
    } else {
        vec![]
    };
    
    if is_new {
        // Add new post
        posts.push(post.clone());
    } else {
        // Update existing post
        if let Some(existing_post) = posts.iter_mut().find(|p| p.slug == post.slug) {
            *existing_post = post.clone();
        }
    }
    
    // Write back to file
    let content = serde_json::to_string_pretty(&posts)
        .context("Failed to serialize posts")?;
    fs::write(posts_file, content)
        .context("Failed to write posts.json")?;
    
    Ok(())
}

/// Delete a post
pub fn delete_post(slug: &str) -> Result<()> {
    // Delete markdown file
    let file_path = Path::new(POSTS_DIR).join(format!("{}.md", slug));
    if file_path.exists() {
        fs::remove_file(&file_path)
            .context(format!("Failed to delete markdown file: {}", file_path.display()))?;
    }
    
    // Update posts.json
    remove_post_from_json(slug)?;
    
    Ok(())
}

/// Remove post from posts.json
fn remove_post_from_json(slug: &str) -> Result<()> {
    let posts_file = Path::new("posts.json");
    
    // Read existing posts
    let mut posts: Vec<Post> = if posts_file.exists() {
        let content = fs::read_to_string(posts_file)
            .context("Failed to read posts.json")?;
        serde_json::from_str(&content)
            .context("Failed to parse posts.json")?
    } else {
        return Ok(());
    };
    
    // Remove post with matching slug
    posts.retain(|post| post.slug != slug);
    
    // Write back to file
    let content = serde_json::to_string_pretty(&posts)
        .context("Failed to serialize posts")?;
    fs::write(posts_file, content)
        .context("Failed to write posts.json")?;
    
    Ok(())
}
