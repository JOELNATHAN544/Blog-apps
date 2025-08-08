use std::fs;
use std::path::Path;
use anyhow::{Result, Context};

const POSTS_DIR: &str = "posts";

/// Read markdown content from a file
pub fn read_markdown_file(slug: &str) -> Result<String> {
    let file_path = Path::new(POSTS_DIR).join(format!("{}.md", slug));
    
    let content = fs::read_to_string(&file_path)
        .context(format!("Failed to read markdown file: {}", file_path.display()))?;
    
    Ok(content)
}

/// Convert markdown content to HTML
pub fn markdown_to_html(markdown: &str) -> String {
    markdown::to_html(markdown)
}

/// Read and convert markdown file to HTML
pub fn read_and_render_markdown(slug: &str) -> Result<String> {
    let markdown_content = read_markdown_file(slug)?;
    let html_content = markdown_to_html(&markdown_content);
    Ok(html_content)
}

/// Read post data from posts.json
pub fn read_post(slug: &str) -> Result<crate::markdown::Post> {
    let posts_content = fs::read_to_string("posts.json")
        .context("Failed to read posts.json")?;
    
    let posts: Vec<crate::markdown::Post> = serde_json::from_str(&posts_content)
        .context("Failed to parse posts.json")?;
    
    posts.into_iter()
        .find(|post| post.slug == slug)
        .ok_or_else(|| anyhow::anyhow!("Post not found: {}", slug))
}


