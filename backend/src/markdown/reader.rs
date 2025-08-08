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


