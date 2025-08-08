# Blog Backend - Local Development Guide

This guide explains how to run and test the blog backend locally without Docker or Keycloak.

## 🚀 Quick Start

### 1. Run the Server
```bash
# Basic run (admin endpoints will require JWT tokens)
cargo run

# Local development mode (bypasses JWT validation)
LOCAL_DEV=1 cargo run
```

### 2. Test Endpoints
```bash
./test_endpoints.sh
```

## 📋 Available Endpoints

### Public Endpoints (No Authentication Required)
- `GET /health` - Server health check
- `GET /posts` - List all posts
- `GET /posts/:slug` - Get specific post as HTML
- `POST /preview` - Preview markdown as HTML

### Admin Endpoints (Require Authentication)
- `POST /admin/new` - Create new post
- `PUT /admin/edit/:slug` - Edit existing post

## 🔧 Local Development Mode

When you set `LOCAL_DEV=1`, the server bypasses JWT validation and allows admin operations without authentication.

### Example Usage:
```bash
# Start server in local dev mode
LOCAL_DEV=1 cargo run

# In another terminal, test admin endpoints
curl -X POST http://localhost:8000/admin/new \
  -H "Content-Type: application/json" \
  -d '{"title": "Test Post", "content": "# Test\n\nThis is a test post."}'
```

## 📁 Project Structure

```
backend/
├── src/
│   ├── main.rs          # Main server and routes
│   ├── auth/            # JWT authentication
│   ├── markdown/        # Markdown reading/writing
│   └── utils.rs         # Utility functions
├── posts/               # Markdown post files
├── posts.json           # Post metadata
└── test_endpoints.sh    # Basic endpoint testing
```

## 🔍 Current Status

### ✅ Working Features
- Server startup and health checks
- Post listing and retrieval
- Markdown to HTML conversion
- Post creation and editing (in LOCAL_DEV mode)
- Error handling for missing posts
- CORS support for frontend integration

### 🔧 Known Issues
- JWT authentication uses placeholder public key
- `reqwest` dependency commented out (needed for Keycloak integration)
- No frontend templates being served
- Hardcoded author name in post creation

## 🛠️ Development Tips

1. **Use LOCAL_DEV mode** for testing admin functionality
2. **Check logs** - the server prints detailed information about requests
3. **Test with curl** - all endpoints can be tested with curl commands
4. **Monitor posts.json** - this file is updated when posts are created/edited
5. **Check posts/ directory** - markdown files are stored here

## 🚨 Troubleshooting

### Server won't start
- Check if port 8000 is available
- Ensure all dependencies are installed: `cargo check`

### Admin endpoints fail
- Use `LOCAL_DEV=1` for local testing
- In production, you'll need valid JWT tokens from Keycloak

### Posts not found
- Check that markdown files exist in `posts/` directory
- Verify `posts.json` contains correct metadata
