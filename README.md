# Blog App

A modern blog application built with Rust, Keycloak authentication, and a responsive frontend.

## Features

- **Backend**: Rust + Axum framework
- **Authentication**: Keycloak integration
- **Frontend**: Modern HTML/CSS/JavaScript with HTMX
- **Storage**: Markdown files with JSON index
- **Admin Interface**: Create, edit, and delete posts (author role required)

## Architecture

```
Blog-app/
├── backend/          # Rust backend server
├── frontend/         # HTML templates and static assets
├── keycloak-config/  # Keycloak configuration
├── nginx/           # Reverse proxy configuration
└── docker-compose.yml
```

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Rust (for local development)

### Using Docker Compose

1. **Set up environment variables:**
   ```bash
   cp env.example .env
   # Edit .env with your preferred settings
   ```

2. **Start the services:**
   ```bash
   docker-compose up -d
   ```

3. **Access the application:**
   - Blog: http://localhost
   - Keycloak Admin: http://localhost:8080

### Local Development

1. **Start the backend:**
   ```bash
   cd backend
   cargo run
   ```

2. **Access the application:**
   - Blog: http://localhost:8000

## Frontend Features

### Main Page (`/`)
- Displays all blog posts in a responsive grid
- Login/logout functionality
- Admin controls for authors
- Markdown preview functionality

### Individual Post Pages (`/posts/:slug`)
- Full post display with markdown rendering
- Admin controls (edit/delete) for authors
- Responsive design

### Admin Interface

#### New Post (`/admin/new`)
- Create new blog posts
- Markdown editor with live preview
- Authentication required (author role)

#### Edit Post (`/admin/edit/:slug`)
- Edit existing posts
- Pre-populated with current content
- Authentication required (author role)

## API Endpoints

### Public Endpoints
- `GET /` - Main page
- `GET /posts` - List all posts (JSON)
- `GET /posts/:slug` - Get specific post (HTML)
- `GET /preview` - Preview markdown content
- `GET /static/:file` - Serve static files (CSS, JS)

### Protected Endpoints (Author role required)
- `POST /admin/new` - Create new post
- `PUT /admin/edit/:slug` - Update existing post
- `DELETE /admin/delete/:slug` - Delete post

### Authentication
- `GET /test-token` - Get test JWT token for development
- Login via Keycloak at `/auth/`

## Frontend Technologies

- **HTML5**: Semantic markup
- **CSS3**: Modern styling with gradients, animations, and responsive design
- **JavaScript**: Vanilla JS for authentication and interactions
- **HTMX**: Dynamic content loading without page refreshes
- **Markdown**: Content authoring with live preview

## Key Features

### Responsive Design
- Mobile-first approach
- Grid layout for posts
- Flexible navigation
- Touch-friendly buttons

### Authentication Integration
- Keycloak OAuth2/OIDC integration
- Role-based access control
- Secure token handling
- Automatic redirect handling

### Admin Interface
- Modal-based forms
- Live markdown preview
- Form validation
- Success/error feedback

### Modern UI/UX
- Clean, modern design
- Smooth animations
- Loading states
- Error handling
- Accessibility considerations

## Development

### Frontend Structure
```
frontend/
├── templates/
│   ├── index.html      # Main page
│   ├── post.html       # Individual post page
│   ├── preview.html    # Markdown preview
│   └── admin/
│       ├── new.html    # New post form
│       └── edit.html   # Edit post form
└── static/
    └── styles.css      # Main stylesheet
```

### Adding New Features

1. **New Pages**: Add HTML templates to `frontend/templates/`
2. **Styling**: Update `frontend/static/styles.css`
3. **Backend Routes**: Add routes in `backend/src/main.rs`
4. **Static Files**: Place in `frontend/static/`

### Testing

Test the application by:
1. Visiting http://localhost:8000
2. Clicking "Login" to authenticate
3. Creating new posts as an author
4. Editing existing posts
5. Testing responsive design on mobile

## Security

- JWT token validation
- Role-based access control
- CORS configuration
- Secure headers
- Input validation

## Deployment

The application is containerized and ready for deployment with Docker Compose. The nginx reverse proxy handles routing between the frontend and Keycloak authentication.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is open source and available under the MIT License.
