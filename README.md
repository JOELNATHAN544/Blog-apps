# Project Architecture and Component Overview

## Key Project Components

### Keycloak
**Keycloak** is an open-source Identity and Access Management (IAM) solution. In our project, it functions as the central **Identity Provider**. Its primary role is to handle user authentication (login, registration) and authorization. The application delegates all identity-related tasks to Keycloak, freeing the blog service from having to manage user accounts, roles, or passwords itself. It is configured as the OAuth 2.0 and OpenID Connect (OIDC) server that issues JSON Web Tokens (JWTs) to authenticated users.

### Nginx
**Nginx** serves as a **reverse proxy** and web server in our setup. It is the public-facing entry point for all incoming web traffic. Its main functions are:
* **Request Routing:** It intelligently forwards requests to the correct internal service (either Keycloak for authentication or the blog service for content).
* **Security:** It hides the internal network topology from the public internet..

### Reverse Proxy
A **reverse proxy** is a server that sits in front of one or more web servers, forwarding client requests to them. In this project, Nginx acts as the reverse proxy. This architecture is a standard practice for modern web applications as it enhances security, provides a single point of entry, and simplifies service management.

### HTMX
**HTMX** is a front-end library used to enhance HTML. Instead of relying on a complex JavaScript framework, HTMX allows the backend to send back HTML snippets, which are then seamlessly inserted into the page. The assignment mentions HTMX is used for creating a simple user interface for actions like "New Post" and "Edit," allowing for a dynamic user experience with minimal client-side JavaScript.

### Blog-Service (Rust)
The **blog-service**, written in Rust, contains the core business logic of the application. It manages blog posts (CRUD operations) and defines which endpoints are public and which are protected. The service does not store user credentials. Instead, it relies on Keycloak for authentication. When a protected endpoint is accessed, the `blog-service` validates the JWT provided by the user in the request header to ensure they have the necessary `author` role.

---

## Project Flow Diagram

1. A user attempts to access a protected resource in the blog application.

2. The request is intercepted by the Nginx reverse proxy and forwarded to the blog-service.

3. he blog-service recognizes the endpoint as protected and checks for a valid authentication token.

4. Finding no token, the blog-service sends a response that triggers a redirect to Keycloak's login page.

5. The user authenticates with their credentials on the Keycloak login page.

6. Keycloak, upon successful login, redirects the user's browser back to the application with an authorization code.

7. Nginx do a request to Keycloak's token endpoint to exchange the code for an access token.

8. Nginx then forwards the original request to the blog-service, now including the newly acquired access token in the request header.

9. The blog-service receives the request and validates the access token (a JWT).

10. The service grants access, processes the request, and returns the requested content (e.g., an HTML page for creating a new post).

11. Nginx sends the final response back to the user's browser.

