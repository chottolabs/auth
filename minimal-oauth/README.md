# Minimal OAuth Client

A minimal OAuth2 client implementation for Google authentication using modern Go 1.24.5 with PKCE support.

## Features

- **PKCE (Proof Key for Code Exchange)** for enhanced security
- **JWT-based authentication** with access and refresh tokens
- **High-performance caching** using Otter v2
- **Modern Go routing** with enhanced pattern matching
- **Minimal dependencies** - only 3 external packages

## Dependencies

- `github.com/maypok86/otter/v2` - High-performance in-memory caching
- `github.com/golang-jwt/jwt/v5` - JWT token handling
- `golang.org/x/oauth2/google` - Google OAuth2 integration

## Setup

1. **Set environment variables:**
   ```bash
   export GOOGLE_CLIENT_ID="your-google-client-id"
   export GOOGLE_CLIENT_SECRET="your-google-client-secret"
   export JWT_SECRET="your-jwt-secret-key"
   export PORT="8788"  # optional, defaults to 8788
   ```

2. **Configure Google OAuth2:**
   - Go to [Google Cloud Console](https://console.cloud.google.com/)
   - Create a new project or select existing
   - Enable Google+ API
   - Create OAuth2 credentials
   - Set authorized redirect URI: `http://localhost:8788/auth/google/callback`

3. **Run the server:**
   ```bash
   go run main.go
   ```

## API Endpoints

### Authentication
- `GET /auth/google` - Initiate Google OAuth flow
- `GET /auth/google/callback` - OAuth callback handler (redirects to /profile)
- `GET /auth/logout` - Clear authentication cookies and redirect to home
- `POST /auth/refresh` - Refresh access token

### Protected Routes
- `GET /profile` - User profile page (HTML) or JSON (with Accept: application/json)
- `GET /dashboard` - Dashboard data (JSON)

## Usage Example

### Browser Flow (Recommended)
1. **Visit** `http://localhost:8788/auth/google` in your browser
2. **Complete OAuth flow** - you'll be redirected to Google for authentication
3. **Automatic redirect** to `/profile` page after successful authentication
4. **Logout** by clicking the logout link or visiting `/auth/logout`

### API Flow
1. **Start authentication:**
   ```bash
   curl http://localhost:8788/auth/google
   ```

2. **Complete OAuth flow in browser** - cookies will be set automatically

3. **Access protected routes:**
   ```bash
   # Get profile as JSON
   curl -H "Accept: application/json" --cookie-jar cookies.txt http://localhost:8788/profile
   
   # Or use Bearer token
   curl -H "Authorization: Bearer <access_token>" http://localhost:8788/profile
   ```

4. **Refresh token:**
   ```bash
   curl -X POST -H "Content-Type: application/json" \
        -d '{"refresh_token": "<refresh_token>"}' \
        http://localhost:8788/auth/refresh
   ```

## Security Features

- **PKCE implementation** prevents authorization code interception
- **JWT tokens** with short expiry (15 minutes access, 7 days refresh)
- **State parameter validation** prevents CSRF attacks
- **Secure token storage** with TTL-based expiry
- **Bearer token authentication** for protected routes

## Architecture

```
├── main.go              # Server entry point with routing
├── config/config.go     # Configuration management
├── models/user.go       # User and token models
├── handlers/
│   ├── auth.go         # OAuth flow with PKCE
│   └── protected.go    # Protected route handlers
├── middleware/
│   └── auth.go         # JWT validation middleware
└── templates/
    ├── home.html       # Home page template
    └── profile.html    # Profile page template
```

## Token Flow

1. **Authorization**: PKCE verifier generated, user redirected to Google
2. **Callback**: Code exchanged for tokens using PKCE verifier
3. **JWT Creation**: Access/refresh tokens created and cached
4. **Authentication**: Bearer tokens validated via middleware
5. **Refresh**: New access tokens issued using refresh tokens