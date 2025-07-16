package main

import (
	"log"
	"net/http"

	"minimal-oauth/config"
	"minimal-oauth/handlers"
	"minimal-oauth/middleware"
)

func main() {
	cfg := config.Load()
	
	authHandler := handlers.NewAuthHandler(cfg)
	protectedHandler := handlers.NewProtectedHandler()
	
	mux := http.NewServeMux()
	
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		html := `
<!DOCTYPE html>
<html>
<head>
    <title>Minimal OAuth Server</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
        .container { background: #f5f5f5; padding: 20px; border-radius: 8px; }
        .login-btn { display: inline-block; background: #4285f4; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; }
        .login-btn:hover { background: #357ae8; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Minimal OAuth Server</h1>
        <p>A minimal OAuth2 client implementation with Google authentication using PKCE.</p>
        <p><a href="/auth/google" class="login-btn">Login with Google</a></p>
        <h3>Available Endpoints:</h3>
        <ul>
            <li><strong>GET /auth/google</strong> - Initiate Google OAuth flow</li>
            <li><strong>GET /auth/logout</strong> - Logout and clear cookies</li>
            <li><strong>POST /auth/refresh</strong> - Refresh access token</li>
            <li><strong>GET /profile</strong> - User profile page (protected)</li>
            <li><strong>GET /dashboard</strong> - Dashboard data (protected)</li>
        </ul>
    </div>
</body>
</html>`
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(html))
	})
	
	mux.HandleFunc("GET /auth/google", authHandler.Login)
	mux.HandleFunc("GET /auth/google/callback", authHandler.Callback)
	mux.HandleFunc("POST /auth/refresh", authHandler.Refresh)
	mux.HandleFunc("GET /auth/logout", authHandler.Logout)
	
	authMiddleware := middleware.AuthMiddleware(authHandler)
	mux.Handle("GET /profile", authMiddleware(http.HandlerFunc(protectedHandler.Profile)))
	mux.Handle("GET /dashboard", authMiddleware(http.HandlerFunc(protectedHandler.Dashboard)))
	
	log.Printf("Starting server on port %s", cfg.Port)
	log.Printf("Google OAuth redirect URI: %s", cfg.OAuth2Config.RedirectURL)
	log.Fatal(http.ListenAndServe(":"+cfg.Port, mux))
}