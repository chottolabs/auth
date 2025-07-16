package main

import (
	"html/template"
	"log"
	"net/http"

	"minimal-oauth/config"
	"minimal-oauth/handlers"
	"minimal-oauth/middleware"
)

func main() {
	cfg := config.Load()
	
	// Parse templates
	homeTemplate := template.Must(template.ParseFiles("templates/home.html"))
	
	authHandler := handlers.NewAuthHandler(cfg)
	protectedHandler := handlers.NewProtectedHandler()
	
	mux := http.NewServeMux()
	
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		homeTemplate.Execute(w, nil)
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