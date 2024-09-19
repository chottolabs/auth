// main.go
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/chottolabs/simple-oauth/handlers"
)

func main() {
	mux := http.NewServeMux()
	// Public Routes
	mux.Handle("/", http.FileServer(http.Dir("templates/")))
	mux.HandleFunc("GET /auth/google/login", handlers.GoogleLogin)
	mux.HandleFunc("GET /auth/google/callback", handlers.GoogleCallback)

	// Protected Routes
	protectedMux := http.NewServeMux()
	protectedMux.HandleFunc("GET /dashboard", dashboardHandler)

	// Wrap the protected routes with the AuthMiddleware
	mux.Handle("GET /dashboard", handlers.AuthMiddleware(protectedMux))

	server := &http.Server{
		Addr:    fmt.Sprintf(":4321"),
		Handler: mux,
	}

	log.Printf("Starting HTTP Server. Listening at %q", server.Addr)
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Printf("%v", err)
	} else {
		log.Println("Server closed!")
	}
}

// Example protected handler
func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	user := handlers.UserFromContext(r.Context())
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Display JWT claims response
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(user); err != nil {
		log.Printf("Error encoding response: %v", err)
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}
