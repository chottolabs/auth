package main

import (
	"fmt"
	"github.com/chottolabs/simple-oauth/handlers"
	"log"
	"net/http"
)

func main() {
	mux := http.NewServeMux()
	// Root
	mux.Handle("/", http.FileServer(http.Dir("templates/")))

	// OauthGoogle
	mux.HandleFunc("GET /auth/google/login", handlers.GoogleLogin)
	mux.HandleFunc("GET /auth/google/callback", handlers.GoogleCallback)

	server := &http.Server{
		Addr:    fmt.Sprintf("localhost:4321"),
		Handler: mux,
	}

	log.Printf("Starting HTTP Server. Listening at %q", server.Addr)
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Printf("%v", err)
	} else {
		log.Println("Server closed!")
	}
}
