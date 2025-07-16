package config

import (
	"log"
	"os"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type Config struct {
	Port           string
	GoogleClientID string
	GoogleSecret   string
	JWTSecret      string
	OAuth2Config   *oauth2.Config
}

func Load() *Config {
	clientID := os.Getenv("GOOGLE_CLIENT_ID")
	clientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")
	jwtSecret := os.Getenv("JWT_SECRET")
	port := os.Getenv("PORT")

	if clientID == "" || clientSecret == "" || jwtSecret == "" {
		log.Fatal("Missing required environment variables: GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, JWT_SECRET")
	}

	if port == "" {
		port = "8788"
	}

	oauth2Config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  "http://localhost:" + port + "/auth/google/callback",
		Scopes:       []string{"openid", "profile", "email"},
		Endpoint:     google.Endpoint,
	}

	return &Config{
		Port:           port,
		GoogleClientID: clientID,
		GoogleSecret:   clientSecret,
		JWTSecret:      jwtSecret,
		OAuth2Config:   oauth2Config,
	}
}

const (
	AccessTokenExpiry  = 15 * time.Minute
	RefreshTokenExpiry = 7 * 24 * time.Hour
	StateExpiry        = 10 * time.Minute
)