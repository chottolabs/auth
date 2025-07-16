package models

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type User struct {
	ID       string    `json:"id"`
	Email    string    `json:"email"`
	Name     string    `json:"name"`
	Picture  string    `json:"picture"`
	LoginAt  time.Time `json:"login_at"`
}

type PKCEState struct {
	State    string    `json:"state"`
	Verifier string    `json:"verifier"`
	Expires  time.Time `json:"expires"`
}

type Claims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Type   string `json:"type"`
	jwt.RegisteredClaims
}

type GoogleUserInfo struct {
	Sub     string `json:"sub"`
	Email   string `json:"email"`
	Name    string `json:"name"`
	Picture string `json:"picture"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}