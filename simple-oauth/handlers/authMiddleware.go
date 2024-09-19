// authMiddleware.go
package handlers

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Key type for context
type key int

const (
	userKey key = iota
)

var issuer = os.Getenv("ISSUER")

// JWT configuration
var jwtSecret = []byte(os.Getenv("JWT_SECRET"))

// CustomClaims defines the structure of the JWT claims.
type CustomClaims struct {
	UserImage     string `json:"user_image"`
	VerifiedEmail bool   `json:"verified_email"`
	Email         string `json:"email"`
	Name          string `json:"name,omitempty"`
	jwt.RegisteredClaims
}

// AuthMiddleware verifies the JWT and adds user information to the request context
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get the JWT from the cookie
		cookie, err := r.Cookie("auth_token")
		if err != nil {
			if err == http.ErrNoCookie {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		// Parse the token
		claims := &CustomClaims{}
		token, err := jwt.ParseWithClaims(cookie.Value, claims, func(token *jwt.Token) (interface{}, error) {
			// Validate the signing method
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method")
			}
			return jwtSecret, nil
		})

		if err != nil {
			if err == jwt.ErrSignatureInvalid {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		if !token.Valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Add the user information to the request context
		ctx := context.WithValue(r.Context(), userKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Helper function to retrieve user from context
func UserFromContext(ctx context.Context) *CustomClaims {
	user, ok := ctx.Value(userKey).(*CustomClaims)
	if !ok {
		return nil
	}
	return user
}

// generateJWT creates a JWT for the authenticated user
func generateJWT(user *GoogleUser) (string, error) {
	claims := CustomClaims{
		UserImage:     user.Picture,
		VerifiedEmail: user.VerifiedEmail,
		Email:         user.Email,
		Name:          user.Name,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   user.Email,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)), // Token expires in 24 hours
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	// Create the token with the specified claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token with the secret key
	signedToken, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}
