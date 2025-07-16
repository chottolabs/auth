package middleware

import (
	"context"
	"net/http"
	"strings"

	"minimal-oauth/handlers"
	"minimal-oauth/models"
)

type contextKey string

const UserContextKey contextKey = "user"

func AuthMiddleware(authHandler *handlers.AuthHandler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var token string
			
			// Try to get token from Authorization header first
			authHeader := r.Header.Get("Authorization")
			if authHeader != "" {
				tokenParts := strings.Split(authHeader, " ")
				if len(tokenParts) == 2 && tokenParts[0] == "Bearer" {
					token = tokenParts[1]
				}
			}
			
			// If no Bearer token, try to get from cookie
			if token == "" {
				if cookie, err := r.Cookie("access_token"); err == nil {
					token = cookie.Value
				}
			}
			
			if token == "" {
				writeUnauthorized(w, "Missing authentication token")
				return
			}

			claims, err := authHandler.ValidateJWT(token)
			if err != nil {
				writeUnauthorized(w, "Invalid token")
				return
			}

			if claims.Type != "access" {
				writeUnauthorized(w, "Invalid token type")
				return
			}

			user, exists := authHandler.GetUser(claims.UserID)
			if !exists {
				writeUnauthorized(w, "User not found")
				return
			}

			ctx := context.WithValue(r.Context(), "user", user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func GetUserFromContext(ctx context.Context) (*models.User, bool) {
	user, ok := ctx.Value("user").(*models.User)
	return user, ok
}

func writeUnauthorized(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte(`{"error": "` + message + `"}`))
}