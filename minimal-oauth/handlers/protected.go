package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"minimal-oauth/models"
)

type ProtectedHandler struct{}

func NewProtectedHandler() *ProtectedHandler {
	return &ProtectedHandler{}
}

func (h *ProtectedHandler) Profile(w http.ResponseWriter, r *http.Request) {
	user, ok := getUserFromContext(r.Context())
	if !ok {
		h.writeError(w, "User not found in context", http.StatusInternalServerError)
		return
	}

	// Check if request accepts JSON (for API calls)
	if r.Header.Get("Accept") == "application/json" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(user)
		return
	}

	// Return HTML page for browser requests
	html := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <title>Profile - Minimal OAuth</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
        .profile { background: #f5f5f5; padding: 20px; border-radius: 8px; }
        .user-info { display: flex; align-items: center; gap: 20px; margin-bottom: 20px; }
        .user-info img { border-radius: 50%%; width: 80px; height: 80px; }
        .logout { color: #dc3545; text-decoration: none; }
        .logout:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <h1>Welcome to your Profile</h1>
    <div class="profile">
        <div class="user-info">
            <img src="%s" alt="Profile Picture">
            <div>
                <h2>%s</h2>
                <p>Email: %s</p>
                <p>User ID: %s</p>
                <p>Login Time: %s</p>
            </div>
        </div>
        <nav>
            <a href="/dashboard">Dashboard</a> |
            <a href="/auth/logout" class="logout">Logout</a>
        </nav>
    </div>
</body>
</html>
	`, user.Picture, user.Name, user.Email, user.ID, user.LoginAt.Format("2006-01-02 15:04:05"))

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

func (h *ProtectedHandler) Dashboard(w http.ResponseWriter, r *http.Request) {
	user, ok := getUserFromContext(r.Context())
	if !ok {
		h.writeError(w, "User not found in context", http.StatusInternalServerError)
		return
	}

	dashboardData := map[string]interface{}{
		"message": "Welcome to your dashboard!",
		"user":    user,
		"stats": map[string]interface{}{
			"login_count":    1,
			"last_login":     user.LoginAt,
			"account_status": "active",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(dashboardData)
}

func getUserFromContext(ctx context.Context) (*models.User, bool) {
	user, ok := ctx.Value("user").(*models.User)
	return user, ok
}

func (h *ProtectedHandler) writeError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

