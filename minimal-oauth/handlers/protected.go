package handlers

import (
	"context"
	"encoding/json"
	"html/template"
	"net/http"

	"minimal-oauth/models"
)

type ProtectedHandler struct{
	profileTemplate *template.Template
}

func NewProtectedHandler() *ProtectedHandler {
	profileTemplate := template.Must(template.ParseFiles("templates/profile.html"))
	return &ProtectedHandler{
		profileTemplate: profileTemplate,
	}
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
	data := struct {
		Name      string
		Email     string
		ID        string
		Picture   string
		LoginTime string
	}{
		Name:      user.Name,
		Email:     user.Email,
		ID:        user.ID,
		Picture:   user.Picture,
		LoginTime: user.LoginAt.Format("2006-01-02 15:04:05"),
	}

	w.Header().Set("Content-Type", "text/html")
	h.profileTemplate.Execute(w, data)
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

