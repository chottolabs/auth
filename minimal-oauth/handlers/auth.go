package handlers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/maypok86/otter/v2"
	"golang.org/x/oauth2"

	"minimal-oauth/config"
	"minimal-oauth/models"
)

type AuthHandler struct {
	cfg        *config.Config
	userCache  *otter.Cache[string, *models.User]
	stateCache *otter.Cache[string, *models.PKCEState]
}

func NewAuthHandler(cfg *config.Config) *AuthHandler {
	userCache, err := otter.New[string, *models.User](
		&otter.Options[string, *models.User]{
			MaximumSize:      10000,
			ExpiryCalculator: otter.ExpiryWriting[string, *models.User](config.AccessTokenExpiry),
		},
	)
	if err != nil {
		log.Fatal("Failed to create user cache:", err)
	}

	stateCache, err := otter.New[string, *models.PKCEState](
		&otter.Options[string, *models.PKCEState]{
			MaximumSize:      10000,
			ExpiryCalculator: otter.ExpiryWriting[string, *models.PKCEState](config.StateExpiry),
		},
	)
	if err != nil {
		log.Fatal("Failed to create state cache:", err)
	}

	return &AuthHandler{
		cfg:        cfg,
		userCache:  userCache,
		stateCache: stateCache,
	}
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	state := h.generateRandomString(32)
	verifier := oauth2.GenerateVerifier()
	
	pkceState := &models.PKCEState{
		State:    state,
		Verifier: verifier,
		Expires:  time.Now().Add(config.StateExpiry),
	}
	
	h.stateCache.Set(state, pkceState)
	
	authURL := h.cfg.OAuth2Config.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))
	
	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

func (h *AuthHandler) Callback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	
	if state == "" || code == "" {
		h.writeError(w, "Missing state or code parameter", http.StatusBadRequest)
		return
	}
	
	pkceState, exists := h.stateCache.GetIfPresent(state)
	if !exists {
		h.writeError(w, "Invalid or expired state", http.StatusBadRequest)
		return
	}
	
	h.stateCache.Invalidate(state)
	
	token, err := h.cfg.OAuth2Config.Exchange(
		context.Background(),
		code,
		oauth2.VerifierOption(pkceState.Verifier),
	)
	if err != nil {
		h.writeError(w, "Failed to exchange code for token", http.StatusInternalServerError)
		return
	}
	
	userInfo, err := h.fetchUserInfo(token.AccessToken)
	if err != nil {
		h.writeError(w, "Failed to fetch user info", http.StatusInternalServerError)
		return
	}
	
	user := &models.User{
		ID:      userInfo.Sub,
		Email:   userInfo.Email,
		Name:    userInfo.Name,
		Picture: userInfo.Picture,
		LoginAt: time.Now(),
	}
	
	accessToken, err := h.createJWT(user, "access")
	if err != nil {
		h.writeError(w, "Failed to create access token", http.StatusInternalServerError)
		return
	}
	
	refreshToken, err := h.createJWT(user, "refresh")
	if err != nil {
		h.writeError(w, "Failed to create refresh token", http.StatusInternalServerError)
		return
	}
	
	h.userCache.Set(user.ID, user)
	
	// Set cookies
	accessCookie := &http.Cookie{
		Name:     "access_token",
		Value:    accessToken,
		HttpOnly: true,
		Secure:   false, // Set to true in production with HTTPS
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(config.AccessTokenExpiry.Seconds()),
		Path:     "/",
	}
	
	refreshCookie := &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		HttpOnly: true,
		Secure:   false, // Set to true in production with HTTPS
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(config.RefreshTokenExpiry.Seconds()),
		Path:     "/",
	}
	
	http.SetCookie(w, accessCookie)
	http.SetCookie(w, refreshCookie)
	
	// Log successful authentication and redirect to profile
	log.Printf("User %s authenticated successfully, redirecting to profile", user.ID)
	
	http.Redirect(w, r, "/profile", http.StatusSeeOther)
}

func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	var requestBody struct {
		RefreshToken string `json:"refresh_token"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
		h.writeError(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	
	claims, err := h.validateJWT(requestBody.RefreshToken)
	if err != nil {
		h.writeError(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}
	
	if claims.Type != "refresh" {
		h.writeError(w, "Invalid token type", http.StatusUnauthorized)
		return
	}
	
	user, exists := h.userCache.GetIfPresent(claims.UserID)
	if !exists {
		h.writeError(w, "User not found", http.StatusUnauthorized)
		return
	}
	
	accessToken, err := h.createJWT(user, "access")
	if err != nil {
		h.writeError(w, "Failed to create access token", http.StatusInternalServerError)
		return
	}
	
	response := models.TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(config.AccessTokenExpiry.Seconds()),
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *AuthHandler) createJWT(user *models.User, tokenType string) (string, error) {
	var expiry time.Time
	if tokenType == "access" {
		expiry = time.Now().Add(config.AccessTokenExpiry)
	} else {
		expiry = time.Now().Add(config.RefreshTokenExpiry)
	}
	
	claims := &models.Claims{
		UserID: user.ID,
		Email:  user.Email,
		Type:   tokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiry),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   user.ID,
		},
	}
	
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(h.cfg.JWTSecret))
}

func (h *AuthHandler) validateJWT(tokenString string) (*models.Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &models.Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(h.cfg.JWTSecret), nil
	})
	
	if err != nil {
		return nil, err
	}
	
	if claims, ok := token.Claims.(*models.Claims); ok && token.Valid {
		return claims, nil
	}
	
	return nil, fmt.Errorf("invalid token")
}

func (h *AuthHandler) fetchUserInfo(accessToken string) (*models.GoogleUserInfo, error) {
	req, err := http.NewRequest("GET", "https://www.googleapis.com/oauth2/v2/userinfo", nil)
	if err != nil {
		return nil, err
	}
	
	req.Header.Set("Authorization", "Bearer "+accessToken)
	
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch user info: %d", resp.StatusCode)
	}
	
	var userInfo models.GoogleUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, err
	}
	
	return &userInfo, nil
}

func (h *AuthHandler) generateRandomString(length int) string {
	bytes := make([]byte, length)
	rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)
}

func (h *AuthHandler) writeError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func (h *AuthHandler) GetUser(userID string) (*models.User, bool) {
	return h.userCache.GetIfPresent(userID)
}

func (h *AuthHandler) ValidateJWT(tokenString string) (*models.Claims, error) {
	return h.validateJWT(tokenString)
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	// Clear cookies
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    "",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Path:     "/",
	})
	
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Path:     "/",
	})
	
	http.Redirect(w, r, "/", http.StatusSeeOther)
}