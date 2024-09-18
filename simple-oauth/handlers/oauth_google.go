package handlers

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type GoogleUser struct {
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}

// OAuth2 configuration
var config = &oauth2.Config{
	RedirectURL:  os.Getenv("GOOGLE_REDIRECT_URI"),
	ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
	ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
	Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
	Endpoint:     google.Endpoint,
}

const googleUserInfoURL = "https://www.googleapis.com/oauth2/v2/userinfo"

// GoogleLogin initiates the OAuth2 login process with PKCE
func GoogleLogin(w http.ResponseWriter, r *http.Request) {
	// Generate OAuth state
	state, err := generateStateOauthCookie(w)
	if err != nil {
		log.Printf("Error generating OAuth state cookie: %v", err)
		http.Error(w, "Failed to generate OAuth state cookie", http.StatusInternalServerError)
		return
	}

	// Generate PKCE verifier and challenge
	codeVerifier, codeChallenge, err := generatePKCE()
	if err != nil {
		log.Printf("Error generating PKCE parameters: %v", err)
		http.Error(w, "Failed to generate PKCE parameters", http.StatusInternalServerError)
		return
	}

	// Store the code verifier in a secure cookie
	verifierCookie := &http.Cookie{
		Name:     "pkce_verifier",
		Value:    codeVerifier,
		Expires:  time.Now().Add(10 * time.Minute), // PKCE verifier is short-lived
		HttpOnly: true,
		Path:     "/",
		Secure:   false, // Set to true in production
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, verifierCookie)

	// Generate the authorization URL with state and PKCE parameters
	authURL := config.AuthCodeURL(state,
		oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

// GoogleCallback handles the OAuth2 callback and exchanges the code for tokens
func GoogleCallback(w http.ResponseWriter, r *http.Request) {
	// Validate the OAuth state
	stateCookie, err := r.Cookie("oauthstate")
	if err != nil || r.FormValue("state") != stateCookie.Value {
		log.Println("Invalid OAuth state", r.FormValue("state"), stateCookie.Value)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	// Retrieve the code verifier from the cookie
	verifierCookie, err := r.Cookie("pkce_verifier")
	if err != nil {
		log.Printf("Error retrieving PKCE verifier cookie: %v", err)
		http.Error(w, "PKCE verifier not found", http.StatusBadRequest)
		return
	}
	codeVerifier := verifierCookie.Value

	// Once retrieved, delete the verifier cookie for security
	expiredCookie := &http.Cookie{
		Name:     "pkce_verifier",
		Value:    "",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Path:     "/",
		Secure:   false, // Ensure consistency with the original cookie
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, expiredCookie)

	code := r.FormValue("code")

	// Exchange the authorization code for tokens, including the code verifier
	token, err := config.Exchange(r.Context(), code,
		oauth2.SetAuthURLParam("code_verifier", codeVerifier),
	)
	if err != nil {
		log.Printf("Error exchanging code for token: %v", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	// Use the token to fetch the user's information
	user, err := fetchGoogleUser(r.Context(), token)
	if err != nil {
		log.Printf("Error fetching user data: %v", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	// TODO: Implement your user handling logic here (e.g., create or fetch the user from your database)

	// Respond with the user information as JSON
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(user); err != nil {
		log.Printf("Error encoding user data: %v", err)
		http.Error(w, "Failed to encode user data", http.StatusInternalServerError)
	}
}

// generateStateOauthCookie generates a random state string and stores it in a secure cookie
func generateStateOauthCookie(w http.ResponseWriter) (string, error) {
	b := make([]byte, 16)

	// crypto/rand provides CSPRNG
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	state := base64.URLEncoding.EncodeToString(b)
	cookie := &http.Cookie{
		Name:     "oauthstate",
		Value:    state,
		Expires:  time.Now().Add(365 * 24 * time.Hour),
		HttpOnly: true,
		Path:     "/",
		Secure:   false, // Set to true in production
		SameSite: http.SameSiteLaxMode,
	}

	http.SetCookie(w, cookie)
	return state, nil
}

// generatePKCE generates a code verifier and its corresponding code challenge.
// It returns both the verifier and the challenge.
func generatePKCE() (verifier string, challenge string, err error) {
	verifierBytes := make([]byte, 32)
	if _, err := rand.Read(verifierBytes); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(verifierBytes)

	hash := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(hash[:])

	return verifier, challenge, nil
}

// fetchGoogleUser retrieves user information from Google using the provided token.
func fetchGoogleUser(ctx context.Context, token *oauth2.Token) (*GoogleUser, error) {
	client := config.Client(ctx, token)
	resp, err := client.Get(googleUserInfoURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var user GoogleUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, err
	}

	return &user, nil
}
