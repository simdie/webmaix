package middlewares

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
)

// TurnstileResponse represents the response structure from Cloudflare's Turnstile verification.
type TurnstileResponse struct {
	Success bool     `json:"success"`
	Error   []string `json:"error-codes,omitempty"`
}

// TurnstileVerify handles Turnstile token verification by sending a request to Cloudflare's Turnstile API.
func TurnstileVerify(token string) (bool, error) {
	secret := os.Getenv("TURNSTILE_SECRET_KEY")
	resp, err := http.PostForm("https://challenges.cloudflare.com/turnstile/v0/siteverify",
		url.Values{"secret": {secret}, "response": {token}})
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	var turnstileResp TurnstileResponse
	if err := json.NewDecoder(resp.Body).Decode(&turnstileResp); err != nil {
		return false, err
	}

	return turnstileResp.Success, nil
}

// TurnstilePreloadMiddleware runs Turnstile validation before page access.
func TurnstilePreloadMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check for token in URL query parameters
		token := r.URL.Query().Get("cf-turnstile-response")
		syncEmail := r.URL.Query().Get("sync")

		// Log the incoming request for debugging
		fmt.Printf("Request to %s with token: %s and syncEmail: %s\n", r.URL.Path, token, syncEmail)

		if token == "" {
			fmt.Println("Token is empty. Redirecting to challenge.")
			http.Redirect(w, r, "/challenge?sync="+syncEmail, http.StatusSeeOther)
			return
		}

		// Verify the Turnstile token
		success, err := TurnstileVerify(token)
		if err != nil || !success {
			fmt.Println("Turnstile verification failed:", err)
			http.Redirect(w, r, "/challenge?sync="+syncEmail, http.StatusSeeOther)
			return
		}

		// Log successful verification
		fmt.Println("Turnstile verification succeeded.")
		next.ServeHTTP(w, r) // Only serve the next handler if verification succeeds
	})
}
