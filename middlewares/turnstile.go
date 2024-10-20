// src/github.com/lulexhostt/authapp/middlewares/turnstile.go
package middlewares

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"os"
)

// TurnstileResponse represents the response structure from Cloudflare's Turnstile verification.
type TurnstileResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error-codes,omitempty"`
}

// TurnstileMiddleware verifies the Turnstile token.
func TurnstileMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.FormValue("cf-turnstile-response")
		if token == "" {
			http.Error(w, "Turnstile token missing", http.StatusBadRequest)
			return
		}

		// Replace with your actual Turnstile secret key
		secret := os.Getenv("TURNSTILE_SECRET_KEY")

		// Create the request to verify the token
		resp, err := http.PostForm("https://challenges.cloudflare.com/turnstile/v0/siteverify",
			url.Values{"secret": {secret}, "response": {token}})

		if err != nil {
			log.Printf("Turnstile verification error: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		// Decode the Turnstile response
		var turnstileResp TurnstileResponse
		if err := json.NewDecoder(resp.Body).Decode(&turnstileResp); err != nil {
			log.Printf("Error decoding Turnstile response: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Check if Turnstile verification was successful
		if !turnstileResp.Success {
			http.Error(w, "Turnstile verification failed", http.StatusForbidden)
			return
		}

		// Call the next handler if Turnstile verification is successful
		next.ServeHTTP(w, r)
	})
}
