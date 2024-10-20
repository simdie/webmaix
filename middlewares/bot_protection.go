package middlewares

import (
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"

	"gopkg.in/yaml.v2"
)

// Predefined bot and headless browser identifiers
var (
	denyBots = []string{
		"googlebot", "bingbot", "censyinspect", "curl", "yandex",
		"baiduspider", "slackbot", "twitterbot", "ahrefsbot",
		"semrushbot", "dotbot", "sogou", "exabot",
		"mj12bot", "python-requests", "scrapy", "apache-httpclient",
		"wget", "httrack", "libwww-perl", "facebookexternalhit",
		"linkedinbot", "twitterbot", "openbot", "bingpreview",
		"duckduckbot", "cocobot", "yisouspider", "yeti",
		"seznambot", "sistrix", "pingdom", "ping-o-matic",
		"netcraft", "screaming frog seo spider", "zapier",
		"nimbostratus", "blexbot", "dataminr", "ai-bot",
		"majestic", "mojombo", "rogerbot", "screaming frog",
		"greynoise", "crawling", "crawlers", "webspider",
		"crawler", "crawlerbot", "spider", "spiderbot",
		"robot", "robot.txt", "eventbot", "getdata",
		"crawler4j", "paros", "charles", "zgrab",
		"flood", "phantomjs", "headlesschrome", "js-scraper",
		"alertbot", "botometer", "tinyurl", "datacrawler",
	}
	denyHeadless = []string{
		"headlesschrome", "phantomjs", "puppeteer", "selenium",
		"selenium-webdriver", "js-scraper",
	}
	denyIPs      []string // Will be populated from the YAML file
	denyPatterns = []string{
		"curl", "wget", "python-requests",
		"scrapy", "httpclient", "httpclient", "requests",
		// Add more patterns here as needed
	}
)

// Config structure for YAML file
type Config struct {
	DenyIPs []string `yaml:"deny_ips"`
}

// LoadDenyIPs reads the YAML configuration file and populates denyIPs
func LoadDenyIPs() error {
	file, err := os.Open("config/deny_ips.yaml")
	if err != nil {
		return err
	}
	defer file.Close()

	data, err := ioutil.ReadAll(file)
	if err != nil {
		return err
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return err
	}

	denyIPs = config.DenyIPs
	return nil
}

// BotProtection middleware to block bots and denied IPs
func BotProtection(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userAgent := r.UserAgent()
		// Check for bots
		for _, bot := range denyBots {
			if strings.Contains(strings.ToLower(userAgent), bot) {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		}
		// Check for headless browsers
		for _, headless := range denyHeadless {
			if strings.Contains(userAgent, headless) {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		}
		// Check for denied patterns
		for _, pattern := range denyPatterns {
			if strings.Contains(userAgent, pattern) {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		}
		// Check denied IPs
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		for _, deniedIP := range denyIPs {
			if ip == deniedIP {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
