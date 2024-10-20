// middlewares/rate_limiter.go
package middlewares

import (
	"net"
	"net/http"
	"sync"
	"time"
)

var (
	rateLimits     = make(map[string]int)
	mu             sync.Mutex
	requestsPerMin = 10
	blockDuration  = 30 * time.Minute
)

func RateLimiter(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		mu.Lock()
		defer mu.Unlock()

		rateLimits[ip]++

		if rateLimits[ip] > requestsPerMin {
			http.Error(w, "Too many requests", http.StatusTooManyRequests)
			return
		}

		go func() {
			time.Sleep(blockDuration)
			mu.Lock()
			rateLimits[ip]--
			mu.Unlock()
		}()

		next.ServeHTTP(w, r)
	})
}
