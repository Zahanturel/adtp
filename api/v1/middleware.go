package v1

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/Zahanturel/adtp/pkg/adtp"
	"golang.org/x/time/rate"
)

const bearerPrefix = "Bearer "

// authBypass returns true for paths that never require authentication.
func authBypass(r *http.Request) bool {
	return r.URL.Path == "/health" || r.URL.Path == "/v1/revocation/list"
}

// AuthMiddleware enforces API-key authentication. Only /health and
// /v1/revocation/list bypass auth; all other endpoints (including GET
// /v1/agents/{did} and /v1/status/{cid}) require a valid
// "Authorization: Bearer <key>" header. Key comparison uses
// crypto/subtle.ConstantTimeCompare to prevent timing side-channels.
// With no keys configured, every request requiring auth is rejected (fail closed).
func AuthMiddleware(validKeys map[string]bool) func(http.Handler) http.Handler {
	keys := make([][]byte, 0, len(validKeys))
	for k := range validKeys {
		keys = append(keys, []byte(k))
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if authBypass(r) {
				next.ServeHTTP(w, r)
				return
			}
			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(auth, bearerPrefix) {
				writeErr(w, http.StatusUnauthorized, adtp.CodeDenied, "missing or malformed Authorization header")
				return
			}
			key := []byte(strings.TrimPrefix(auth, bearerPrefix))
			if len(key) == 0 || !constantTimeContains(keys, key) {
				writeErr(w, http.StatusUnauthorized, adtp.CodeDenied, "invalid API key")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// constantTimeContains checks whether candidate matches any entry in keys.
// Every entry is compared regardless of early match to avoid leaking which
// index matched, though the total number of keys is not hidden.
func constantTimeContains(keys [][]byte, candidate []byte) bool {
	var match int
	for _, k := range keys {
		if subtle.ConstantTimeCompare(k, candidate) == 1 {
			match = 1
		}
	}
	return match == 1
}

// RateLimitMiddleware applies a global token-bucket rate limit. Requests that
// exceed the limit receive 429 Too Many Requests. Health and revocation-list
// endpoints are exempt.
func RateLimitMiddleware(rps float64, burst int) func(http.Handler) http.Handler {
	limiter := rate.NewLimiter(rate.Limit(rps), burst)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if authBypass(r) {
				next.ServeHTTP(w, r)
				return
			}
			if !limiter.Allow() {
				writeErr(w, http.StatusTooManyRequests, adtp.CodeRateLimited, "rate limit exceeded")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
