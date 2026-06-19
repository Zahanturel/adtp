package v1

import (
	"net/http"
	"strings"

	"github.com/adtp/adtp/pkg/adtp"
)

const bearerPrefix = "Bearer "

// AuthMiddleware enforces API-key authentication on mutating requests. Read-only
// requests — any GET, which covers /health, /v1/status/{cid}, /v1/agents/{did},
// and /v1/revocation/list — pass through; every other method (the credential
// issuance, delegation, and revocation endpoints) requires a valid
// "Authorization: Bearer <key>" header. With no keys configured the map is empty
// and every mutating request is rejected (fail closed).
func AuthMiddleware(validKeys map[string]bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/health" || r.Method == http.MethodGet {
				next.ServeHTTP(w, r)
				return
			}
			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(auth, bearerPrefix) {
				writeErr(w, http.StatusUnauthorized, adtp.CodeDenied, "missing or malformed Authorization header")
				return
			}
			key := strings.TrimPrefix(auth, bearerPrefix)
			if key == "" || !validKeys[key] {
				writeErr(w, http.StatusUnauthorized, adtp.CodeDenied, "invalid API key")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
