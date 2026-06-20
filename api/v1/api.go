package v1

import "net/http"

// NewRouter wires the v1 endpoints onto a stdlib ServeMux and wraps them with
// API-key authentication. Method+path routing requires Go 1.22+.
func NewRouter(svc *Service) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/agents", handleRegisterAgent(svc))
	mux.HandleFunc("POST /v1/credentials", handleIssueCredential(svc))
	mux.HandleFunc("POST /v1/delegations", handleDelegate(svc))
	mux.HandleFunc("POST /v1/verify", handleVerify(svc))
	mux.HandleFunc("POST /v1/revoke", handleRevoke(svc))
	mux.HandleFunc("GET /v1/revocation/list", handleGetRevocationList(svc))
	mux.HandleFunc("GET /v1/status/{cid}", handleGetStatus(svc))
	mux.HandleFunc("GET /v1/agents/{did}", handleGetAgent(svc))
	mux.HandleFunc("GET /health", handleHealth(svc))

	var h http.Handler = svc.authGate()(mux)
	if rps := svc.Config.Server.RateLimitRPS; rps > 0 {
		burst := svc.Config.Server.RateLimitBurst
		if burst <= 0 {
			burst = int(rps)
		}
		h = RateLimitMiddleware(rps, burst)(h)
	}
	return h
}

// authGate selects the authentication middleware: OIDC bearer-token validation
// when an OIDC verifier is configured, otherwise API-key auth.
func (svc *Service) authGate() func(http.Handler) http.Handler {
	if svc.OIDC != nil {
		return OIDCMiddleware(svc.OIDC)
	}
	return AuthMiddleware(svc.APIKeys)
}
