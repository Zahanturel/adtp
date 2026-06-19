package v1

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/adtp/adtp/pkg/adtp"
)

// ErrOIDCToken reports a bearer token that fails OIDC validation.
var ErrOIDCToken = errors.New("invalid OIDC token")

// jwksProvider supplies the IdP's RSA signing keys indexed by key id. It is an
// interface so tests can inject a static key set without network access.
type jwksProvider interface {
	keys() (map[string]*rsa.PublicKey, error)
}

// OIDCVerifier validates RS256 JWT bearer tokens against an OIDC provider's
// issuer, audience, and JWKS. RS256 is what Entra/Okta/Auth0 issue by default.
// Only RS256 is accepted: "none" and HMAC algorithms are rejected outright,
// which closes the classic JWT algorithm-confusion attack.
type OIDCVerifier struct {
	issuer   string
	audience string
	provider jwksProvider
	leeway   time.Duration
}

// NewOIDCVerifier builds a verifier that fetches keys from jwksURL over HTTPS.
func NewOIDCVerifier(issuer, audience, jwksURL string) *OIDCVerifier {
	return &OIDCVerifier{
		issuer:   issuer,
		audience: audience,
		provider: &httpJWKS{url: jwksURL, ttl: 5 * time.Minute},
		leeway:   60 * time.Second,
	}
}

// Verify checks the token's RS256 signature and its iss/aud/exp/nbf claims,
// returning the authenticated subject (sub) on success.
func (v *OIDCVerifier) Verify(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("%w: not a compact JWS", ErrOIDCToken)
	}

	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("%w: header not base64url", ErrOIDCToken)
	}
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return "", fmt.Errorf("%w: header not JSON", ErrOIDCToken)
	}
	if hdr.Alg != "RS256" {
		return "", fmt.Errorf("%w: alg %q not supported (RS256 only)", ErrOIDCToken, hdr.Alg)
	}

	keys, err := v.provider.keys()
	if err != nil {
		return "", fmt.Errorf("%w: jwks: %v", ErrOIDCToken, err)
	}
	pub := keys[hdr.Kid]
	if pub == nil {
		if hdr.Kid == "" && len(keys) == 1 {
			for _, k := range keys {
				pub = k
			}
		} else {
			return "", fmt.Errorf("%w: no signing key for kid %q", ErrOIDCToken, hdr.Kid)
		}
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", fmt.Errorf("%w: signature not base64url", ErrOIDCToken)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		return "", fmt.Errorf("%w: signature verification failed", ErrOIDCToken)
	}

	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("%w: payload not base64url", ErrOIDCToken)
	}
	var claims struct {
		Iss string          `json:"iss"`
		Sub string          `json:"sub"`
		Aud json.RawMessage `json:"aud"`
		Exp int64           `json:"exp"`
		Nbf int64           `json:"nbf"`
	}
	if err := json.Unmarshal(pb, &claims); err != nil {
		return "", fmt.Errorf("%w: claims not JSON", ErrOIDCToken)
	}

	if claims.Iss != v.issuer {
		return "", fmt.Errorf("%w: issuer %q != %q", ErrOIDCToken, claims.Iss, v.issuer)
	}
	if !audienceContains(claims.Aud, v.audience) {
		return "", fmt.Errorf("%w: audience does not include %q", ErrOIDCToken, v.audience)
	}
	now := time.Now()
	if claims.Exp == 0 || now.After(time.Unix(claims.Exp, 0).Add(v.leeway)) {
		return "", fmt.Errorf("%w: token expired or missing exp", ErrOIDCToken)
	}
	if claims.Nbf != 0 && now.Before(time.Unix(claims.Nbf, 0).Add(-v.leeway)) {
		return "", fmt.Errorf("%w: token not yet valid", ErrOIDCToken)
	}
	if claims.Sub == "" {
		return "", fmt.Errorf("%w: missing sub claim", ErrOIDCToken)
	}
	return claims.Sub, nil
}

// audienceContains reports whether the JWT aud claim (a string or array of
// strings) includes want.
func audienceContains(raw json.RawMessage, want string) bool {
	if len(raw) == 0 {
		return false
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return one == want
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil {
		for _, a := range many {
			if a == want {
				return true
			}
		}
	}
	return false
}

// httpJWKS fetches and caches an RSA JWKS document over HTTP, refreshing after a
// TTL so key rotation is eventually picked up.
type httpJWKS struct {
	url    string
	ttl    time.Duration
	client *http.Client

	mu        sync.Mutex
	cached    map[string]*rsa.PublicKey
	fetchedAt time.Time
}

func (h *httpJWKS) keys() (map[string]*rsa.PublicKey, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cached != nil && time.Since(h.fetchedAt) < h.ttl {
		return h.cached, nil
	}
	client := h.client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Get(h.url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks fetch: status %d", resp.StatusCode)
	}
	keys, err := parseJWKS(resp.Body)
	if err != nil {
		return nil, err
	}
	h.cached = keys
	h.fetchedAt = time.Now()
	return keys, nil
}

// jwksDoc / jwk model the subset of the JWKS schema we consume (RSA keys).
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func parseJWKS(r io.Reader) (map[string]*rsa.PublicKey, error) {
	var doc struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, fmt.Errorf("jwks decode: %w", err)
	}
	out := make(map[string]*rsa.PublicKey)
	for _, k := range doc.Keys {
		if k.Kty != "RSA" {
			continue
		}
		pub, err := rsaPublicKeyFromJWK(k.N, k.E)
		if err != nil {
			return nil, err
		}
		out[k.Kid] = pub
	}
	if len(out) == 0 {
		return nil, errors.New("jwks contains no RSA keys")
	}
	return out, nil
}

func rsaPublicKeyFromJWK(nB64, eB64 string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		return nil, fmt.Errorf("jwk modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil {
		return nil, fmt.Errorf("jwk exponent: %w", err)
	}
	e := int(new(big.Int).SetBytes(eBytes).Int64())
	if e == 0 {
		return nil, errors.New("jwk exponent is zero")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil
}

// principalCtxKey carries the OIDC-authenticated subject through the request.
type principalCtxKey struct{}

func principalFromContext(ctx context.Context) (string, bool) {
	p, ok := ctx.Value(principalCtxKey{}).(string)
	return p, ok
}

// OIDCMiddleware validates an OIDC bearer token on mutating requests and injects
// the authenticated subject into the request context. Read-only GETs and /health
// remain open, matching AuthMiddleware.
func OIDCMiddleware(v *OIDCVerifier) func(http.Handler) http.Handler {
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
			sub, err := v.Verify(strings.TrimPrefix(auth, bearerPrefix))
			if err != nil {
				writeErr(w, http.StatusUnauthorized, adtp.CodeDenied, "invalid bearer token")
				return
			}
			ctx := context.WithValue(r.Context(), principalCtxKey{}, sub)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
