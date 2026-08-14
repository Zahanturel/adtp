// SPDX-License-Identifier: Apache-2.0

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

	"github.com/Zahanturel/adtp/pkg/adtp"
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

	// mu guards the fields below. It is never held across a network call.
	mu        sync.Mutex
	cached    map[string]*rsa.PublicKey
	fetchedAt time.Time
	inflight  *jwksFetch // non-nil while a refresh is running
}

// jwksFetch is one in-flight refresh, shared by every caller that arrives while
// it runs. done is closed once keys and err are final.
type jwksFetch struct {
	done chan struct{}
	keys map[string]*rsa.PublicKey
	err  error
}

// keys returns the IdP's signing keys, refreshing the cache when it has expired.
//
// Two properties matter here, and the original implementation had neither: the
// cache lock is not held across the fetch, and concurrent refreshes are
// coalesced into a single upstream request whose result every waiter shares.
//
// Holding the lock across a 10-second fetch meant one unresponsive IdP stalled
// the entire control plane — every authenticated request queued on the mutex,
// including those whose cache entry was already fresh — and because a failed
// fetch leaves the cache stale, each queued caller then issued its own request
// and waited its own full timeout. N requests against a hanging IdP cost N
// timeouts, serially. They now cost one.
func (h *httpJWKS) keys() (map[string]*rsa.PublicKey, error) {
	h.mu.Lock()
	if h.cached != nil && time.Since(h.fetchedAt) < h.ttl {
		keys := h.cached
		h.mu.Unlock()
		return keys, nil
	}
	if f := h.inflight; f != nil {
		h.mu.Unlock()
		<-f.done
		return f.keys, f.err
	}
	f := &jwksFetch{done: make(chan struct{})}
	h.inflight = f
	h.mu.Unlock()

	keys, err := h.fetch()

	h.mu.Lock()
	if err == nil {
		h.cached = keys
		h.fetchedAt = time.Now()
	}
	h.inflight = nil
	h.mu.Unlock()

	f.keys, f.err = keys, err
	close(f.done)
	return keys, err
}

// fetch performs one JWKS retrieval. It holds no lock.
func (h *httpJWKS) fetch() (map[string]*rsa.PublicKey, error) {
	client := h.client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Get(h.url)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks fetch: status %d", resp.StatusCode)
	}
	return parseJWKS(resp.Body)
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

// minRSAModulusBits is the smallest RSA modulus accepted from a JWKS. A 1024-bit
// modulus is factorable by a well-resourced adversary, and accepting one lets an
// IdP — or anyone who can influence its published key set — downgrade
// control-plane authentication to a strength the daemon never chose.
const minRSAModulusBits = 2048

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
	n := new(big.Int).SetBytes(nBytes)
	if bits := n.BitLen(); bits < minRSAModulusBits {
		return nil, fmt.Errorf("jwk modulus is %d bits, minimum is %d", bits, minRSAModulusBits)
	}
	return &rsa.PublicKey{N: n, E: e}, nil
}

// principalCtxKey carries the OIDC-authenticated subject through the request.
type principalCtxKey struct{}

func principalFromContext(ctx context.Context) (string, bool) {
	p, ok := ctx.Value(principalCtxKey{}).(string)
	return p, ok
}

// OIDCMiddleware validates an OIDC bearer token and injects the authenticated
// subject into the request context. Only paths exempted by authBypass
// (/health, /v1/revocation/list) skip validation — all other endpoints,
// including GETs, require a valid token.
func OIDCMiddleware(v *OIDCVerifier) func(http.Handler) http.Handler {
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
