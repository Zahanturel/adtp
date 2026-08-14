// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Zahanturel/adtp/config"
	"github.com/Zahanturel/adtp/internal/identity"
	"github.com/Zahanturel/adtp/internal/verify"
	"github.com/Zahanturel/adtp/pkg/adtp"
	"github.com/Zahanturel/adtp/store/memory"
)

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// signJWT mints an RS256 JWT. If alg is "" it defaults to RS256.
func signJWT(t *testing.T, key *rsa.PrivateKey, kid, alg string, claims map[string]any) string {
	t.Helper()
	if alg == "" {
		alg = "RS256"
	}
	hdr := map[string]any{"alg": alg, "typ": "JWT"}
	if kid != "" {
		hdr["kid"] = kid
	}
	hb, _ := json.Marshal(hdr)
	pb, _ := json.Marshal(claims)
	signingInput := b64url(hb) + "." + b64url(pb)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signingInput + "." + b64url(sig)
}

type fakeJWKS struct{ m map[string]*rsa.PublicKey }

func (f fakeJWKS) keys() (map[string]*rsa.PublicKey, error) { return f.m, nil }

func testVerifier(t *testing.T, key *rsa.PrivateKey, kid string) *OIDCVerifier {
	t.Helper()
	return &OIDCVerifier{
		issuer:   "https://idp.example.com",
		audience: "api://adtp",
		provider: fakeJWKS{m: map[string]*rsa.PublicKey{kid: &key.PublicKey}},
		leeway:   60 * time.Second,
	}
}

func validClaims() map[string]any {
	now := time.Now().Unix()
	return map[string]any{
		"iss": "https://idp.example.com",
		"aud": "api://adtp",
		"sub": "user@example.com",
		"exp": now + 300,
		"nbf": now - 10,
	}
}

func TestOIDCVerifyHappyPath(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	v := testVerifier(t, key, "k1")
	token := signJWT(t, key, "k1", "", validClaims())
	sub, err := v.Verify(token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if sub != "user@example.com" {
		t.Errorf("sub = %q", sub)
	}
}

func TestOIDCVerifyRejections(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	v := testVerifier(t, key, "k1")
	now := time.Now().Unix()

	mod := func(f func(map[string]any)) map[string]any {
		c := validClaims()
		f(c)
		return c
	}

	cases := []struct {
		name  string
		token string
	}{
		{"alg none (confusion)", signJWT(t, key, "k1", "none", validClaims())},
		{"alg HS256 (confusion)", signJWT(t, key, "k1", "HS256", validClaims())},
		{"wrong issuer", signJWT(t, key, "k1", "", mod(func(c map[string]any) { c["iss"] = "https://evil" }))},
		{"wrong audience", signJWT(t, key, "k1", "", mod(func(c map[string]any) { c["aud"] = "api://other" }))},
		{"expired", signJWT(t, key, "k1", "", mod(func(c map[string]any) { c["exp"] = now - 3600 }))},
		{"missing exp", signJWT(t, key, "k1", "", mod(func(c map[string]any) { delete(c, "exp") }))},
		{"not yet valid", signJWT(t, key, "k1", "", mod(func(c map[string]any) { c["nbf"] = now + 3600 }))},
		{"missing sub", signJWT(t, key, "k1", "", mod(func(c map[string]any) { delete(c, "sub") }))},
		{"unknown kid", signJWT(t, key, "unknown", "", validClaims())},
		{"signed by other key", signJWT(t, other, "k1", "", validClaims())},
		{"not a jwt", "not-a-jwt"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := v.Verify(c.token); !errors.Is(err, ErrOIDCToken) {
				t.Errorf("Verify(%s) = %v, want ErrOIDCToken", c.name, err)
			}
		})
	}
}

// TestOIDCVerifyOverHTTPJWKS covers the httpJWKS provider and JWK parsing.
func TestOIDCVerifyOverHTTPJWKS(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwks := fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":"k1","n":%q,"e":%q}]}`,
		b64url(key.N.Bytes()), b64url(big.NewInt(int64(key.E)).Bytes()))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, jwks)
	}))
	defer srv.Close()

	v := NewOIDCVerifier("https://idp.example.com", "api://adtp", srv.URL)
	token := signJWT(t, key, "k1", "", validClaims())
	sub, err := v.Verify(token)
	if err != nil || sub != "user@example.com" {
		t.Errorf("Verify over HTTP JWKS = (%q, %v)", sub, err)
	}
}

// A 1024-bit modulus is factorable by a well-resourced adversary. Accepting one
// lets the IdP's published key set silently downgrade control-plane auth.
func TestJWKSRejectsUndersizedModulus(t *testing.T) {
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	jwks := fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":"weak","n":%q,"e":%q}]}`,
		b64url(weak.N.Bytes()), b64url(big.NewInt(int64(weak.E)).Bytes()))
	if _, err := parseJWKS(strings.NewReader(jwks)); err == nil {
		t.Fatal("FATAL: 1024-bit RSA key accepted from JWKS")
	}

	strong, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	ok := fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":"ok","n":%q,"e":%q}]}`,
		b64url(strong.N.Bytes()), b64url(big.NewInt(int64(strong.E)).Bytes()))
	if _, err := parseJWKS(strings.NewReader(ok)); err != nil {
		t.Errorf("2048-bit RSA key rejected: %v", err)
	}
}

// A failing IdP must cost one upstream request per refresh, not one per caller.
// A failed fetch leaves the cache stale, so under the original implementation
// each queued caller acquired the mutex in turn and issued its own request,
// waiting its own full timeout: N callers, N sequential timeouts. The success
// path hides this — the first fetch populates the cache and the rest hit it —
// which is exactly why the failure path is the one worth asserting.
func TestJWKSCoalescesConcurrentFetches(t *testing.T) {
	var hits int32
	arrived := make(chan struct{}, 1)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		select {
		case arrived <- struct{}{}:
		default:
		}
		<-release // hold the "IdP" open until every caller is waiting
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	h := &httpJWKS{url: srv.URL, ttl: time.Minute}

	const callers = 8
	var wg sync.WaitGroup
	// The first caller starts the fetch; wait until the handler has it in hand so
	// the rest genuinely arrive mid-flight rather than racing the start.
	wg.Add(1)
	go func() { defer wg.Done(); _, _ = h.keys() }()
	<-arrived
	for i := 1; i < callers; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = h.keys() }()
	}

	// Give the late callers time to block, then let the IdP respond.
	time.Sleep(100 * time.Millisecond)
	close(release)
	wg.Wait()

	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("FATAL: %d upstream JWKS requests for %d concurrent callers, want 1", got, callers)
	}
}

// A read that only needs the cache must not block behind an in-flight refresh.
func TestJWKSFreshCacheReadableDuringSlowFetch(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwks := fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":"k1","n":%q,"e":%q}]}`,
		b64url(key.N.Bytes()), b64url(big.NewInt(int64(key.E)).Bytes()))

	var hits int32
	arrived := make(chan struct{}, 1)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if atomic.AddInt32(&hits, 1) > 1 {
			select {
			case arrived <- struct{}{}:
			default:
			}
			<-release
		}
		io.WriteString(w, jwks)
	}))
	defer srv.Close()
	defer close(release)

	h := &httpJWKS{url: srv.URL, ttl: 50 * time.Millisecond}
	if _, err := h.keys(); err != nil {
		t.Fatalf("initial fetch: %v", err)
	}

	// Let the cache expire, then start a refresh that hangs in the handler.
	time.Sleep(60 * time.Millisecond)
	go func() { _, _ = h.keys() }()
	<-arrived

	// The refresh is in flight. Re-freshen the cache and read it: this must not
	// wait on the hanging fetch. Acquiring mu here is itself the assertion —
	// under the old implementation the refresh holds it for the fetch's duration.
	locked := make(chan struct{})
	go func() {
		h.mu.Lock()
		h.fetchedAt = time.Now()
		h.mu.Unlock()
		_, _ = h.keys()
		close(locked)
	}()
	select {
	case <-locked:
	case <-time.After(2 * time.Second):
		t.Fatal("FATAL: cache access blocked behind an in-flight JWKS fetch")
	}
}

func TestAudienceContains(t *testing.T) {
	if !audienceContains(json.RawMessage(`"a"`), "a") {
		t.Errorf("string aud not matched")
	}
	if !audienceContains(json.RawMessage(`["x","a","y"]`), "a") {
		t.Errorf("array aud not matched")
	}
	if audienceContains(json.RawMessage(`["x"]`), "a") {
		t.Errorf("absent aud matched")
	}
	if audienceContains(nil, "a") {
		t.Errorf("empty aud matched")
	}
}

func TestOIDCMiddlewareGetAgentRequiresAuth(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	platformDID, platformKey, _ := identity.GenerateDID()

	svc := &Service{
		Store:       memory.New(),
		Keys:        identity.NewMemoryKeyStore(),
		PlatformKey: platformKey,
		PlatformDID: platformDID,
		Config:      config.Default(),
		NonceCache:  verify.NewMemoryNonceCache(),
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		OIDC:        testVerifier(t, key, "k1"),
	}
	srv := httptest.NewServer(NewRouter(svc))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/v1/agents/did:key:zABC")
	if err != nil {
		t.Fatalf("GET /v1/agents/did:key:zABC: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET /v1/agents/{did} without token: got %d, want 401", resp.StatusCode)
	}
}

func TestOIDCMiddlewareHealthBypass(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	platformDID, platformKey, _ := identity.GenerateDID()

	svc := &Service{
		Store:       memory.New(),
		Keys:        identity.NewMemoryKeyStore(),
		PlatformKey: platformKey,
		PlatformDID: platformDID,
		Config:      config.Default(),
		NonceCache:  verify.NewMemoryNonceCache(),
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		OIDC:        testVerifier(t, key, "k1"),
	}
	srv := httptest.NewServer(NewRouter(svc))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /health without token: got %d, want 200", resp.StatusCode)
	}
}

// TestOIDCMiddlewareEndToEnd wires the OIDC verifier into the router and checks
// that a valid token authorizes registration with the sub as sponsor.
func TestOIDCMiddlewareEndToEnd(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	platformDID, platformKey, _ := identity.GenerateDID()

	svc := &Service{
		Store:       memory.New(),
		Keys:        identity.NewMemoryKeyStore(),
		PlatformKey: platformKey,
		PlatformDID: platformDID,
		Config:      config.Default(),
		NonceCache:  verify.NewMemoryNonceCache(),
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		OIDC:        testVerifier(t, key, "k1"),
	}
	srv := httptest.NewServer(NewRouter(svc))
	defer srv.Close()

	doRegister := func(token string) (int, adtp.RegisterAgentResponse) {
		body := strings.NewReader(`{}`) // no sponsor_did; it comes from the token
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/agents", body)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		defer resp.Body.Close()
		var out adtp.RegisterAgentResponse
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}

	t.Run("valid token registers with sub as sponsor", func(t *testing.T) {
		code, out := doRegister(signJWT(t, key, "k1", "", validClaims()))
		if code != http.StatusCreated {
			t.Fatalf("code = %d, want 201", code)
		}
		if out.SponsorDID != "user@example.com" {
			t.Errorf("sponsor = %q, want sub user@example.com", out.SponsorDID)
		}
	})

	t.Run("no token rejected", func(t *testing.T) {
		if code, _ := doRegister(""); code != http.StatusUnauthorized {
			t.Errorf("code = %d, want 401", code)
		}
	})

	t.Run("expired token rejected", func(t *testing.T) {
		now := time.Now().Unix()
		c := validClaims()
		c["exp"] = now - 100
		if code, _ := doRegister(signJWT(t, key, "k1", "", c)); code != http.StatusUnauthorized {
			t.Errorf("code = %d, want 401", code)
		}
	})
}
