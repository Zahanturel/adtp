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
		b64url(key.PublicKey.N.Bytes()), b64url(big.NewInt(int64(key.PublicKey.E)).Bytes()))

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
