package v1

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/adtp/adtp/pkg/adtp"
)

// doReq issues a request with an optional bearer token and returns the status.
func doReq(t *testing.T, method, url, token string, body any) int {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func TestAuthMiddleware(t *testing.T) {
	srv := newTestServer(t)
	var health adtp.HealthResponse
	get(t, srv.URL+"/health", &health) // health open

	reg := adtp.RegisterAgentRequest{SponsorDID: health.PlatformDID}

	t.Run("mutating without auth header -> 401", func(t *testing.T) {
		if code := doReq(t, http.MethodPost, srv.URL+"/v1/agents", "", reg); code != http.StatusUnauthorized {
			t.Errorf("code = %d, want 401", code)
		}
	})
	t.Run("mutating with invalid key -> 401", func(t *testing.T) {
		if code := doReq(t, http.MethodPost, srv.URL+"/v1/agents", "wrong-key", reg); code != http.StatusUnauthorized {
			t.Errorf("code = %d, want 401", code)
		}
	})
	t.Run("mutating with valid key -> proceeds", func(t *testing.T) {
		if code := doReq(t, http.MethodPost, srv.URL+"/v1/agents", testAPIKey, reg); code != http.StatusCreated {
			t.Errorf("code = %d, want 201", code)
		}
	})
	t.Run("health open without auth -> 200", func(t *testing.T) {
		if code := doReq(t, http.MethodGet, srv.URL+"/health", "", nil); code != http.StatusOK {
			t.Errorf("code = %d, want 200", code)
		}
	})
	t.Run("read-only status open without auth -> 200", func(t *testing.T) {
		if code := doReq(t, http.MethodGet, srv.URL+"/v1/status/bafkreitest", "", nil); code != http.StatusOK {
			t.Errorf("code = %d, want 200", code)
		}
	})
	t.Run("malformed bearer -> 401", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/agents", bytes.NewReader([]byte("{}")))
		req.Header.Set("Authorization", "Token "+testAPIKey) // wrong scheme
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("code = %d, want 401", resp.StatusCode)
		}
	})
}

// TestAuthMiddlewareEmptyKeysFailsClosed verifies that with no configured keys,
// every mutating request is rejected.
func TestAuthMiddlewareEmptyKeysFailsClosed(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/x", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	h := AuthMiddleware(map[string]bool{})(mux)
	srv := httptest.NewServer(h)
	defer srv.Close()

	if code := doReq(t, http.MethodPost, srv.URL+"/v1/x", "anything", nil); code != http.StatusUnauthorized {
		t.Errorf("empty keys: code = %d, want 401", code)
	}
}
