//go:build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	v1 "github.com/Zahanturel/adtp/api/v1"
	"github.com/Zahanturel/adtp/config"
	"github.com/Zahanturel/adtp/internal/identity"
	"github.com/Zahanturel/adtp/internal/verify"
	"github.com/Zahanturel/adtp/store/memory"
)

const testAPIKey = "e2e-test-key-do-not-use-in-production"

type testDaemon struct {
	srv    *httptest.Server
	apiKey string
	url    string
}

func startDaemon(t *testing.T) *testDaemon {
	t.Helper()

	platformDID, platformKey, err := identity.GenerateDID()
	if err != nil {
		t.Fatalf("GenerateDID: %v", err)
	}

	cfg := config.Default()
	cfg.Verify.MaxChainDepth = 10
	cfg.Verify.ClockSkewSeconds = 5
	cfg.Verify.DefaultRiskTier = "HIGH"

	svc := &v1.Service{
		Store:       memory.New(),
		Keys:        identity.NewMemoryKeyStore(),
		PlatformKey: platformKey,
		PlatformDID: platformDID,
		Config:      cfg,
		NonceCache:  verify.NewMemoryNonceCache(),
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		APIKeys:     map[string]bool{testAPIKey: true},
		StartTime:   time.Now().Unix(),
	}

	srv := httptest.NewServer(v1.NewRouter(svc))
	t.Cleanup(srv.Close)

	// Wait for the server to be ready.
	for i := 0; i < 10; i++ {
		conn, err := net.DialTimeout("tcp", srv.Listener.Addr().String(), 100*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	return &testDaemon{srv: srv, apiKey: testAPIKey, url: srv.URL}
}

func (d *testDaemon) do(t *testing.T, method, path string, body any) (int, []byte) {
	t.Helper()
	return d.doWithKey(t, method, path, body, d.apiKey)
}

func (d *testDaemon) doWithKey(t *testing.T, method, path string, body any, key string) (int, []byte) {
	t.Helper()
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		bodyReader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, d.url+path, bodyReader)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do %s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, raw
}

func (d *testDaemon) doJSON(t *testing.T, method, path string, body any, out any) int {
	t.Helper()
	code, raw := d.do(t, method, path, body)
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			t.Fatalf("unmarshal response from %s %s (status %d): %v\nbody: %s", method, path, code, err, raw)
		}
	}
	return code
}

func (d *testDaemon) registerAgent(t *testing.T, sponsorDID string) string {
	t.Helper()
	var resp struct {
		DID   string `json:"did"`
		State string `json:"state"`
	}
	code := d.doJSON(t, "POST", "/v1/agents", map[string]string{"sponsor_did": sponsorDID}, &resp)
	if code != http.StatusCreated {
		t.Fatalf("register agent: got %d, want 201", code)
	}
	if resp.DID == "" {
		t.Fatal("register agent: empty DID")
	}
	if resp.State != "ACTIVE" {
		t.Fatalf("register agent: state = %q, want ACTIVE", resp.State)
	}
	return resp.DID
}

func (d *testDaemon) issueCredential(t *testing.T, agentDID string, caps []map[string]any, expSeconds int64) (string, string) {
	t.Helper()
	var resp struct {
		CID   string `json:"cid"`
		Token string `json:"token"`
	}
	code := d.doJSON(t, "POST", "/v1/credentials", map[string]any{
		"agent_did":    agentDID,
		"capabilities": caps,
		"exp_seconds":  expSeconds,
	}, &resp)
	if code != http.StatusCreated {
		t.Fatalf("issue credential: got %d, want 201", code)
	}
	if resp.CID == "" || resp.Token == "" {
		t.Fatal("issue credential: empty CID or token")
	}
	return resp.CID, resp.Token
}

func (d *testDaemon) delegate(t *testing.T, parentCID, audienceDID, mode string, depthLeft int, caveats []map[string]any) (int, string) {
	t.Helper()
	body := map[string]any{
		"parent_cid":   parentCID,
		"audience_did": audienceDID,
		"mode":         mode,
		"depth_left":   depthLeft,
	}
	if caveats != nil {
		body["caveats"] = caveats
	}
	var resp struct {
		CID string `json:"cid"`
	}
	var errResp struct {
		Error string `json:"error"`
	}
	code, raw := d.do(t, "POST", "/v1/delegations", body)
	if code == http.StatusCreated {
		if err := json.Unmarshal(raw, &resp); err != nil {
			t.Fatalf("unmarshal delegate response: %v", err)
		}
		return code, resp.CID
	}
	_ = json.Unmarshal(raw, &errResp)
	return code, errResp.Error
}

func (d *testDaemon) verify(t *testing.T, leafCID, action, resource string, params map[string]any) (bool, int, string) {
	t.Helper()
	body := map[string]any{
		"chain":    []string{leafCID},
		"action":   action,
		"resource": resource,
	}
	if params != nil {
		body["parameters"] = params
	}
	var resp struct {
		Authorized bool   `json:"authorized"`
		ChainDepth int    `json:"chain_depth"`
		Error      string `json:"error,omitempty"`
		ErrorCode  string `json:"error_code,omitempty"`
	}
	code := d.doJSON(t, "POST", "/v1/verify", body, &resp)
	if code != http.StatusOK {
		t.Fatalf("verify: got status %d, want 200", code)
	}
	if !resp.Authorized {
		t.Logf("verify denied: code=%s error=%s depth=%d", resp.ErrorCode, resp.Error, resp.ChainDepth)
	}
	return resp.Authorized, resp.ChainDepth, resp.ErrorCode
}

func (d *testDaemon) revoke(t *testing.T, subjectCID, scope, status string) int {
	t.Helper()
	var resp struct {
		Seq     int64 `json:"seq"`
		Cascade int   `json:"cascade_count"`
	}
	code := d.doJSON(t, "POST", "/v1/revoke", map[string]string{
		"subject_cid": subjectCID,
		"scope":       scope,
		"status":      status,
	}, &resp)
	return code
}

func (d *testDaemon) getStatus(t *testing.T, cid string) (bool, string) {
	t.Helper()
	var resp struct {
		CID     string `json:"cid"`
		Revoked bool   `json:"revoked"`
		Status  string `json:"status"`
	}
	code := d.doJSON(t, "GET", fmt.Sprintf("/v1/status/%s", cid), nil, &resp)
	if code != http.StatusOK {
		t.Fatalf("get status: got %d, want 200", code)
	}
	return resp.Revoked, resp.Status
}

func toolInvokeCap(resource string, constraints ...map[string]any) map[string]any {
	cap := map[string]any{
		"can":  "tool/invoke",
		"with": resource,
	}
	if len(constraints) > 0 {
		cap["constraints"] = constraints
	}
	return cap
}

func delegateCap(resource string, maxDepth int) map[string]any {
	return map[string]any{
		"can":  "agent/delegate",
		"with": resource,
		"constraints": []map[string]any{
			{"type": "delegation_depth", "max": maxDepth},
		},
	}
}

func timeWindowCaveat(start, end int64) map[string]any {
	return map[string]any{
		"type":  "time_window",
		"start": start,
		"end":   end,
	}
}

func resourceRestrictCaveat(resource string) map[string]any {
	return map[string]any{
		"type":     "resource_restrict",
		"resource": resource,
	}
}

func methodRestrictCaveat(methods ...string) map[string]any {
	return map[string]any{
		"type":    "method_restrict",
		"methods": methods,
	}
}
