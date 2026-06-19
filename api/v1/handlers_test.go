package v1

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/adtp/adtp/config"
	"github.com/adtp/adtp/internal/credential"
	"github.com/adtp/adtp/internal/identity"
	"github.com/adtp/adtp/internal/lifecycle"
	"github.com/adtp/adtp/internal/verify"
	"github.com/adtp/adtp/pkg/adtp"
	"github.com/adtp/adtp/store/memory"
)

// faultyStore wraps the in-memory store and injects failures on selected writes
// to exercise the handlers' 5xx paths.
type faultyStore struct {
	*memory.MemoryStore
	failPutAgent      bool
	failPutCredential bool
	failRegister      bool
}

var errFaulty = errors.New("injected store fault")

func (f *faultyStore) PutAgent(a *lifecycle.Agent) error {
	if f.failPutAgent {
		return errFaulty
	}
	return f.MemoryStore.PutAgent(a)
}

func (f *faultyStore) PutCredential(raw []byte) (string, error) {
	if f.failPutCredential {
		return "", errFaulty
	}
	return f.MemoryStore.PutCredential(raw)
}

func (f *faultyStore) Register(cid string, chain []string) error {
	if f.failRegister {
		return errFaulty
	}
	return f.MemoryStore.Register(cid, chain)
}

func TestHandlerStoreFailures(t *testing.T) {
	fs := &faultyStore{MemoryStore: memory.New()}
	did, key, _ := identity.GenerateDID()
	svc := &Service{
		Store: fs, Keys: identity.NewMemoryKeyStore(), PlatformKey: key, PlatformDID: did,
		Config: config.Default(), NonceCache: verify.NewMemoryNonceCache(),
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		APIKeys: map[string]bool{testAPIKey: true},
	}
	srv := httptest.NewServer(NewRouter(svc))
	defer srv.Close()

	t.Run("register persists agent failure", func(t *testing.T) {
		fs.failPutAgent = true
		defer func() { fs.failPutAgent = false }()
		if code := post(t, srv.URL+"/v1/agents", adtp.RegisterAgentRequest{SponsorDID: did}, nil); code != http.StatusInternalServerError {
			t.Errorf("code = %d, want 500", code)
		}
	})

	var agent adtp.RegisterAgentResponse
	post(t, srv.URL+"/v1/agents", adtp.RegisterAgentRequest{SponsorDID: did}, &agent)

	t.Run("issue credential store failure", func(t *testing.T) {
		fs.failPutCredential = true
		defer func() { fs.failPutCredential = false }()
		code := post(t, srv.URL+"/v1/credentials", adtp.IssueCredentialRequest{
			AgentDID: agent.DID, Capabilities: []adtp.Capability{mustCap(t, credential.CanToolInvoke, "tool://s/x")}, ExpSeconds: 60,
		}, nil)
		if code != http.StatusInternalServerError {
			t.Errorf("code = %d, want 500", code)
		}
	})

	t.Run("delegate registration failure", func(t *testing.T) {
		// Issue a delegable credential first (no faults).
		var issued adtp.IssueCredentialResponse
		post(t, srv.URL+"/v1/credentials", adtp.IssueCredentialRequest{
			AgentDID: agent.DID,
			Capabilities: []adtp.Capability{mustCap(t, credential.CanAgentDelegate, "agent://p/a",
				credential.DelegationDepthConstraint{Type: credential.ConstraintDelegationDepth, Max: 5})},
			ExpSeconds: 3600,
		}, &issued)

		fs.failRegister = true
		defer func() { fs.failRegister = false }()
		code := post(t, srv.URL+"/v1/delegations", adtp.DelegateRequest{
			ParentCID: issued.CID, AudienceDID: "did:key:zB", Mode: "restrict",
			Caveats: adtp.Caveats{credential.NewTimeWindow(1, 1<<40)}, DepthLeft: 4,
		}, nil)
		if code != http.StatusInternalServerError {
			t.Errorf("code = %d, want 500", code)
		}
	})
}

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	did, key, err := identity.GenerateDID()
	if err != nil {
		t.Fatalf("platform key: %v", err)
	}
	svc := &Service{
		Store:       memory.New(),
		Keys:        identity.NewMemoryKeyStore(),
		PlatformKey: key,
		PlatformDID: did,
		Config:      config.Default(),
		NonceCache:  verify.NewMemoryNonceCache(),
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		APIKeys:     map[string]bool{testAPIKey: true},
	}
	srv := httptest.NewServer(NewRouter(svc))
	t.Cleanup(srv.Close)
	return srv
}

// testAPIKey is the key configured on test servers; post() sends it as a bearer
// token so mutating requests pass AuthMiddleware.
const testAPIKey = "test-api-key-0123456789"

func post(t *testing.T, url string, body any, out any) int {
	t.Helper()
	b, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		t.Fatalf("new request %s: %v", url, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testAPIKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil && err != io.EOF {
			t.Fatalf("decode %s: %v", url, err)
		}
	}
	return resp.StatusCode
}

func get(t *testing.T, url string, out any) int {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if out != nil {
		_ = json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode
}

func TestAPIFullFlow(t *testing.T) {
	srv := newTestServer(t)
	now := time.Now().Unix()

	// Read the platform DID from /health to use as the sponsor.
	var health adtp.HealthResponse
	if code := get(t, srv.URL+"/health", &health); code != http.StatusOK {
		t.Fatalf("/health = %d", code)
	}
	platformDID := health.PlatformDID

	// 1. Register two agents.
	var agentA adtp.RegisterAgentResponse
	if code := post(t, srv.URL+"/v1/agents", adtp.RegisterAgentRequest{SponsorDID: platformDID}, &agentA); code != http.StatusCreated {
		t.Fatalf("register A = %d", code)
	}
	if agentA.State != "ACTIVE" || agentA.DID == "" {
		t.Fatalf("agent A = %+v", agentA)
	}
	var agentB adtp.RegisterAgentResponse
	if code := post(t, srv.URL+"/v1/agents", adtp.RegisterAgentRequest{SponsorDID: platformDID}, &agentB); code != http.StatusCreated {
		t.Fatalf("register B = %d", code)
	}

	// 2. Issue a delegable root credential to agent A.
	delegateCap := mustCap(t, credential.CanAgentDelegate, "agent://platform/agents",
		credential.DelegationDepthConstraint{Type: credential.ConstraintDelegationDepth, Max: 5})
	toolCap := mustCap(t, credential.CanToolInvoke, "tool://server/*")
	var issued adtp.IssueCredentialResponse
	if code := post(t, srv.URL+"/v1/credentials", adtp.IssueCredentialRequest{
		AgentDID: agentA.DID, Capabilities: []adtp.Capability{delegateCap, toolCap}, ExpSeconds: 3600,
	}, &issued); code != http.StatusCreated {
		t.Fatalf("issue = %d", code)
	}
	rootCID := issued.CID

	// 3. Delegate (RESTRICT) from the root to agent B.
	var deleg adtp.DelegateResponse
	if code := post(t, srv.URL+"/v1/delegations", adtp.DelegateRequest{
		ParentCID: rootCID, AudienceDID: agentB.DID, Mode: "restrict",
		Caveats:   adtp.Caveats{credential.NewTimeWindow(now-100, now+3600)},
		DepthLeft: 4, ExpSeconds: 3600,
	}, &deleg); code != http.StatusCreated {
		t.Fatalf("delegate = %d", code)
	}
	leafCID := deleg.CID

	// 4. Verify the chain — authorized.
	var v1Resp adtp.VerifyResponse
	if code := post(t, srv.URL+"/v1/verify", adtp.VerifyRequest{
		ChainCIDs: []string{leafCID}, Action: credential.CanToolInvoke, Resource: "tool://server/search",
	}, &v1Resp); code != http.StatusOK {
		t.Fatalf("verify = %d", code)
	}
	if !v1Resp.Authorized {
		t.Fatalf("expected authorized, got %+v", v1Resp)
	}

	// 5. Revoke the root credential (COMPROMISED) — cascades to the leaf.
	var rev adtp.RevokeResponse
	if code := post(t, srv.URL+"/v1/revoke", adtp.RevokeRequest{
		SubjectCID: rootCID, Scope: "subtree", Status: "COMPROMISED",
	}, &rev); code != http.StatusOK {
		t.Fatalf("revoke = %d", code)
	}
	if rev.Cascade != 1 {
		t.Errorf("cascade_count = %d, want 1", rev.Cascade)
	}

	// 6. Verify again — now denied with ADTP_REVOKED.
	var v2Resp adtp.VerifyResponse
	if code := post(t, srv.URL+"/v1/verify", adtp.VerifyRequest{
		ChainCIDs: []string{leafCID}, Action: credential.CanToolInvoke, Resource: "tool://server/search",
	}, &v2Resp); code != http.StatusOK {
		t.Fatalf("verify2 = %d", code)
	}
	if v2Resp.Authorized {
		t.Errorf("expected denied after compromise")
	}
	if v2Resp.ErrorCode != adtp.CodeRevoked {
		t.Errorf("error_code = %q, want %q", v2Resp.ErrorCode, adtp.CodeRevoked)
	}

	// 7. Status of the leaf is revoked.
	var status adtp.StatusResponse
	if code := get(t, srv.URL+"/v1/status/"+leafCID, &status); code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if !status.Revoked {
		t.Errorf("leaf status not revoked: %+v", status)
	}

	// 8. Agent A is ACTIVE.
	var ag adtp.AgentResponse
	if code := get(t, srv.URL+"/v1/agents/"+agentA.DID, &ag); code != http.StatusOK {
		t.Fatalf("get agent = %d", code)
	}
	if ag.State != "ACTIVE" {
		t.Errorf("agent state = %q", ag.State)
	}

	// 9. Revocation list is served and signed.
	var list map[string]any
	if code := get(t, srv.URL+"/v1/revocation/list", &list); code != http.StatusOK {
		t.Fatalf("revocation list = %d", code)
	}
	if list["sig"] == "" {
		t.Errorf("revocation list not signed")
	}
}

func TestAPIErrorCases(t *testing.T) {
	srv := newTestServer(t)

	t.Run("register without sponsor", func(t *testing.T) {
		if code := post(t, srv.URL+"/v1/agents", adtp.RegisterAgentRequest{}, nil); code != http.StatusBadRequest {
			t.Errorf("code = %d, want 400", code)
		}
	})
	t.Run("issue to invalid DID", func(t *testing.T) {
		code := post(t, srv.URL+"/v1/credentials", adtp.IssueCredentialRequest{
			AgentDID: "not-a-did", Capabilities: []adtp.Capability{mustCap(t, credential.CanToolInvoke, "tool://s/x")}, ExpSeconds: 60,
		}, nil)
		if code != http.StatusBadRequest {
			t.Errorf("code = %d, want 400", code)
		}
	})
	t.Run("issue to unregistered agent", func(t *testing.T) {
		did, _, _ := identity.GenerateDID()
		code := post(t, srv.URL+"/v1/credentials", adtp.IssueCredentialRequest{
			AgentDID: did, Capabilities: []adtp.Capability{mustCap(t, credential.CanToolInvoke, "tool://s/x")}, ExpSeconds: 60,
		}, nil)
		if code != http.StatusNotFound {
			t.Errorf("code = %d, want 404", code)
		}
	})
	t.Run("delegate unknown parent", func(t *testing.T) {
		code := post(t, srv.URL+"/v1/delegations", adtp.DelegateRequest{
			ParentCID: "bafkreimissing", AudienceDID: "did:key:zB", Mode: "restrict",
			Caveats: adtp.Caveats{credential.NewTimeWindow(1, 2)}, DepthLeft: 1,
		}, nil)
		if code != http.StatusNotFound {
			t.Errorf("code = %d, want 404", code)
		}
	})
	t.Run("unauthorized revocation status", func(t *testing.T) {
		code := post(t, srv.URL+"/v1/revoke", adtp.RevokeRequest{
			SubjectCID: "bafkreix", Scope: "credential", Status: "GIBBERISH",
		}, nil)
		if code != http.StatusForbidden {
			t.Errorf("code = %d, want 403", code)
		}
	})
	t.Run("missing revoke subject", func(t *testing.T) {
		code := post(t, srv.URL+"/v1/revoke", adtp.RevokeRequest{Scope: "credential", Status: "REVOKED"}, nil)
		if code != http.StatusBadRequest {
			t.Errorf("code = %d, want 400", code)
		}
	})
	t.Run("agent not found", func(t *testing.T) {
		if code := get(t, srv.URL+"/v1/agents/did:key:zNope", nil); code != http.StatusNotFound {
			t.Errorf("code = %d, want 404", code)
		}
	})
	t.Run("malformed json", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/agents", bytes.NewReader([]byte("{not json")))
		req.Header.Set("Authorization", "Bearer "+testAPIKey)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("code = %d, want 400", resp.StatusCode)
		}
	})
}

func TestAPIRestateDelegation(t *testing.T) {
	srv := newTestServer(t)

	var health adtp.HealthResponse
	get(t, srv.URL+"/health", &health)

	var agentA, agentB adtp.RegisterAgentResponse
	post(t, srv.URL+"/v1/agents", adtp.RegisterAgentRequest{SponsorDID: health.PlatformDID}, &agentA)
	post(t, srv.URL+"/v1/agents", adtp.RegisterAgentRequest{SponsorDID: health.PlatformDID}, &agentB)

	var issued adtp.IssueCredentialResponse
	post(t, srv.URL+"/v1/credentials", adtp.IssueCredentialRequest{
		AgentDID:     agentA.DID,
		Capabilities: []adtp.Capability{mustCap(t, credential.CanToolInvoke, "tool://server/*")},
		ExpSeconds:   3600,
	}, &issued)

	// RESTATE a covered subset.
	var deleg adtp.DelegateResponse
	if code := post(t, srv.URL+"/v1/delegations", adtp.DelegateRequest{
		ParentCID: issued.CID, AudienceDID: agentB.DID, Mode: "restate",
		Capabilities: []adtp.Capability{mustCap(t, credential.CanToolInvoke, "tool://server/search")},
	}, &deleg); code != http.StatusCreated {
		t.Fatalf("restate delegate = %d", code)
	}

	var vResp adtp.VerifyResponse
	post(t, srv.URL+"/v1/verify", adtp.VerifyRequest{
		ChainCIDs: []string{deleg.CID}, Action: credential.CanToolInvoke, Resource: "tool://server/search",
	}, &vResp)
	if !vResp.Authorized {
		t.Errorf("restate chain not authorized: %+v", vResp)
	}

	// RESTATE escalation is forbidden.
	if code := post(t, srv.URL+"/v1/delegations", adtp.DelegateRequest{
		ParentCID: issued.CID, AudienceDID: agentB.DID, Mode: "restate",
		Capabilities: []adtp.Capability{mustCap(t, credential.CanResourceWrite, "resource://db/x")},
	}, nil); code != http.StatusForbidden {
		t.Errorf("escalation code = %d, want 403", code)
	}
}

func TestAPIVerifyProvidedInvocation(t *testing.T) {
	srv := newTestServer(t)

	t.Run("malformed invocation", func(t *testing.T) {
		code := post(t, srv.URL+"/v1/verify", adtp.VerifyRequest{
			ChainCIDs: []string{"bafkreix"}, Action: "tool/invoke", Resource: "tool://s/x",
			Invocation: json.RawMessage(`{not-json`),
		}, nil)
		if code != http.StatusBadRequest {
			t.Errorf("code = %d, want 400", code)
		}
	})

	t.Run("well-formed but invalid invocation is denied", func(t *testing.T) {
		var resp adtp.VerifyResponse
		post(t, srv.URL+"/v1/verify", adtp.VerifyRequest{
			ChainCIDs: []string{"bafkreix"}, Action: "tool/invoke", Resource: "tool://s/x",
			Invocation: json.RawMessage(`{"typ":"aitp/inv/1"}`),
		}, &resp)
		if resp.Authorized {
			t.Errorf("empty invocation should not authorize")
		}
	})
}

func TestAPIPlainRevoke(t *testing.T) {
	srv := newTestServer(t)
	var health adtp.HealthResponse
	get(t, srv.URL+"/health", &health)

	var agent adtp.RegisterAgentResponse
	post(t, srv.URL+"/v1/agents", adtp.RegisterAgentRequest{SponsorDID: health.PlatformDID}, &agent)
	var issued adtp.IssueCredentialResponse
	post(t, srv.URL+"/v1/credentials", adtp.IssueCredentialRequest{
		AgentDID: agent.DID, Capabilities: []adtp.Capability{mustCap(t, credential.CanToolInvoke, "tool://s/x")}, ExpSeconds: 3600,
	}, &issued)

	var rev adtp.RevokeResponse
	if code := post(t, srv.URL+"/v1/revoke", adtp.RevokeRequest{
		SubjectCID: issued.CID, Scope: "credential", Status: "REVOKED",
	}, &rev); code != http.StatusOK {
		t.Fatalf("revoke = %d", code)
	}
	if rev.Seq != 1 || rev.Status != "REVOKED" || rev.Cascade != 0 {
		t.Errorf("revoke response = %+v", rev)
	}
	var status adtp.StatusResponse
	get(t, srv.URL+"/v1/status/"+issued.CID, &status)
	if !status.Revoked || status.Status != "REVOKED" {
		t.Errorf("status = %+v", status)
	}
}

func TestAPIDelegateNonDelegableParent(t *testing.T) {
	srv := newTestServer(t)
	var health adtp.HealthResponse
	get(t, srv.URL+"/health", &health)

	var agent adtp.RegisterAgentResponse
	post(t, srv.URL+"/v1/agents", adtp.RegisterAgentRequest{SponsorDID: health.PlatformDID}, &agent)
	// A credential without an agent/delegate capability cannot delegate.
	var issued adtp.IssueCredentialResponse
	post(t, srv.URL+"/v1/credentials", adtp.IssueCredentialRequest{
		AgentDID: agent.DID, Capabilities: []adtp.Capability{mustCap(t, credential.CanToolInvoke, "tool://s/x")}, ExpSeconds: 3600,
	}, &issued)

	code := post(t, srv.URL+"/v1/delegations", adtp.DelegateRequest{
		ParentCID: issued.CID, AudienceDID: "did:key:zB", Mode: "restrict",
		Caveats: adtp.Caveats{credential.NewTimeWindow(1, 1<<40)}, DepthLeft: 1,
	}, nil)
	if code != http.StatusBadRequest {
		t.Errorf("non-delegable parent code = %d, want 400", code)
	}
}

func TestAPIVerifyMissingLeafNoInvocation(t *testing.T) {
	srv := newTestServer(t)
	code := post(t, srv.URL+"/v1/verify", adtp.VerifyRequest{
		ChainCIDs: []string{"bafkreimissing"}, Action: "tool/invoke", Resource: "tool://s/x",
	}, nil)
	if code != http.StatusBadRequest {
		t.Errorf("code = %d, want 400", code)
	}
}

func TestAPIMultiHopDelegation(t *testing.T) {
	srv := newTestServer(t)
	now := time.Now().Unix()
	var health adtp.HealthResponse
	get(t, srv.URL+"/health", &health)

	reg := func() string {
		var a adtp.RegisterAgentResponse
		post(t, srv.URL+"/v1/agents", adtp.RegisterAgentRequest{SponsorDID: health.PlatformDID}, &a)
		return a.DID
	}
	a, b, c := reg(), reg(), reg()

	var issued adtp.IssueCredentialResponse
	post(t, srv.URL+"/v1/credentials", adtp.IssueCredentialRequest{
		AgentDID: a,
		Capabilities: []adtp.Capability{
			mustCap(t, credential.CanAgentDelegate, "agent://p/a", credential.DelegationDepthConstraint{Type: credential.ConstraintDelegationDepth, Max: 5}),
			mustCap(t, credential.CanToolInvoke, "tool://server/*"),
		},
		ExpSeconds: 3600,
	}, &issued)

	caveats := adtp.Caveats{credential.NewTimeWindow(now-100, now+3600)}
	var hop1 adtp.DelegateResponse
	post(t, srv.URL+"/v1/delegations", adtp.DelegateRequest{
		ParentCID: issued.CID, AudienceDID: b, Mode: "restrict", Caveats: caveats, DepthLeft: 4,
	}, &hop1)
	// Delegate again from the RESTRICT block (exercises the block-parent path).
	var hop2 adtp.DelegateResponse
	if code := post(t, srv.URL+"/v1/delegations", adtp.DelegateRequest{
		ParentCID: hop1.CID, AudienceDID: c, Mode: "restrict", Caveats: caveats, DepthLeft: 3,
	}, &hop2); code != http.StatusCreated {
		t.Fatalf("second hop = %d", code)
	}

	var vResp adtp.VerifyResponse
	post(t, srv.URL+"/v1/verify", adtp.VerifyRequest{
		ChainCIDs: []string{hop2.CID}, Action: credential.CanToolInvoke, Resource: "tool://server/search",
	}, &vResp)
	if !vResp.Authorized || vResp.ChainDepth != 3 {
		t.Errorf("multi-hop verify = %+v", vResp)
	}

	// Status of an unrevoked credential reports active.
	var status adtp.StatusResponse
	get(t, srv.URL+"/v1/status/"+hop2.CID, &status)
	if status.Revoked {
		t.Errorf("unrevoked credential reported as revoked")
	}
}

func TestAPIDelegateValidation(t *testing.T) {
	srv := newTestServer(t)
	now := time.Now().Unix()
	var health adtp.HealthResponse
	get(t, srv.URL+"/health", &health)

	reg := func() string {
		var a adtp.RegisterAgentResponse
		post(t, srv.URL+"/v1/agents", adtp.RegisterAgentRequest{SponsorDID: health.PlatformDID}, &a)
		return a.DID
	}
	a, b := reg(), reg()

	var root adtp.IssueCredentialResponse
	post(t, srv.URL+"/v1/credentials", adtp.IssueCredentialRequest{
		AgentDID: a,
		Capabilities: []adtp.Capability{
			mustCap(t, credential.CanAgentDelegate, "agent://p/a", credential.DelegationDepthConstraint{Type: credential.ConstraintDelegationDepth, Max: 5}),
			mustCap(t, credential.CanToolInvoke, "tool://server/*"),
		},
		ExpSeconds: 3600,
	}, &root)

	t.Run("invalid mode", func(t *testing.T) {
		if code := post(t, srv.URL+"/v1/delegations", adtp.DelegateRequest{
			ParentCID: root.CID, AudienceDID: b, Mode: "teleport", DepthLeft: 4,
		}, nil); code != http.StatusBadRequest {
			t.Errorf("code = %d, want 400", code)
		}
	})

	t.Run("restate without capabilities", func(t *testing.T) {
		if code := post(t, srv.URL+"/v1/delegations", adtp.DelegateRequest{
			ParentCID: root.CID, AudienceDID: b, Mode: "restate",
		}, nil); code != http.StatusBadRequest {
			t.Errorf("code = %d, want 400", code)
		}
	})

	t.Run("restate from a restrict block", func(t *testing.T) {
		var block adtp.DelegateResponse
		post(t, srv.URL+"/v1/delegations", adtp.DelegateRequest{
			ParentCID: root.CID, AudienceDID: b, Mode: "restrict",
			Caveats: adtp.Caveats{credential.NewTimeWindow(now-100, now+3600)}, DepthLeft: 4,
		}, &block)
		if code := post(t, srv.URL+"/v1/delegations", adtp.DelegateRequest{
			ParentCID: block.CID, AudienceDID: b, Mode: "restate",
			Capabilities: []adtp.Capability{mustCap(t, credential.CanToolInvoke, "tool://server/search")},
		}, nil); code != http.StatusBadRequest {
			t.Errorf("code = %d, want 400", code)
		}
	})
}

func TestAPIVerifyKeyNotHeld(t *testing.T) {
	srv := newTestServer(t)
	now := time.Now().Unix()
	var health adtp.HealthResponse
	get(t, srv.URL+"/health", &health)

	var a adtp.RegisterAgentResponse
	post(t, srv.URL+"/v1/agents", adtp.RegisterAgentRequest{SponsorDID: health.PlatformDID}, &a)
	var issued adtp.IssueCredentialResponse
	post(t, srv.URL+"/v1/credentials", adtp.IssueCredentialRequest{
		AgentDID: a.DID,
		Capabilities: []adtp.Capability{
			mustCap(t, credential.CanAgentDelegate, "agent://p/a", credential.DelegationDepthConstraint{Type: credential.ConstraintDelegationDepth, Max: 5}),
			mustCap(t, credential.CanToolInvoke, "tool://server/*"),
		},
		ExpSeconds: 3600,
	}, &issued)

	// Delegate to an unregistered DID, then ask to verify without an invocation:
	// the daemon cannot custodially sign for an agent whose key it does not hold.
	var hop adtp.DelegateResponse
	post(t, srv.URL+"/v1/delegations", adtp.DelegateRequest{
		ParentCID: issued.CID, AudienceDID: "did:key:zStranger", Mode: "restrict",
		Caveats: adtp.Caveats{credential.NewTimeWindow(now-100, now+3600)}, DepthLeft: 4,
	}, &hop)

	if code := post(t, srv.URL+"/v1/verify", adtp.VerifyRequest{
		ChainCIDs: []string{hop.CID}, Action: credential.CanToolInvoke, Resource: "tool://server/search",
	}, nil); code != http.StatusBadRequest {
		t.Errorf("verify without held key = %d, want 400", code)
	}
}

func TestParseTier(t *testing.T) {
	cases := map[string]verify.RiskTier{
		"HIGH": verify.TierHigh, "MEDIUM": verify.TierMedium, "LOW": verify.TierLow,
		"ANALYTICS": verify.TierAnalytics, "": verify.TierMedium, "other": verify.TierMedium,
	}
	for in, want := range cases {
		if got := parseTier(in); got != want {
			t.Errorf("parseTier(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestAPIBodyTooLarge(t *testing.T) {
	srv := newTestServer(t)
	big := bytes.Repeat([]byte("a"), 70*1024)
	body := append(append([]byte(`{"sponsor_did":"`), big...), []byte(`"}`)...)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/agents", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testAPIKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("code = %d, want 413", resp.StatusCode)
	}
}

func TestAPIErrorSanitization(t *testing.T) {
	srv := newTestServer(t)
	var health adtp.HealthResponse
	get(t, srv.URL+"/health", &health)

	var agent adtp.RegisterAgentResponse
	post(t, srv.URL+"/v1/agents", adtp.RegisterAgentRequest{SponsorDID: health.PlatformDID}, &agent)
	// A credential without an agent/delegate capability cannot delegate; the
	// failure must not leak internal error detail to the client.
	var issued adtp.IssueCredentialResponse
	post(t, srv.URL+"/v1/credentials", adtp.IssueCredentialRequest{
		AgentDID: agent.DID, Capabilities: []adtp.Capability{mustCap(t, credential.CanToolInvoke, "tool://s/x")}, ExpSeconds: 3600,
	}, &issued)

	var errResp adtp.ErrorResponse
	code := post(t, srv.URL+"/v1/delegations", adtp.DelegateRequest{
		ParentCID: issued.CID, AudienceDID: "did:key:zB", Mode: "restrict",
		Caveats: adtp.Caveats{credential.NewTimeWindow(1, 2)}, DepthLeft: 1,
	}, &errResp)
	if code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400", code)
	}
	if errResp.Error != "parent cannot delegate" {
		t.Errorf("error = %q, want generic 'parent cannot delegate'", errResp.Error)
	}
	if strings.Contains(errResp.Error, "aitp/") || strings.Contains(errResp.Error, "agent/delegate") {
		t.Errorf("response leaked internal detail: %q", errResp.Error)
	}
}

func mustCap(t *testing.T, can, with string, cs ...credential.Constraint) credential.Capability {
	t.Helper()
	c, err := credential.NewCapability(can, with, cs...)
	if err != nil {
		t.Fatalf("NewCapability: %v", err)
	}
	return c
}
