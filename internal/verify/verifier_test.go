package verify

import (
	"testing"
	"time"

	"github.com/adtp/adtp/internal/audit"
	"github.com/adtp/adtp/internal/credential"
	"github.com/adtp/adtp/internal/delegation"
	"github.com/adtp/adtp/internal/revocation"
)

func TestVerifyHappyPath(t *testing.T) {
	f := freshChain(t)
	res := Verify(nil, f.invoke(t), f.config)
	if !res.OK {
		t.Fatalf("verification failed: %v", res.Error)
	}
	if res.AuthorizedCapability == nil || res.AuthorizedCapability.Can != credential.CanToolInvoke {
		t.Errorf("authorized capability = %+v", res.AuthorizedCapability)
	}
	if res.Chain == nil || len(res.Chain.Elements) != 3 {
		t.Errorf("unexpected chain: %+v", res.Chain)
	}
}

func TestVerifyUnauthorizedResource(t *testing.T) {
	f := freshChain(t)
	inv, err := CreateInvocation(f.leafCID, credential.CanToolInvoke, "tool://other/thing", nil, f.leafKey, f.verifierDID, "")
	if err != nil {
		t.Fatalf("CreateInvocation: %v", err)
	}
	res := Verify(nil, inv, f.config)
	if res.OK || res.Error.Code != CodeCapInsufficient {
		t.Errorf("code = %v, want V007 (got OK=%v)", res.Error, res.OK)
	}
}

func TestVerifyExpiredChain(t *testing.T) {
	now := time.Now().Unix()
	f := restrictChain(t, now-100, now-3600) // expired
	res := Verify(nil, f.invoke(t), f.config)
	if res.OK || res.Error.Code != CodeExpired {
		t.Errorf("code = %v, want V002 (OK=%v)", res.Error, res.OK)
	}
}

func TestVerifyRevoked(t *testing.T) {
	f := freshChain(t)
	key, did := genKey(t)
	entry, err := revocation.CreateRevocationEntry(
		revocation.RevocationSubject{CID: f.leafCID}, revocation.ScopeCredential, revocation.StatusRevoked,
		revocation.RevocationAuth{DID: did, Basis: revocation.AuthPlatform}, 1, "", key)
	if err != nil {
		t.Fatalf("CreateRevocationEntry: %v", err)
	}
	if err := f.config.RevocationCache.(*revocation.MemoryRevocationCache).Revoke(*entry); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	res := Verify(nil, f.invoke(t), f.config)
	if res.OK || res.Error.Code != CodeRevoked {
		t.Errorf("code = %v, want V004 (OK=%v)", res.Error, res.OK)
	}
}

func TestVerifyCompromised(t *testing.T) {
	f := freshChain(t)
	key, did := genKey(t)
	entry, err := revocation.CreateRevocationEntry(
		revocation.RevocationSubject{DID: f.leafDID}, revocation.ScopeIdentity, revocation.StatusCompromised,
		revocation.RevocationAuth{DID: did, Basis: revocation.AuthPlatform}, 1, "", key)
	if err != nil {
		t.Fatalf("CreateRevocationEntry: %v", err)
	}
	if err := f.config.RevocationCache.(*revocation.MemoryRevocationCache).Revoke(*entry); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	res := Verify(nil, f.invoke(t), f.config)
	if res.OK || res.Error.Code != CodeCompromised {
		t.Errorf("code = %v, want V006 (OK=%v)", res.Error, res.OK)
	}
}

// TestVerifyRejectsCIDMismatch: a store that serves content not matching the
// requested CID (a poisoned cache / forged self-loop) must be rejected at chain
// build with a CID mismatch (SD-5, Section 10.2). Content addressing makes a
// genuine cycle infeasible, so this is the realized form of the old "circular"
// rejection.
func TestVerifyRejectsCIDMismatch(t *testing.T) {
	config := &VerifierConfig{
		VerifierDID:     "did:key:zV",
		TrustedRootDIDs: map[string]bool{},
		ProofStore:      loopStore{},
		NonceCache:      NewMemoryNonceCache(),
	}
	key, _ := genKey(t)
	inv, err := CreateInvocation("bafkreiloopaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "tool/invoke", "tool://s/x", nil, key, "did:key:zV", "")
	if err != nil {
		t.Fatalf("CreateInvocation: %v", err)
	}
	res := Verify(nil, inv, config)
	if res.OK || res.Error.Code != CodeCIDMismatch {
		t.Errorf("code = %v, want V018 CID mismatch (OK=%v)", res.Error, res.OK)
	}
}

func TestVerifyCrossOrg(t *testing.T) {
	f := freshChain(t)
	inv := f.invoke(t)
	// The root is no longer a directly trusted root.
	f.config.TrustedRootDIDs = map[string]bool{}

	// Without a trust policy, an untrusted root is rejected at step 3.
	if res := Verify(nil, inv, f.config); res.OK || res.Error.Code != CodeUntrustedRoot {
		t.Fatalf("no-policy code = %v, want V012 (OK=%v)", res.Error, res.OK)
	}

	// With a matching policy, the cross-org chain verifies. The previous attempt
	// failed before the nonce was consumed (step 3 precedes step 10), so the same
	// invocation is still fresh.
	f.config.TrustPolicies = []TrustPolicy{{Platforms: []string{f.platformDID}, MaxDelegationDepth: 10}}
	if res := Verify(nil, inv, f.config); !res.OK {
		t.Errorf("cross-org with policy failed: %v", res.Error)
	}
}

func TestVerifyCrossOrgDepthPolicy(t *testing.T) {
	f := freshChain(t)
	f.config.TrustedRootDIDs = map[string]bool{}
	f.config.TrustPolicies = []TrustPolicy{{Platforms: []string{f.platformDID}, MaxDelegationDepth: 1}}
	res := Verify(nil, f.invoke(t), f.config)
	if res.OK || res.Error.Code != CodeCrossOrg {
		t.Errorf("code = %v, want V013 (OK=%v)", res.Error, res.OK)
	}
}

func TestVerifyReplay(t *testing.T) {
	f := freshChain(t)
	inv := f.invoke(t)
	if res := Verify(nil, inv, f.config); !res.OK {
		t.Fatalf("first verify failed: %v", res.Error)
	}
	if res := Verify(nil, inv, f.config); res.OK || res.Error.Code != CodePoPFailed {
		t.Errorf("replay code = %v, want V014 (OK=%v)", res.Error, res.OK)
	}
}

func TestVerifyWrongPresenter(t *testing.T) {
	f := freshChain(t)
	wrongKey, _ := genKey(t)
	inv, err := CreateInvocation(f.leafCID, credential.CanToolInvoke, "tool://server/search", nil, wrongKey, f.verifierDID, "")
	if err != nil {
		t.Fatalf("CreateInvocation: %v", err)
	}
	res := Verify(nil, inv, f.config)
	if res.OK || res.Error.Code != CodePoPFailed {
		t.Errorf("code = %v, want V014 (OK=%v)", res.Error, res.OK)
	}
}

func TestVerifyEscalationRestate(t *testing.T) {
	now := time.Now().Unix()
	store := delegation.NewMemoryProofStore()
	platformKey, platformDID := genKey(t)
	agentKey, agentDID := genKey(t)
	leafKey, leafDID := genKey(t)
	_, verifierDID := genKey(t)

	toolCap := vcap(t, credential.CanToolInvoke, "tool://server/*")
	rootToken, err := credential.CreateUCAN(credential.UCANPayload{
		Iss: platformDID, Aud: agentDID,
		Att: []credential.Capability{toolCap},
		Prf: []string{}, Exp: now + 3600, Nbf: now - 60, Iat: now,
	}, platformKey)
	if err != nil {
		t.Fatalf("CreateUCAN: %v", err)
	}
	root, err := credential.ParseUCAN(rootToken)
	if err != nil {
		t.Fatalf("ParseUCAN: %v", err)
	}
	store.Put([]byte(rootToken))

	// A malicious RESTATE hop restating a capability the root never granted.
	// CreateRestateHop does not enforce subset; the verifier must reject it.
	escalated := []credential.Capability{vcap(t, credential.CanResourceWrite, "resource://secret/data")}
	hopToken, err := credential.CreateRestateHop(root, leafDID, escalated, agentKey)
	if err != nil {
		t.Fatalf("CreateRestateHop: %v", err)
	}
	hopCID := store.Put([]byte(hopToken))

	config := &VerifierConfig{
		VerifierDID:     verifierDID,
		TrustedRootDIDs: map[string]bool{platformDID: true},
		MaxChainDepth:   10,
		ProofStore:      store,
		NonceCache:      NewMemoryNonceCache(),
		RevocationCache: revocation.NewMemoryRevocationCache(),
	}
	inv, err := CreateInvocation(hopCID, credential.CanResourceWrite, "resource://secret/data", nil, leafKey, verifierDID, "")
	if err != nil {
		t.Fatalf("CreateInvocation: %v", err)
	}
	res := Verify(nil, inv, config)
	if res.OK || res.Error.Code != CodeAttenuation {
		t.Errorf("code = %v, want V008 (OK=%v)", res.Error, res.OK)
	}
}

func TestVerifyDeepChainExceedsDepth(t *testing.T) {
	now := time.Now().Unix()
	store := delegation.NewMemoryProofStore()
	platformKey, platformDID := genKey(t)
	agentKey, agentDID := genKey(t)

	delegateCap := vcap(t, credential.CanAgentDelegate, "agent://platform/agents",
		credential.DelegationDepthConstraint{Type: credential.ConstraintDelegationDepth, Max: 20})
	toolCap := vcap(t, credential.CanToolInvoke, "tool://server/*")
	rootToken, err := credential.CreateUCAN(credential.UCANPayload{
		Iss: platformDID, Aud: agentDID,
		Att: []credential.Capability{delegateCap, toolCap},
		Prf: []string{}, Exp: now + 3600, Nbf: now - 60, Iat: now,
	}, platformKey)
	if err != nil {
		t.Fatalf("CreateUCAN: %v", err)
	}
	root, err := credential.ParseUCAN(rootToken)
	if err != nil {
		t.Fatalf("ParseUCAN: %v", err)
	}
	parent, err := delegation.ParentFromUCAN(root, store.Put([]byte(rootToken)))
	if err != nil {
		t.Fatalf("ParentFromUCAN: %v", err)
	}

	caveats := credential.Constraints{credential.NewTimeWindow(now-100, now+3600)}
	curKey := agentKey
	leafKey := agentKey
	var leafCID string
	for i, dl := 0, 11; i < 11; i, dl = i+1, dl-1 {
		childKey, childDID := genKey(t)
		block, cid, err := delegation.DelegateRestrict(parent, childDID, caveats, dl, curKey, store)
		if err != nil {
			t.Fatalf("DelegateRestrict hop %d: %v", i, err)
		}
		parent = delegation.ParentFromBlock(block, cid)
		curKey, leafKey, leafCID = childKey, childKey, cid
	}

	_, verifierDID := genKey(t)
	config := &VerifierConfig{
		VerifierDID:     verifierDID,
		TrustedRootDIDs: map[string]bool{platformDID: true},
		MaxChainDepth:   10,
		ProofStore:      store,
		NonceCache:      NewMemoryNonceCache(),
		RevocationCache: revocation.NewMemoryRevocationCache(),
	}
	inv, err := CreateInvocation(leafCID, credential.CanToolInvoke, "tool://server/search", nil, leafKey, verifierDID, "")
	if err != nil {
		t.Fatalf("CreateInvocation: %v", err)
	}
	res := Verify(nil, inv, config)
	if res.OK || res.Error.Code != CodeChainTooDeep {
		t.Errorf("code = %v, want V010 (OK=%v)", res.Error, res.OK)
	}
}

func TestVerifyRestateHappyPath(t *testing.T) {
	now := time.Now().Unix()
	store := delegation.NewMemoryProofStore()
	platformKey, platformDID := genKey(t)
	agentKey, agentDID := genKey(t)
	leafKey, leafDID := genKey(t)
	_, verifierDID := genKey(t)

	toolCap := vcap(t, credential.CanToolInvoke, "tool://server/*")
	rootToken, err := credential.CreateUCAN(credential.UCANPayload{
		Iss: platformDID, Aud: agentDID,
		Att: []credential.Capability{toolCap},
		Prf: []string{}, Exp: now + 3600, Nbf: now - 60, Iat: now,
	}, platformKey)
	if err != nil {
		t.Fatalf("CreateUCAN: %v", err)
	}
	root, err := credential.ParseUCAN(rootToken)
	if err != nil {
		t.Fatalf("ParseUCAN: %v", err)
	}
	store.Put([]byte(rootToken))

	subset := []credential.Capability{vcap(t, credential.CanToolInvoke, "tool://server/search")}
	_, hopCID, err := delegation.DelegateRestate(root, leafDID, subset, agentKey, store)
	if err != nil {
		t.Fatalf("DelegateRestate: %v", err)
	}

	config := &VerifierConfig{
		VerifierDID:     verifierDID,
		TrustedRootDIDs: map[string]bool{platformDID: true},
		MaxChainDepth:   10,
		ProofStore:      store,
		NonceCache:      NewMemoryNonceCache(),
		RevocationCache: revocation.NewMemoryRevocationCache(),
	}
	inv, err := CreateInvocation(hopCID, credential.CanToolInvoke, "tool://server/search", nil, leafKey, verifierDID, "")
	if err != nil {
		t.Fatalf("CreateInvocation: %v", err)
	}
	if res := Verify(nil, inv, config); !res.OK {
		t.Errorf("RESTATE verification failed: %v", res.Error)
	}
}

// TestVerifyRootOnlyInlineToken exercises the inline-leaf overlay path: a
// direct root credential presented with no proof store.
func TestVerifyRootOnlyInlineToken(t *testing.T) {
	now := time.Now().Unix()
	platformKey, platformDID := genKey(t)
	agentKey, agentDID := genKey(t)
	_, verifierDID := genKey(t)

	toolCap := vcap(t, credential.CanToolInvoke, "tool://server/search")
	rootToken, err := credential.CreateUCAN(credential.UCANPayload{
		Iss: platformDID, Aud: agentDID,
		Att: []credential.Capability{toolCap},
		Prf: []string{}, Exp: now + 3600, Nbf: now - 60, Iat: now,
	}, platformKey)
	if err != nil {
		t.Fatalf("CreateUCAN: %v", err)
	}
	root, err := credential.ParseUCAN(rootToken)
	if err != nil {
		t.Fatalf("ParseUCAN: %v", err)
	}

	config := &VerifierConfig{
		VerifierDID:     verifierDID,
		TrustedRootDIDs: map[string]bool{platformDID: true},
		NonceCache:      NewMemoryNonceCache(),
		RiskTierFn:      func(string) RiskTier { return TierLow },
		NowFn:           func() int64 { return time.Now().Unix() },
	}
	// The agent (root audience) is the presenter.
	inv, err := CreateInvocation(root.CID(), credential.CanToolInvoke, "tool://server/search", nil, agentKey, verifierDID, "")
	if err != nil {
		t.Fatalf("CreateInvocation: %v", err)
	}
	if res := Verify(root, inv, config); !res.OK {
		t.Errorf("root-only verification failed: %v", res.Error)
	}
}

// TestVerifyMissingParent exercises the empty-store path when a referenced proof
// is absent.
func TestVerifyMissingParent(t *testing.T) {
	now := time.Now().Unix()
	key, did := genKey(t)
	_, verifierDID := genKey(t)
	// A hop whose parent proof is not available anywhere.
	hopToken, err := credential.CreateUCAN(credential.UCANPayload{
		Iss: "did:key:zParent", Aud: did,
		Att: []credential.Capability{vcap(t, credential.CanToolInvoke, "tool://s/x")},
		Prf: []string{"bafkreimissingaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		Exp: now + 3600, Nbf: now - 60, Iat: now,
	}, key)
	if err != nil {
		t.Fatalf("CreateUCAN: %v", err)
	}
	hop, err := credential.ParseUCAN(hopToken)
	if err != nil {
		t.Fatalf("ParseUCAN: %v", err)
	}
	config := &VerifierConfig{VerifierDID: verifierDID, NonceCache: NewMemoryNonceCache()}
	inv, err := CreateInvocation(hop.CID(), credential.CanToolInvoke, "tool://s/x", nil, key, verifierDID, "")
	if err != nil {
		t.Fatalf("CreateInvocation: %v", err)
	}
	res := Verify(hop, inv, config)
	if res.OK || res.Error.Code != CodeProofCacheMiss {
		t.Errorf("code = %v, want O004 (OK=%v)", res.Error, res.OK)
	}
}

func TestVerifyNoInvocation(t *testing.T) {
	res := Verify(nil, nil, &VerifierConfig{})
	if res.OK || res.Error.Code != CodePoPFailed {
		t.Errorf("code = %v, want PoP failed", res.Error)
	}
}

// TestVerifyAuditsDenial (Fix 10): a denied verification must leave a
// CAPABILITY_DENIED audit entry carrying the error code, not just ALLOWs.
func TestVerifyAuditsDenial(t *testing.T) {
	now := time.Now().Unix()
	f := restrictChain(t, now-100, now-3600) // expired chain
	res := Verify(nil, f.invoke(t), f.config)
	if res.OK || res.Error.Code != CodeExpired {
		t.Fatalf("want expired denial, got OK=%v err=%v", res.OK, res.Error)
	}
	entries, err := f.config.AuditLog.Query(audit.AuditFilter{EventType: audit.EventCapabilityDenied})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("denial audit entries = %d, want 1", len(entries))
	}
	if entries[0].Payload["code"] != string(CodeExpired) {
		t.Errorf("audit code = %v, want %s", entries[0].Payload["code"], CodeExpired)
	}
}

// TestVerifyRejectsOBO (Fix 11): an invocation carrying on_behalf_of is rejected
// (fail closed) until OBO validation is implemented.
func TestVerifyRejectsOBO(t *testing.T) {
	f := freshChain(t)
	inv := f.invoke(t)
	inv.OBO = &OnBehalfOf{Principal: "did:key:zPrincipal"}
	res := Verify(nil, inv, f.config)
	if res.OK || res.Error.Code != CodePoPFailed {
		t.Errorf("code = %v, want V014 PoP (OK=%v)", res.Error, res.OK)
	}
}

// TestVerifyRejectsPreStartInvocation (Fix 12): an invocation whose iat predates
// the daemon's boot time is rejected, because its nonce-cache window is gone.
func TestVerifyRejectsPreStartInvocation(t *testing.T) {
	f := freshChain(t)
	inv := f.invoke(t)

	f.config.StartTime = time.Now().Unix() + 100 // boot "after" the invocation
	if res := Verify(nil, inv, f.config); res.OK || res.Error.Code != CodePoPFailed {
		t.Errorf("pre-start code = %v, want V014 PoP (OK=%v)", res.Error, res.OK)
	}

	// A boot time preceding the invocation lets it through (nonce reset to be safe).
	f.config.StartTime = inv.Iat - 10
	f.config.NonceCache = NewMemoryNonceCache()
	if res := Verify(nil, inv, f.config); !res.OK {
		t.Errorf("post-start verify failed: %v", res.Error)
	}
}

// loopStore returns a self-referential RESTRICT block for any CID.
type loopStore struct{}

func (loopStore) Get(cid string) ([]byte, error) {
	return []byte(`{"typ":"aitp/cav/1","iss":"did:key:zA","aud":"did:key:zB","prf":"` + cid +
		`","nbf":1,"exp":2,"dl":1,"cav":[{"type":"time_window","start":1,"end":2}],"sig":"AA"}`), nil
}
