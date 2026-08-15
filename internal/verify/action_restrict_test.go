// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/Zahanturel/adtp/internal/audit"
	"github.com/Zahanturel/adtp/internal/credential"
	"github.com/Zahanturel/adtp/internal/delegation"
	"github.com/Zahanturel/adtp/internal/revocation"
)

// readOnlyFixture builds the scenario that RESTRICT could not previously
// express: a root holding both resource/read and resource/write over the same
// URI space, delegating read-only to a sub-agent.
type readOnlyFixture struct {
	store       *delegation.MemoryProofStore
	config      *VerifierConfig
	rootCID     string
	agentKey    ed25519.PrivateKey
	agentDID    string
	leafKey     ed25519.PrivateKey
	leafDID     string
	verifierDID string
	now         int64
}

func newReadOnlyFixture(t *testing.T) *readOnlyFixture {
	t.Helper()
	now := time.Now().Unix()
	store := delegation.NewMemoryProofStore()

	platformKey, platformDID := genKey(t)
	agentKey, agentDID := genKey(t)
	leafKey, leafDID := genKey(t)
	_, verifierDID := genKey(t)

	// The root holds read AND write over the same URI space, plus the authority
	// to delegate. This is the ordinary shape of a service credential.
	root, err := credential.CreateUCAN(credential.UCANPayload{
		Iss: platformDID, Aud: agentDID,
		Att: []credential.Capability{
			vcap(t, credential.CanAgentDelegate, "agent://platform/agents",
				credential.DelegationDepthConstraint{Type: credential.ConstraintDelegationDepth, Max: 5}),
			vcap(t, credential.CanResourceRead, "resource://store/*"),
			vcap(t, credential.CanResourceWrite, "resource://store/*"),
		},
		Prf: []string{}, Exp: now + 3600, Nbf: now - 60, Iat: now,
	}, platformKey)
	if err != nil {
		t.Fatalf("CreateUCAN: %v", err)
	}
	rootCID := store.Put([]byte(root))

	f := &readOnlyFixture{
		store: store, rootCID: rootCID,
		agentKey: agentKey, agentDID: agentDID,
		leafKey: leafKey, leafDID: leafDID,
		verifierDID: verifierDID, now: now,
		config: &VerifierConfig{
			VerifierDID:     verifierDID,
			TrustedRootDIDs: map[string]bool{platformDID: true},
			MaxChainDepth:   10,
			ProofStore:      store,
			NonceCache:      NewMemoryNonceCache(),
			RevocationCache: revocation.NewMemoryRevocationCache(),
			AuditLog:        audit.NewMemoryAuditLog(),
			NowFn:           func() int64 { return now },
		},
	}
	return f
}

// delegate mints a RESTRICT hop from the root to the leaf carrying caveats.
func (f *readOnlyFixture) delegate(t *testing.T, caveats credential.Constraints) string {
	t.Helper()
	rootToken, err := credential.ParseUCAN(string(mustGet(t, f.store, f.rootCID)))
	if err != nil {
		t.Fatalf("ParseUCAN: %v", err)
	}
	parent, err := delegation.ParentFromUCAN(rootToken, f.rootCID)
	if err != nil {
		t.Fatalf("ParentFromUCAN: %v", err)
	}
	_, leafCID, err := delegation.DelegateRestrict(parent, f.leafDID, caveats, 4, f.agentKey, f.store)
	if err != nil {
		t.Fatalf("DelegateRestrict: %v", err)
	}
	return leafCID
}

func (f *readOnlyFixture) verify(t *testing.T, leafCID, action, resource string) *VerificationResult {
	t.Helper()
	f.config.NonceCache = NewMemoryNonceCache()
	inv, err := CreateInvocation(leafCID, action, resource, nil, f.leafKey, f.verifierDID, "")
	if err != nil {
		t.Fatalf("CreateInvocation: %v", err)
	}
	return Verify(context.Background(), nil, inv, f.config)
}

// The headline scenario: a root holding read and write delegates read-only.
func TestActionRestrictReadOnlyDelegation(t *testing.T) {
	f := newReadOnlyFixture(t)
	leafCID := f.delegate(t, credential.Constraints{
		credential.NewTimeWindow(f.now-60, f.now+3600),
		credential.ActionRestrictConstraint{
			Type: credential.ConstraintActionRestrict, Actions: []string{credential.CanResourceRead},
		},
	})

	if res := f.verify(t, leafCID, credential.CanResourceRead, "resource://store/doc"); !res.OK {
		t.Fatalf("read was denied for a read-only delegate: %v", res.Error)
	}

	res := f.verify(t, leafCID, credential.CanResourceWrite, "resource://store/doc")
	if res.OK {
		t.Fatal("FATAL: write was authorized for a read-only delegate")
	}
	if res.Error.Code != CodeCapInsufficient {
		t.Errorf("code = %s, want %s", res.Error.Code, CodeCapInsufficient)
	}
	if res.Error.Step != 8 {
		t.Errorf("step = %d, want 8 (authorization)", res.Error.Step)
	}

	// Without the caveat the same delegate can write: the caveat is what denies,
	// not some unrelated property of the fixture.
	openCID := f.delegate(t, credential.Constraints{credential.NewTimeWindow(f.now-60, f.now+3600)})
	if res := f.verify(t, openCID, credential.CanResourceWrite, "resource://store/doc"); !res.OK {
		t.Fatalf("control: write denied without action_restrict: %v", res.Error)
	}
}

// Caveats are conjunctive, so a chain's effective action set is the intersection
// down the path and a child can only narrow it.
func TestActionRestrictIntersectsDownTheChain(t *testing.T) {
	f := newReadOnlyFixture(t)
	rootToken, err := credential.ParseUCAN(string(mustGet(t, f.store, f.rootCID)))
	if err != nil {
		t.Fatalf("ParseUCAN: %v", err)
	}
	parent, err := delegation.ParentFromUCAN(rootToken, f.rootCID)
	if err != nil {
		t.Fatalf("ParentFromUCAN: %v", err)
	}

	// Hop 1 permits read and write.
	sub1Key, sub1DID := genKey(t)
	block1, block1CID, err := delegation.DelegateRestrict(parent, sub1DID, credential.Constraints{
		credential.NewTimeWindow(f.now-60, f.now+3600),
		credential.ActionRestrictConstraint{Type: credential.ConstraintActionRestrict,
			Actions: []string{credential.CanResourceRead, credential.CanResourceWrite}},
	}, 4, f.agentKey, f.store)
	if err != nil {
		t.Fatalf("hop1: %v", err)
	}

	// Hop 2 narrows to read.
	_, leafCID, err := delegation.DelegateRestrict(
		delegation.ParentFromBlock(block1, block1CID), f.leafDID, credential.Constraints{
			credential.ActionRestrictConstraint{Type: credential.ConstraintActionRestrict,
				Actions: []string{credential.CanResourceRead}},
		}, 3, sub1Key, f.store)
	if err != nil {
		t.Fatalf("hop2: %v", err)
	}

	if res := f.verify(t, leafCID, credential.CanResourceRead, "resource://store/doc"); !res.OK {
		t.Fatalf("read denied at the leaf: %v", res.Error)
	}
	if res := f.verify(t, leafCID, credential.CanResourceWrite, "resource://store/doc"); res.OK {
		t.Fatal("FATAL: write authorized despite the leaf narrowing to read")
	}

	// And a child cannot widen: hop 2 asking for write, which hop 1 permits, is
	// still denied at the leaf because hop 2's own caveat excludes it. The
	// converse — a child listing an action its parent excluded — is denied by
	// hop 1's caveat, which step 8 evaluates independently.
	_, wideCID, err := delegation.DelegateRestrict(
		delegation.ParentFromBlock(block1, block1CID), f.leafDID, credential.Constraints{
			credential.ActionRestrictConstraint{Type: credential.ConstraintActionRestrict,
				Actions: []string{credential.CanToolInvoke}},
		}, 3, sub1Key, f.store)
	if err != nil {
		t.Fatalf("wide hop: %v", err)
	}
	if res := f.verify(t, wideCID, credential.CanToolInvoke, "tool://server/x"); res.OK {
		t.Fatal("FATAL: a child widened the action set beyond its parent")
	}
}

func TestActionRestrictValidation(t *testing.T) {
	tests := []struct {
		name string
		c    credential.ActionRestrictConstraint
		ok   bool
	}{
		{"valid single", credential.ActionRestrictConstraint{
			Type: credential.ConstraintActionRestrict, Actions: []string{credential.CanResourceRead}}, true},
		{"valid multiple", credential.ActionRestrictConstraint{
			Type:    credential.ConstraintActionRestrict,
			Actions: []string{credential.CanResourceRead, credential.CanResourceWrite}}, true},
		{"wrong type tag", credential.ActionRestrictConstraint{
			Type: credential.ConstraintMethodRestrict, Actions: []string{credential.CanResourceRead}}, false},
		{"empty action list", credential.ActionRestrictConstraint{
			Type: credential.ConstraintActionRestrict}, false},
		// Fails closed: an unrecognized ability is refused at issuance rather than
		// carried as a caveat nobody can evaluate.
		{"unknown ability", credential.ActionRestrictConstraint{
			Type: credential.ConstraintActionRestrict, Actions: []string{"admin/everything"}}, false},
		{"one unknown among known", credential.ActionRestrictConstraint{
			Type:    credential.ConstraintActionRestrict,
			Actions: []string{credential.CanResourceRead, "admin/everything"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.c.Validate(); (err == nil) != tt.ok {
				t.Errorf("Validate() = %v, want ok=%v", err, tt.ok)
			}
		})
	}
}

// Issuance must refuse an invalid action_restrict, not only verification.
func TestActionRestrictRejectedAtIssuance(t *testing.T) {
	f := newReadOnlyFixture(t)
	rootToken, err := credential.ParseUCAN(string(mustGet(t, f.store, f.rootCID)))
	if err != nil {
		t.Fatalf("ParseUCAN: %v", err)
	}
	parent, err := delegation.ParentFromUCAN(rootToken, f.rootCID)
	if err != nil {
		t.Fatalf("ParentFromUCAN: %v", err)
	}
	_, _, err = delegation.DelegateRestrict(parent, f.leafDID, credential.Constraints{
		credential.ActionRestrictConstraint{
			Type: credential.ConstraintActionRestrict, Actions: []string{"admin/everything"}},
	}, 4, f.agentKey, f.store)
	if err == nil {
		t.Fatal("FATAL: issuance accepted an action_restrict naming an unknown ability")
	}
}
