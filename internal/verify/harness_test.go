package verify

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/adtp/adtp/internal/audit"
	"github.com/adtp/adtp/internal/credential"
	"github.com/adtp/adtp/internal/delegation"
	"github.com/adtp/adtp/internal/identity"
	"github.com/adtp/adtp/internal/revocation"
)

func genKey(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	did, priv, err := identity.GenerateDID()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return priv, did
}

func vcap(t *testing.T, can, with string, cs ...credential.Constraint) credential.Capability {
	t.Helper()
	c, err := credential.NewCapability(can, with, cs...)
	if err != nil {
		t.Fatalf("NewCapability: %v", err)
	}
	return c
}

// fixture is a built RESTRICT chain plus a verifier configured to trust it.
type fixture struct {
	store       *delegation.MemoryProofStore
	config      *VerifierConfig
	leafCID     string
	leafKey     ed25519.PrivateKey
	leafDID     string
	platformDID string
	verifierDID string
}

// restrictChain builds platform-root -> RESTRICT -> RESTRICT with the given
// validity window, returning the fixture. The two hops carry a time_window
// caveat spanning the window.
func restrictChain(t *testing.T, exp, nbf int64) *fixture {
	t.Helper()
	store := delegation.NewMemoryProofStore()

	platformKey, platformDID := genKey(t)
	agentKey, agentDID := genKey(t)
	sub1Key, sub1DID := genKey(t)
	leafKey, leafDID := genKey(t)
	_, verifierDID := genKey(t)

	delegateCap := vcap(t, credential.CanAgentDelegate, "agent://platform/agents",
		credential.DelegationDepthConstraint{Type: credential.ConstraintDelegationDepth, Max: 5})
	toolCap := vcap(t, credential.CanToolInvoke, "tool://server/*")

	rootToken, err := credential.CreateUCAN(credential.UCANPayload{
		Iss: platformDID, Aud: agentDID,
		Att: []credential.Capability{delegateCap, toolCap},
		Prf: []string{}, Exp: exp, Nbf: nbf, Iat: nbf,
	}, platformKey)
	if err != nil {
		t.Fatalf("CreateUCAN: %v", err)
	}
	root, err := credential.ParseUCAN(rootToken)
	if err != nil {
		t.Fatalf("ParseUCAN: %v", err)
	}
	rootCID := store.Put([]byte(rootToken))

	parent, err := delegation.ParentFromUCAN(root, rootCID)
	if err != nil {
		t.Fatalf("ParentFromUCAN: %v", err)
	}
	caveats := credential.Constraints{credential.NewTimeWindow(nbf, exp)}
	block1, block1CID, err := delegation.DelegateRestrict(parent, sub1DID, caveats, 4, agentKey, store)
	if err != nil {
		t.Fatalf("DelegateRestrict hop1: %v", err)
	}
	_, block2CID, err := delegation.DelegateRestrict(delegation.ParentFromBlock(block1, block1CID), leafDID, caveats, 3, sub1Key, store)
	if err != nil {
		t.Fatalf("DelegateRestrict hop2: %v", err)
	}

	config := &VerifierConfig{
		VerifierDID:      verifierDID,
		TrustedRootDIDs:  map[string]bool{platformDID: true},
		MaxChainDepth:    10,
		ClockSkewSeconds: 60,
		ProofStore:       store,
		NonceCache:       NewMemoryNonceCache(),
		RevocationCache:  revocation.NewMemoryRevocationCache(),
		AuditLog:         audit.NewMemoryAuditLog(),
	}
	return &fixture{
		store: store, config: config, leafCID: block2CID,
		leafKey: leafKey, leafDID: leafDID,
		platformDID: platformDID, verifierDID: verifierDID,
	}
}

// freshChain builds a chain valid around the present moment.
func freshChain(t *testing.T) *fixture {
	now := time.Now().Unix()
	return restrictChain(t, now+3600, now-60)
}

// invoke builds a signed invocation from the leaf for the standard authorized
// action and resource.
func (f *fixture) invoke(t *testing.T) *UCANInvocation {
	t.Helper()
	inv, err := CreateInvocation(f.leafCID, credential.CanToolInvoke, "tool://server/search", nil, f.leafKey, f.verifierDID, "")
	if err != nil {
		t.Fatalf("CreateInvocation: %v", err)
	}
	return inv
}
