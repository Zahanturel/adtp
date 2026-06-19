package delegation

import (
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/adtp/adtp/internal/credential"
	"github.com/adtp/adtp/internal/identity"
)

func genID(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	did, priv, err := identity.GenerateDID()
	if err != nil {
		t.Fatalf("GenerateDID: %v", err)
	}
	return priv, did
}

func mustCap(t *testing.T, can, with string, cs ...credential.Constraint) credential.Capability {
	t.Helper()
	c, err := credential.NewCapability(can, with, cs...)
	if err != nil {
		t.Fatalf("NewCapability: %v", err)
	}
	return c
}

// delegableRoot mints and stores a root credential that authorizes delegation
// (depth-left 5) and grants a wildcard tool capability.
func delegableRoot(t *testing.T, store *MemoryProofStore) (root *credential.UCAN, rootCID, agentDID string, agentKey ed25519.PrivateKey) {
	t.Helper()
	platformKey, platformDID := genID(t)
	agentKey, agentDID = genID(t)

	delegate := mustCap(t, credential.CanAgentDelegate, "agent://platform/agents",
		credential.DelegationDepthConstraint{Type: credential.ConstraintDelegationDepth, Max: 5})
	tool := mustCap(t, credential.CanToolInvoke, "tool://server/*")

	token, err := credential.CreateUCAN(credential.UCANPayload{
		Iss: platformDID, Aud: agentDID,
		Att: []credential.Capability{delegate, tool},
		Prf: []string{}, Exp: 5000, Nbf: 1000, Iat: 1000,
	}, platformKey)
	if err != nil {
		t.Fatalf("CreateUCAN: %v", err)
	}
	root, err = credential.ParseUCAN(token)
	if err != nil {
		t.Fatalf("ParseUCAN: %v", err)
	}
	return root, store.Put([]byte(token)), agentDID, agentKey
}

func caveat(t *testing.T) credential.Constraints {
	t.Helper()
	return credential.Constraints{credential.NewTimeWindow(1000, 5000)}
}

// twoHopRestrictChain stores root -> RESTRICT -> RESTRICT and returns the leaf CID.
func twoHopRestrictChain(t *testing.T, store *MemoryProofStore) string {
	t.Helper()
	root, rootCID, _, agentKey := delegableRoot(t, store)
	parent, err := ParentFromUCAN(root, rootCID)
	if err != nil {
		t.Fatalf("ParentFromUCAN: %v", err)
	}
	subKey, subDID := genID(t)
	block1, block1CID, err := DelegateRestrict(parent, subDID, caveat(t), 4, agentKey, store)
	if err != nil {
		t.Fatalf("DelegateRestrict hop1: %v", err)
	}
	_, sub2DID := genID(t)
	_, block2CID, err := DelegateRestrict(ParentFromBlock(block1, block1CID), sub2DID, caveat(t), 3, subKey, store)
	if err != nil {
		t.Fatalf("DelegateRestrict hop2: %v", err)
	}
	return block2CID
}

func TestBuildChainThreeElements(t *testing.T) {
	store := NewMemoryProofStore()
	leafCID := twoHopRestrictChain(t, store)

	chain, err := BuildChain(leafCID, store, DefaultMaxDepth)
	if err != nil {
		t.Fatalf("BuildChain: %v", err)
	}
	if len(chain.Elements) != 3 {
		t.Fatalf("chain length = %d, want 3", len(chain.Elements))
	}
	if chain.Depth != 2 {
		t.Errorf("depth = %d, want 2", chain.Depth)
	}
	if chain.Leaf().Mode != ModeRestrict {
		t.Errorf("leaf mode = %q", chain.Leaf().Mode)
	}
	if !chain.Root().IsRoot || chain.Root().Mode != ModeRoot {
		t.Errorf("root element = %+v", chain.Root())
	}
	if chain.Leaf().CID != leafCID {
		t.Errorf("leaf CID mismatch")
	}
}

// mismatchStore returns valid credential bytes regardless of the requested CID —
// exactly what a poisoned cache or dishonest CAS does. BuildChain must reject the
// content because its real CID never equals the lookup key (SD-5, Section 10.2).
type mismatchStore struct{ raw []byte }

func (s mismatchStore) Get(string) ([]byte, error) { return s.raw, nil }

func TestBuildChainRejectsCIDMismatch(t *testing.T) {
	key, did := genID(t)
	token, err := credential.CreateUCAN(credential.UCANPayload{
		Iss: did, Aud: "did:key:zChild",
		Att: []credential.Capability{mustCap(t, credential.CanToolInvoke, "tool://s/x")},
		Prf: []string{}, Exp: 5000, Nbf: 1000, Iat: 1000,
	}, key)
	if err != nil {
		t.Fatalf("CreateUCAN: %v", err)
	}
	wrongCID := "bafkreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if credential.ComputeCID([]byte(token)) == wrongCID {
		t.Fatal("precondition: real CID must differ from the wrong key")
	}
	if _, err := BuildChain(wrongCID, mismatchStore{raw: []byte(token)}, DefaultMaxDepth); !errors.Is(err, ErrCIDMismatch) {
		t.Errorf("err = %v, want ErrCIDMismatch", err)
	}
}

// TestBuildChainForgedSelfLoopRejected confirms a forged self-referential block
// (a would-be cycle) is rejected. Because content addressing makes a genuine CID
// cycle infeasible, the forgery is caught as a CID mismatch rather than reaching
// the cycle guard, which remains as defense-in-depth.
func TestBuildChainForgedSelfLoopRejected(t *testing.T) {
	selfLoop := []byte(`{"typ":"aitp/cav/1","iss":"did:key:zA","aud":"did:key:zB","prf":"bafkreiself","nbf":1,"exp":2,"dl":1,"cav":[{"type":"time_window","start":1,"end":2}],"sig":"AA"}`)
	if _, err := BuildChain("bafkreiself", mismatchStore{raw: selfLoop}, DefaultMaxDepth); !errors.Is(err, ErrCIDMismatch) {
		t.Errorf("err = %v, want ErrCIDMismatch", err)
	}
}

func TestBuildChainDepthExceeded(t *testing.T) {
	store := NewMemoryProofStore()
	leafCID := twoHopRestrictChain(t, store) // depth 2
	if _, err := BuildChain(leafCID, store, 1); !errors.Is(err, ErrChainTooDeep) {
		t.Errorf("err = %v, want ErrChainTooDeep", err)
	}
}

func TestBuildChainProofNotFound(t *testing.T) {
	store := NewMemoryProofStore()
	if _, err := BuildChain("bafkreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", store, DefaultMaxDepth); !errors.Is(err, ErrProofNotFound) {
		t.Errorf("err = %v, want ErrProofNotFound", err)
	}
}

func TestBuildChainBranchingUnsupported(t *testing.T) {
	store := NewMemoryProofStore()
	key, did := genID(t)
	token, err := credential.CreateUCAN(credential.UCANPayload{
		Iss: did, Aud: "did:key:zChild",
		Att: []credential.Capability{mustCap(t, credential.CanToolInvoke, "tool://s/x")},
		Prf: []string{"bafkreione", "bafkreitwo"},
		Exp: 5000, Nbf: 1000, Iat: 1000,
	}, key)
	if err != nil {
		t.Fatalf("CreateUCAN: %v", err)
	}
	leafCID := store.Put([]byte(token))
	if _, err := BuildChain(leafCID, store, DefaultMaxDepth); !errors.Is(err, ErrBranchingUnsupported) {
		t.Errorf("err = %v, want ErrBranchingUnsupported", err)
	}
}

func TestBuildChainModeMixingViolation(t *testing.T) {
	store := NewMemoryProofStore()
	root, rootCID, _, agentKey := delegableRoot(t, store)
	parent, err := ParentFromUCAN(root, rootCID)
	if err != nil {
		t.Fatalf("ParentFromUCAN: %v", err)
	}
	subKey, subDID := genID(t)
	_, blockCID, err := DelegateRestrict(parent, subDID, caveat(t), 4, agentKey, store)
	if err != nil {
		t.Fatalf("DelegateRestrict: %v", err)
	}

	// A RESTATE hop (UCAN with one prf) whose parent is the RESTRICT block:
	// RESTATE after RESTRICT is prohibited.
	restateToken, err := credential.CreateUCAN(credential.UCANPayload{
		Iss: subDID, Aud: "did:key:zLeaf",
		Att: []credential.Capability{mustCap(t, credential.CanToolInvoke, "tool://server/search")},
		Prf: []string{blockCID},
		Exp: 5000, Nbf: 1000, Iat: 1000,
	}, subKey)
	if err != nil {
		t.Fatalf("CreateUCAN: %v", err)
	}
	leafCID := store.Put([]byte(restateToken))

	if _, err := BuildChain(leafCID, store, DefaultMaxDepth); !errors.Is(err, ErrModeMixing) {
		t.Errorf("err = %v, want ErrModeMixing", err)
	}
}

func TestPutVerified(t *testing.T) {
	store := NewMemoryProofStore()
	raw := []byte("some-credential-bytes")
	cid := credential.ComputeCID(raw)

	if err := store.PutVerified(raw, cid); err != nil {
		t.Errorf("PutVerified(correct cid): %v", err)
	}
	if err := store.PutVerified(raw, "bafkreiwrong"); !errors.Is(err, ErrCIDMismatch) {
		t.Errorf("PutVerified(wrong cid) = %v, want ErrCIDMismatch", err)
	}
}
