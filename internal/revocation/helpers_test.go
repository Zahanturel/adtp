package revocation

import (
	"crypto/ed25519"
	"fmt"
	"testing"

	"github.com/adtp/adtp/internal/credential"
	"github.com/adtp/adtp/internal/identity"
)

func genKey(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	did, priv, err := identity.GenerateDID()
	if err != nil {
		t.Fatalf("GenerateDID: %v", err)
	}
	return priv, did
}

func platformAuth(did string) RevocationAuth {
	return RevocationAuth{DID: did, Basis: AuthPlatform, Proof: "bafkreiproof"}
}

// signedEntry builds a properly signed revocation entry whose authority DID is
// the did:key of key, so it passes VerifyEntrySelfSignature at apply time.
func signedEntry(t *testing.T, key ed25519.PrivateKey, did string, sub RevocationSubject, status RevocationStatus, seq int64) RevocationEntry {
	t.Helper()
	e, err := CreateRevocationEntry(sub, ScopeCredential, status, platformAuth(did), seq, "", key)
	if err != nil {
		t.Fatalf("signedEntry: %v", err)
	}
	return *e
}

func pubOf(key ed25519.PrivateKey) ed25519.PublicKey {
	return key.Public().(ed25519.PublicKey)
}

// testCredStore is an in-memory CredentialStore and delegation.ProofStore.
type testCredStore struct {
	m     map[string][]byte
	order []string
}

func newTestCredStore() *testCredStore {
	return &testCredStore{m: make(map[string][]byte)}
}

func (s *testCredStore) put(cid string, raw []byte) {
	s.m[cid] = raw
	s.order = append(s.order, cid)
}

func (s *testCredStore) Get(cid string) ([]byte, error) {
	if b, ok := s.m[cid]; ok {
		return append([]byte(nil), b...), nil
	}
	return nil, fmt.Errorf("not found: %s", cid)
}

func (s *testCredStore) ListCredentials() ([]string, error) {
	return append([]string(nil), s.order...), nil
}

// buildSampleChain mints root -> RESTRICT(mid) -> RESTRICT(leaf) and stores all
// three, returning the store and their CIDs.
func buildSampleChain(t *testing.T) (store *testCredStore, rootCID, midCID, leafCID string) {
	t.Helper()
	store = newTestCredStore()

	platformKey, platformDID := genKey(t)
	agentKey, agentDID := genKey(t)
	sub1Key, sub1DID := genKey(t)
	_, leafDID := genKey(t)

	delegateCap, err := credential.NewCapability(credential.CanAgentDelegate, "agent://p/a",
		credential.DelegationDepthConstraint{Type: credential.ConstraintDelegationDepth, Max: 5})
	if err != nil {
		t.Fatalf("cap: %v", err)
	}
	toolCap, err := credential.NewCapability(credential.CanToolInvoke, "tool://server/*")
	if err != nil {
		t.Fatalf("cap: %v", err)
	}
	rootToken, err := credential.CreateUCAN(credential.UCANPayload{
		Iss: platformDID, Aud: agentDID,
		Att: []credential.Capability{delegateCap, toolCap},
		Prf: []string{}, Exp: 5000, Nbf: 1000, Iat: 1000,
	}, platformKey)
	if err != nil {
		t.Fatalf("CreateUCAN: %v", err)
	}
	rootCID = credential.ComputeCID([]byte(rootToken))
	store.put(rootCID, []byte(rootToken))

	caveats := credential.Constraints{credential.NewTimeWindow(1000, 5000)}
	_, midRaw, err := credential.CreateRestrictBlock(
		credential.DelegationParent{CID: rootCID, Aud: agentDID, Exp: 5000, Nbf: 1000, DL: 5},
		sub1DID, 4, caveats, agentKey)
	if err != nil {
		t.Fatalf("mid block: %v", err)
	}
	midCID = credential.ComputeCID(midRaw)
	store.put(midCID, midRaw)

	_, leafRaw, err := credential.CreateRestrictBlock(
		credential.DelegationParent{CID: midCID, Aud: sub1DID, Exp: 5000, Nbf: 1000, DL: 4},
		leafDID, 3, caveats, sub1Key)
	if err != nil {
		t.Fatalf("leaf block: %v", err)
	}
	leafCID = credential.ComputeCID(leafRaw)
	store.put(leafCID, leafRaw)

	return store, rootCID, midCID, leafCID
}
