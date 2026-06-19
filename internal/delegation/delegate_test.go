package delegation

import (
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/adtp/adtp/internal/credential"
)

func TestDelegateRestrictSuccess(t *testing.T) {
	store := NewMemoryProofStore()
	root, rootCID, agentDID, agentKey := delegableRoot(t, store)
	parent, err := ParentFromUCAN(root, rootCID)
	if err != nil {
		t.Fatalf("ParentFromUCAN: %v", err)
	}

	_, subDID := genID(t)
	block, cid, err := DelegateRestrict(parent, subDID, caveat(t), 4, agentKey, store)
	if err != nil {
		t.Fatalf("DelegateRestrict: %v", err)
	}
	if block.Iss != agentDID {
		t.Errorf("iss = %q, want %q", block.Iss, agentDID)
	}
	if block.DL != 4 {
		t.Errorf("dl = %d, want 4", block.DL)
	}
	// The block is retrievable from the store under its returned CID.
	if _, err := store.Get(cid); err != nil {
		t.Errorf("stored block not found: %v", err)
	}
	if err := block.Verify(agentKey.Public().(ed25519.PublicKey)); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

func TestDelegateRestrictDepthExhaustion(t *testing.T) {
	store := NewMemoryProofStore()
	root, rootCID, _, agentKey := delegableRoot(t, store)
	parent, err := ParentFromUCAN(root, rootCID)
	if err != nil {
		t.Fatalf("ParentFromUCAN: %v", err)
	}

	// Delegate down to depth-left 0.
	subKey, subDID := genID(t)
	block, blockCID, err := DelegateRestrict(parent, subDID, caveat(t), 0, agentKey, store)
	if err != nil {
		t.Fatalf("DelegateRestrict to dl 0: %v", err)
	}

	// A credential with depth-left 0 can no longer delegate.
	exhausted := ParentFromBlock(block, blockCID)
	if _, _, err := DelegateRestrict(exhausted, "did:key:zX", caveat(t), -1, subKey, store); !errors.Is(err, ErrDepthExhausted) {
		t.Errorf("err = %v, want ErrDepthExhausted", err)
	}
}

func TestDelegateRestrictDepthNotReduced(t *testing.T) {
	store := NewMemoryProofStore()
	root, rootCID, _, agentKey := delegableRoot(t, store)
	parent, err := ParentFromUCAN(root, rootCID)
	if err != nil {
		t.Fatalf("ParentFromUCAN: %v", err)
	}
	if _, _, err := DelegateRestrict(parent, "did:key:zX", caveat(t), parent.DL, agentKey, store); !errors.Is(err, credential.ErrDepthNotReduced) {
		t.Errorf("err = %v, want ErrDepthNotReduced", err)
	}
}

func TestDelegateRestateSuccess(t *testing.T) {
	store := NewMemoryProofStore()
	root, _, _, agentKey := delegableRoot(t, store)

	// The root grants tool://server/* ; restating tool://server/search is covered.
	subset := []credential.Capability{mustCap(t, credential.CanToolInvoke, "tool://server/search")}
	token, cid, err := DelegateRestate(root, "did:key:zChild", subset, agentKey, store)
	if err != nil {
		t.Fatalf("DelegateRestate: %v", err)
	}
	if _, err := store.Get(cid); err != nil {
		t.Errorf("stored hop not found: %v", err)
	}
	hop, err := credential.ParseUCAN(token)
	if err != nil {
		t.Fatalf("ParseUCAN: %v", err)
	}
	if hop.Header.Seal == nil {
		t.Errorf("restate hop missing att_seal")
	}
}

func TestDelegateRestateEscalation(t *testing.T) {
	store := NewMemoryProofStore()
	root, _, _, agentKey := delegableRoot(t, store)

	// The root has no resource/write capability; restating it is escalation.
	escalated := []credential.Capability{mustCap(t, credential.CanResourceWrite, "resource://db/customers")}
	if _, _, err := DelegateRestate(root, "did:key:zChild", escalated, agentKey, store); !errors.Is(err, ErrEscalation) {
		t.Errorf("err = %v, want ErrEscalation", err)
	}

	// Widening the wildcard scope is also escalation.
	widened := []credential.Capability{mustCap(t, credential.CanToolInvoke, "tool://server/a/b")}
	if _, _, err := DelegateRestate(root, "did:key:zChild", widened, agentKey, store); !errors.Is(err, ErrEscalation) {
		t.Errorf("widened err = %v, want ErrEscalation", err)
	}
}

func TestParentFromUCANNonDelegable(t *testing.T) {
	store := NewMemoryProofStore()
	platformKey, platformDID := genID(t)
	_, agentDID := genID(t)
	// A root with no agent/delegate capability cannot delegate.
	token, err := credential.CreateUCAN(credential.UCANPayload{
		Iss: platformDID, Aud: agentDID,
		Att: []credential.Capability{mustCap(t, credential.CanToolInvoke, "tool://s/x")},
		Prf: []string{}, Exp: 5000, Nbf: 1000, Iat: 1000,
	}, platformKey)
	if err != nil {
		t.Fatalf("CreateUCAN: %v", err)
	}
	root, err := credential.ParseUCAN(token)
	if err != nil {
		t.Fatalf("ParseUCAN: %v", err)
	}
	if _, err := ParentFromUCAN(root, store.Put([]byte(token))); !errors.Is(err, ErrCannotDelegate) {
		t.Errorf("err = %v, want ErrCannotDelegate", err)
	}
}
