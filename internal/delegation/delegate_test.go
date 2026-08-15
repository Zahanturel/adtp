// SPDX-License-Identifier: Apache-2.0

package delegation

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/Zahanturel/adtp/internal/credential"
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
	if _, err := store.Get(context.Background(), cid); err != nil {
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
