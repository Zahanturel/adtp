package memory

import (
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/adtp/adtp/internal/identity"
	"github.com/adtp/adtp/internal/lifecycle"
	"github.com/adtp/adtp/internal/revocation"
)

func revocationKey(t *testing.T) (ed25519.PrivateKey, string, error) {
	t.Helper()
	did, priv, err := identity.GenerateDID()
	return priv, did, err
}

func TestAgents(t *testing.T) {
	s := New()
	if _, err := s.GetAgent("did:key:zMissing"); !errors.Is(err, ErrAgentNotFound) {
		t.Errorf("GetAgent(missing) = %v, want ErrAgentNotFound", err)
	}
	if err := s.PutAgent(&lifecycle.Agent{}); !errors.Is(err, ErrInvalidAgent) {
		t.Errorf("PutAgent(no DID) = %v, want ErrInvalidAgent", err)
	}

	agent := lifecycle.NewAgent("did:key:zAgent", "did:key:zSponsor")
	if err := s.PutAgent(agent); err != nil {
		t.Fatalf("PutAgent: %v", err)
	}
	got, err := s.GetAgent("did:key:zAgent")
	if err != nil {
		t.Fatalf("GetAgent: %v", err)
	}
	if got.SponsorDID != "did:key:zSponsor" {
		t.Errorf("sponsor = %q", got.SponsorDID)
	}
}

func TestCredentials(t *testing.T) {
	s := New()
	if _, err := s.Get("bafkreimissing"); !errors.Is(err, ErrCredentialNotFound) {
		t.Errorf("Get(missing) = %v, want ErrCredentialNotFound", err)
	}

	cid, err := s.PutCredential([]byte("credential-bytes"))
	if err != nil {
		t.Fatalf("PutCredential: %v", err)
	}
	got, err := s.Get(cid)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "credential-bytes" {
		t.Errorf("Get = %q", got)
	}
	// Idempotent re-put does not duplicate the order entry.
	s.PutCredential([]byte("credential-bytes"))
	list, _ := s.ListCredentials()
	if len(list) != 1 || list[0] != cid {
		t.Errorf("ListCredentials = %v", list)
	}
}

func TestRegistrationIndex(t *testing.T) {
	s := New()
	s.Register("leaf", []string{"leaf", "mid", "root"})
	s.Register("mid", []string{"mid", "root"})

	desc, _ := s.FindDescendants("mid")
	if len(desc) != 1 || desc[0] != "leaf" {
		t.Errorf("FindDescendants(mid) = %v, want [leaf]", desc)
	}
	if !s.Contains("leaf", "root") {
		t.Errorf("Contains(leaf, root) = false, want true")
	}
	if s.Contains("root", "leaf") {
		t.Errorf("Contains(root, leaf) = true, want false")
	}
}

func TestRevocation(t *testing.T) {
	key, did, err := revocationKey(t)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	s := New()
	if got, _ := s.GetStatus("c"); got != nil {
		t.Errorf("GetStatus(active) = %+v, want nil", got)
	}
	entry, err := revocation.CreateRevocationEntry(
		revocation.RevocationSubject{CID: "c"}, revocation.ScopeCredential, revocation.StatusRevoked,
		revocation.RevocationAuth{DID: did, Basis: revocation.AuthPlatform}, 1, "", key)
	if err != nil {
		t.Fatalf("entry: %v", err)
	}
	if err := s.Revoke(*entry); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	got, _ := s.GetStatus("c")
	if got == nil || got.Status != revocation.StatusRevoked {
		t.Errorf("GetStatus = %+v, want REVOKED", got)
	}
	if s.CurrentSeq("c") != 1 {
		t.Errorf("CurrentSeq = %d, want 1", s.CurrentSeq("c"))
	}
}

func TestUpdateFromListAndAudit(t *testing.T) {
	key, did, err := revocationKey(t)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	s := New()
	entry, err := revocation.CreateRevocationEntry(
		revocation.RevocationSubject{CID: "c"}, revocation.ScopeCredential, revocation.StatusRevoked,
		revocation.RevocationAuth{DID: did, Basis: revocation.AuthPlatform}, 1, "", key)
	if err != nil {
		t.Fatalf("entry: %v", err)
	}
	list, err := revocation.CreateRevocationList([]revocation.RevocationEntry{*entry}, did, "", 1, key)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if err := s.UpdateFromList(list, key.Public().(ed25519.PublicKey)); err != nil {
		t.Fatalf("UpdateFromList: %v", err)
	}
	if got, _ := s.GetStatus("c"); got == nil {
		t.Errorf("entry from list not applied")
	}
	if s.Audit() == nil {
		t.Errorf("Audit() returned nil")
	}
}
