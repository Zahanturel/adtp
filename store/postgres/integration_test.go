//go:build integration

// These tests run only with the `integration` build tag and a live PostgreSQL
// instance addressed by ADTP_TEST_POSTGRES. CI uses the in-memory backend.
package postgres

import (
	"crypto/ed25519"
	"os"
	"testing"

	"github.com/adtp/adtp/internal/audit"
	"github.com/adtp/adtp/internal/credential"
	"github.com/adtp/adtp/internal/identity"
	"github.com/adtp/adtp/internal/lifecycle"
	"github.com/adtp/adtp/internal/revocation"
)

func testStore(t *testing.T) *PostgresStore {
	t.Helper()
	dsn := os.Getenv("ADTP_TEST_POSTGRES")
	if dsn == "" {
		t.Skip("set ADTP_TEST_POSTGRES to run PostgreSQL integration tests")
	}
	s, err := NewPostgresStore(dsn)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	// Start from a clean slate.
	for _, tbl := range []string{"audit_log", "revocation_entries", "registration_index", "credentials", "agents"} {
		if _, err := s.pool.Exec(t.Context(), "TRUNCATE "+tbl+" RESTART IDENTITY CASCADE"); err != nil {
			t.Fatalf("truncate %s: %v", tbl, err)
		}
	}
	return s
}

func TestPostgresAgentsAndCredentials(t *testing.T) {
	s := testStore(t)

	agent := lifecycle.NewAgent("did:key:zAgent", "did:key:zSponsor")
	if err := s.PutAgent(agent); err != nil {
		t.Fatalf("PutAgent: %v", err)
	}
	got, err := s.GetAgent("did:key:zAgent")
	if err != nil || got.SponsorDID != "did:key:zSponsor" {
		t.Fatalf("GetAgent = %+v, %v", got, err)
	}

	platformDID, platformKey, _ := identity.GenerateDID()
	tok, err := credential.CreateUCAN(credential.UCANPayload{
		Iss: platformDID, Aud: "did:key:zAgent",
		Att: []credential.Capability{mustCap(t)}, Prf: []string{},
		Exp: 5000, Nbf: 1000, Iat: 1000,
	}, platformKey)
	if err != nil {
		t.Fatalf("CreateUCAN: %v", err)
	}
	cid, err := s.PutCredential([]byte(tok))
	if err != nil {
		t.Fatalf("PutCredential: %v", err)
	}
	if raw, err := s.Get(cid); err != nil || string(raw) != tok {
		t.Fatalf("Get round-trip failed: %v", err)
	}
	if list, _ := s.ListCredentials(); len(list) != 1 {
		t.Errorf("ListCredentials = %v", list)
	}
}

func TestPostgresRegistrationAndRevocation(t *testing.T) {
	s := testStore(t)

	if err := s.Register("leaf", []string{"leaf", "mid", "root"}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	desc, _ := s.FindDescendants("mid")
	if len(desc) != 1 || desc[0] != "leaf" {
		t.Errorf("FindDescendants = %v", desc)
	}
	if !s.Contains("leaf", "root") {
		t.Errorf("Contains(leaf, root) = false")
	}

	key, did := mustKey(t)
	entry, err := revocation.CreateRevocationEntry(
		revocation.RevocationSubject{CID: "leaf"}, revocation.ScopeCredential, revocation.StatusRevoked,
		revocation.RevocationAuth{DID: did, Basis: revocation.AuthPlatform}, 1, "", key)
	if err != nil {
		t.Fatalf("entry: %v", err)
	}
	if err := s.Revoke(*entry); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	status, _ := s.GetStatus("leaf")
	if status == nil || status.Status != revocation.StatusRevoked {
		t.Errorf("GetStatus = %+v", status)
	}
	if s.CurrentSeq("leaf") != 1 {
		t.Errorf("CurrentSeq = %d", s.CurrentSeq("leaf"))
	}
}

func TestPostgresAudit(t *testing.T) {
	s := testStore(t)
	log := s.Audit()
	for i := 0; i < 3; i++ {
		if err := log.Append(audit.AuditEntry{EventType: audit.EventCapabilityInvoked, Payload: map[string]any{"i": i}}); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	if err := log.VerifyChain(); err != nil {
		t.Errorf("VerifyChain: %v", err)
	}
	if got, _ := log.Query(audit.AuditFilter{EventType: audit.EventCapabilityInvoked}); len(got) != 3 {
		t.Errorf("Query = %d, want 3", len(got))
	}
}

func mustCap(t *testing.T) credential.Capability {
	t.Helper()
	c, err := credential.NewCapability(credential.CanToolInvoke, "tool://s/x")
	if err != nil {
		t.Fatalf("NewCapability: %v", err)
	}
	return c
}

func mustKey(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	did, priv, err := identity.GenerateDID()
	if err != nil {
		t.Fatalf("GenerateDID: %v", err)
	}
	return priv, did
}
