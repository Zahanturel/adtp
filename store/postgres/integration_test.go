//go:build integration

package postgres

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Zahanturel/adtp/internal/audit"
	"github.com/Zahanturel/adtp/internal/credential"
	"github.com/Zahanturel/adtp/internal/identity"
	"github.com/Zahanturel/adtp/internal/lifecycle"
	"github.com/Zahanturel/adtp/internal/revocation"
)

func testStore(t *testing.T) *PostgresStore {
	t.Helper()
	dsn := os.Getenv("ADTP_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set ADTP_TEST_POSTGRES_DSN to run PostgreSQL integration tests")
	}
	s, err := NewPostgresStore(dsn)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	for _, tbl := range []string{"audit_log", "revocation_entries", "registration_index", "credentials", "agents"} {
		if _, err := s.pool.Exec(t.Context(), "TRUNCATE "+tbl+" RESTART IDENTITY CASCADE"); err != nil {
			t.Fatalf("truncate %s: %v", tbl, err)
		}
	}
	return s
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

func TestPostgresRegisterAndContains(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	if err := s.Register(ctx, "leaf-a", []string{"leaf-a", "root"}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if !s.Contains(ctx, "leaf-a", "root") {
		t.Error("Contains(leaf-a, root) = false, want true")
	}
	if s.Contains(ctx, "unregistered", "root") {
		t.Error("Contains(unregistered, root) = true, want false")
	}
	if s.Contains(ctx, "root", "leaf-a") {
		t.Error("Contains(root, leaf-a) = true, want false")
	}
}

func TestPostgresStoreAndRetrieveCredential(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	platformDID, platformKey, _ := identity.GenerateDID()
	tok, err := credential.CreateUCAN(credential.UCANPayload{
		Iss: platformDID, Aud: "did:key:zAgent",
		Att: []credential.Capability{mustCap(t)}, Prf: []string{},
		Exp: 5000, Nbf: 1000, Iat: 1000,
	}, platformKey)
	if err != nil {
		t.Fatalf("CreateUCAN: %v", err)
	}

	cid, err := s.PutCredential(ctx, []byte(tok))
	if err != nil {
		t.Fatalf("PutCredential: %v", err)
	}
	raw, err := s.Get(ctx, cid)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(raw) != tok {
		t.Errorf("Get round-trip mismatch: got %d bytes, want %d", len(raw), len(tok))
	}

	list, err := s.ListCredentials(ctx)
	if err != nil {
		t.Fatalf("ListCredentials: %v", err)
	}
	if len(list) != 1 || list[0] != cid {
		t.Errorf("ListCredentials = %v, want [%s]", list, cid)
	}
}

func TestPostgresFindDescendants(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	if err := s.Register(ctx, "child-1", []string{"child-1", "parent"}); err != nil {
		t.Fatalf("Register child-1: %v", err)
	}
	if err := s.Register(ctx, "child-2", []string{"child-2", "parent"}); err != nil {
		t.Fatalf("Register child-2: %v", err)
	}
	if err := s.Register(ctx, "child-3", []string{"child-3", "parent"}); err != nil {
		t.Fatalf("Register child-3: %v", err)
	}

	desc, err := s.FindDescendants(ctx, "parent")
	if err != nil {
		t.Fatalf("FindDescendants: %v", err)
	}
	if len(desc) != 3 {
		t.Fatalf("FindDescendants(parent) returned %d descendants, want 3: %v", len(desc), desc)
	}
	got := map[string]bool{}
	for _, d := range desc {
		got[d] = true
	}
	for _, want := range []string{"child-1", "child-2", "child-3"} {
		if !got[want] {
			t.Errorf("missing descendant %s in %v", want, desc)
		}
	}
}

func TestPostgresRevocationRoundtrip(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	key, did := mustKey(t)

	got, err := s.GetStatus(ctx, "target-cid")
	if err != nil {
		t.Fatalf("GetStatus(clean): %v", err)
	}
	if got != nil {
		t.Errorf("GetStatus(clean) = %+v, want nil", got)
	}

	entry, err := revocation.CreateRevocationEntry(
		revocation.RevocationSubject{CID: "target-cid"}, revocation.ScopeCredential, revocation.StatusCompromised,
		revocation.RevocationAuth{DID: did, Basis: revocation.AuthPlatform}, 1, "", key)
	if err != nil {
		t.Fatalf("CreateRevocationEntry: %v", err)
	}
	if err := s.Revoke(ctx, *entry); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	got, err = s.GetStatus(ctx, "target-cid")
	if err != nil {
		t.Fatalf("GetStatus(revoked): %v", err)
	}
	if got == nil || got.Status != revocation.StatusCompromised {
		t.Errorf("GetStatus = %+v, want COMPROMISED", got)
	}

	seq, err := s.CurrentSeq(ctx, "target-cid")
	if err != nil {
		t.Fatalf("CurrentSeq: %v", err)
	}
	if seq != 1 {
		t.Errorf("CurrentSeq = %d, want 1", seq)
	}
}

func TestPostgresRevocationSequenceGuard(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	key, did := mustKey(t)

	high, err := revocation.CreateRevocationEntry(
		revocation.RevocationSubject{CID: "seq-guard"}, revocation.ScopeCredential, revocation.StatusRevoked,
		revocation.RevocationAuth{DID: did, Basis: revocation.AuthPlatform}, 5, "", key)
	if err != nil {
		t.Fatalf("entry seq=5: %v", err)
	}
	if err := s.Revoke(ctx, *high); err != nil {
		t.Fatalf("Revoke(seq=5): %v", err)
	}

	low, err := revocation.CreateRevocationEntry(
		revocation.RevocationSubject{CID: "seq-guard"}, revocation.ScopeCredential, revocation.StatusReinstated,
		revocation.RevocationAuth{DID: did, Basis: revocation.AuthPlatform}, 3, "", key)
	if err != nil {
		t.Fatalf("entry seq=3: %v", err)
	}
	err = s.Revoke(ctx, *low)
	if err == nil {
		t.Fatal("Revoke(seq=3 after seq=5) succeeded, want ErrSequenceRollback")
	}
	if !errors.Is(err, revocation.ErrSequenceRollback) {
		t.Errorf("err = %v, want ErrSequenceRollback", err)
	}

	seq, err := s.CurrentSeq(ctx, "seq-guard")
	if err != nil {
		t.Fatalf("CurrentSeq: %v", err)
	}
	if seq != 5 {
		t.Errorf("CurrentSeq = %d, want 5 (unchanged)", seq)
	}
}

func TestPostgresAuditLogAppend(t *testing.T) {
	s := testStore(t)
	log := s.Audit()

	for i := 0; i < 3; i++ {
		if err := log.Append(audit.AuditEntry{
			EventType: audit.EventCapabilityInvoked,
			Ts:        int64(1000 + i),
			Payload:   map[string]any{"i": i},
		}); err != nil {
			t.Fatalf("Append(%d): %v", i, err)
		}
	}

	entries, err := log.Query(audit.AuditFilter{EventType: audit.EventCapabilityInvoked})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("Query returned %d entries, want 3", len(entries))
	}
	for i, e := range entries {
		if e.Ts != int64(1000+i) {
			t.Errorf("entry[%d].Ts = %d, want %d", i, e.Ts, 1000+i)
		}
	}

	if err := log.VerifyChain(); err != nil {
		t.Errorf("VerifyChain: %v", err)
	}
}

func TestPostgresConcurrentRevocation(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	key, did := mustKey(t)

	const n = 10
	entries := make([]revocation.RevocationEntry, n)
	for i := range entries {
		e, err := revocation.CreateRevocationEntry(
			revocation.RevocationSubject{CID: "concurrent-target"}, revocation.ScopeCredential, revocation.StatusCompromised,
			revocation.RevocationAuth{DID: did, Basis: revocation.AuthPlatform}, 1, "", key)
		if err != nil {
			t.Fatalf("entry %d: %v", i, err)
		}
		entries[i] = *e
	}

	var wg sync.WaitGroup
	var successes, failures atomic.Int32
	wg.Add(n)
	for i := range entries {
		go func(e revocation.RevocationEntry) {
			defer wg.Done()
			if err := s.Revoke(ctx, e); err != nil {
				failures.Add(1)
			} else {
				successes.Add(1)
			}
		}(entries[i])
	}
	wg.Wait()

	if got := successes.Load(); got != 1 {
		t.Errorf("successes = %d, want exactly 1", got)
	}
	if got := failures.Load(); got != int32(n-1) {
		t.Errorf("failures = %d, want %d", got, n-1)
	}
}

func TestPostgresAgents(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	agent := lifecycle.NewAgent("did:key:zAgent", "did:key:zSponsor")
	if err := s.PutAgent(ctx, agent); err != nil {
		t.Fatalf("PutAgent: %v", err)
	}
	got, err := s.GetAgent(ctx, "did:key:zAgent")
	if err != nil {
		t.Fatalf("GetAgent: %v", err)
	}
	if got.SponsorDID != "did:key:zSponsor" {
		t.Errorf("sponsor = %q, want %q", got.SponsorDID, "did:key:zSponsor")
	}
}
