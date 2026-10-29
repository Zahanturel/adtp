//go:build integration

// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"sort"
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
	for _, tbl := range []string{"audit_log", "revocation_entries", "registration_index", "credentials", "agents", "agent_keys"} {
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

// --- key store ---

func TestPostgresKeyStoreRoundTrip(t *testing.T) {
	s := testStore(t)
	ks := s.Keys()

	priv, did := mustKey(t)
	if err := ks.Store(did, priv); err != nil {
		t.Fatalf("Store: %v", err)
	}
	got, err := ks.Load(did)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !got.Equal(priv) {
		t.Error("loaded key does not equal the stored key")
	}
	// The returned slice must be a copy: mutating it must not corrupt the store.
	got[0] ^= 0xff
	again, err := ks.Load(did)
	if err != nil {
		t.Fatalf("Load after mutation: %v", err)
	}
	if !again.Equal(priv) {
		t.Error("mutating a loaded key altered the stored key")
	}
}

// TestPostgresKeyStoreSurvivesReconnect is the reason this backend exists: a new
// pool against the same database — what a daemon restart looks like — must still
// resolve keys registered by the previous process.
func TestPostgresKeyStoreSurvivesReconnect(t *testing.T) {
	s := testStore(t)
	priv, did := mustKey(t)
	if err := s.Keys().Store(did, priv); err != nil {
		t.Fatalf("Store: %v", err)
	}

	reopened, err := NewPostgresStore(os.Getenv("ADTP_TEST_POSTGRES_DSN"))
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer reopened.Close()

	got, err := reopened.Keys().Load(did)
	if err != nil {
		t.Fatalf("Load after reconnect: %v", err)
	}
	if !got.Equal(priv) {
		t.Error("key did not survive reconnect intact")
	}
}

func TestPostgresKeyStoreMissingAndDelete(t *testing.T) {
	s := testStore(t)
	ks := s.Keys()

	if _, err := ks.Load("did:key:zAbsent"); !errors.Is(err, identity.ErrKeyNotFound) {
		t.Errorf("Load(absent) error = %v, want identity.ErrKeyNotFound", err)
	}
	if err := ks.Delete("did:key:zAbsent"); !errors.Is(err, identity.ErrKeyNotFound) {
		t.Errorf("Delete(absent) error = %v, want identity.ErrKeyNotFound", err)
	}

	priv, did := mustKey(t)
	if err := ks.Store(did, priv); err != nil {
		t.Fatalf("Store: %v", err)
	}
	if err := ks.Delete(did); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := ks.Load(did); !errors.Is(err, identity.ErrKeyNotFound) {
		t.Errorf("Load after Delete error = %v, want identity.ErrKeyNotFound", err)
	}
}

func TestPostgresKeyStoreRejectsBadInput(t *testing.T) {
	ks := testStore(t).Keys()
	priv, _ := mustKey(t)

	if err := ks.Store("", priv); !errors.Is(err, identity.ErrEmptyDID) {
		t.Errorf("Store(empty did) error = %v, want identity.ErrEmptyDID", err)
	}
	if err := ks.Store("did:key:zShort", priv[:16]); !errors.Is(err, identity.ErrInvalidPrivateKey) {
		t.Errorf("Store(short key) error = %v, want identity.ErrInvalidPrivateKey", err)
	}
}

// TestPostgresKeyStoreRejectsCorruptRow guards the panic path: ed25519.Sign
// panics on a wrong-sized key, so a corrupt row must fail at Load.
func TestPostgresKeyStoreRejectsCorruptRow(t *testing.T) {
	s := testStore(t)
	if _, err := s.pool.Exec(t.Context(),
		`INSERT INTO agent_keys (did, private_key, created_at) VALUES ($1, $2, 0)`,
		"did:key:zCorrupt", []byte{1, 2, 3}); err != nil {
		t.Fatalf("insert corrupt row: %v", err)
	}
	if _, err := s.Keys().Load("did:key:zCorrupt"); !errors.Is(err, identity.ErrInvalidPrivateKey) {
		t.Errorf("Load(corrupt) error = %v, want identity.ErrInvalidPrivateKey", err)
	}
}

func TestPostgresKeyStoreList(t *testing.T) {
	ks := testStore(t).Keys()
	if got := ks.List(); len(got) != 0 {
		t.Errorf("List() on empty store = %v, want empty", got)
	}

	var dids []string
	for i := 0; i < 3; i++ {
		priv, did := mustKey(t)
		if err := ks.Store(did, priv); err != nil {
			t.Fatalf("Store: %v", err)
		}
		dids = append(dids, did)
	}
	sort.Strings(dids)

	got := ks.List()
	if len(got) != len(dids) {
		t.Fatalf("List() returned %d DIDs, want %d", len(got), len(dids))
	}
	for i := range dids {
		if got[i] != dids[i] {
			t.Errorf("List()[%d] = %q, want %q (must be ascending)", i, got[i], dids[i])
		}
	}
}

// TestPostgresKeyStoreListIsByteOrdered pins List() to byte order rather than
// the database's collation. MemoryKeyStore.List sorts with sort.Strings, so
// without an explicit COLLATE the two backends disagree on any pair of DIDs
// whose first differing byte differs only in case: a linguistic collation such
// as en_US.utf8 — the default in the postgres:16 image CI uses — folds case and
// puts "...cgd" before "...HJS", while byte order puts 'H' (0x48) before
// 'c' (0x63). TestPostgresKeyStoreList catches this only when the randomly
// generated DIDs happen to differ in case at the deciding position, which is
// why it passed on 2026-10-20 and failed on 2026-10-27. These DIDs are the
// pair from that failure, so the disagreement is reproduced on every run.
func TestPostgresKeyStoreListIsByteOrdered(t *testing.T) {
	ks := testStore(t).Keys()
	priv, _ := mustKey(t)

	// Byte order: 'H' (0x48) < 'c' (0x63), so the "HJSF" DID sorts first.
	// Collation order under en_US.utf8: the reverse.
	const (
		upper = "did:key:z6MkiHJSF3iQxXDGVjdtqjboyx8JtdsvwKGG9d7WhVWPvMjL"
		lower = "did:key:z6MkicgdCQFiX64pd4K7G1HrE4CTv8KYHoAvd3aZnGD7XJvH"
	)
	// Stored in the order that is wrong for the assertion, so a store that
	// simply echoed insertion order would fail too.
	for _, did := range []string{lower, upper} {
		if err := ks.Store(did, priv); err != nil {
			t.Fatalf("Store(%s): %v", did, err)
		}
	}

	want := []string{upper, lower}
	got := ks.List()
	if len(got) != len(want) {
		t.Fatalf("List() returned %d DIDs, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("List()[%d] = %q, want %q (must be byte order, not collation order)",
				i, got[i], want[i])
		}
	}
}
