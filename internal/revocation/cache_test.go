package revocation

import (
	"errors"
	"testing"
)

func TestCacheRevokeAndGetStatus(t *testing.T) {
	key, did := genKey(t)
	c := NewMemoryRevocationCache()
	if got, _ := c.GetStatus("bafkreione"); got != nil {
		t.Errorf("unknown subject status = %+v, want nil", got)
	}

	if err := c.Revoke(signedEntry(t, key, did, RevocationSubject{CID: "bafkreione"}, StatusRevoked, 1)); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	got, _ := c.GetStatus("bafkreione")
	if got == nil || got.Status != StatusRevoked {
		t.Errorf("status = %+v, want REVOKED", got)
	}
	if c.CurrentSeq("bafkreione") != 1 {
		t.Errorf("CurrentSeq = %d, want 1", c.CurrentSeq("bafkreione"))
	}
}

// TestCacheRevokeRejectsUnsigned proves the apply-time authenticity gate: a
// well-formed but unsigned entry (no resolvable authority) is rejected.
func TestCacheRevokeRejectsUnsigned(t *testing.T) {
	c := NewMemoryRevocationCache()
	err := c.Revoke(RevocationEntry{Subject: RevocationSubject{CID: "bafkreione"}, Status: StatusRevoked, Seq: 1})
	if err == nil {
		t.Fatal("Revoke(unsigned) = nil, want rejection")
	}
}

// TestCacheRevokeRejectsForgedSignature proves an entry signed by a key other
// than the authority it names is rejected.
func TestCacheRevokeRejectsForgedSignature(t *testing.T) {
	key, did := genKey(t)
	other, _ := genKey(t)
	c := NewMemoryRevocationCache()
	// Build a valid entry, then re-sign its struct with a different key while
	// keeping the original authority DID — the signature no longer matches.
	e := signedEntry(t, key, did, RevocationSubject{CID: "c"}, StatusRevoked, 1)
	forged, err := CreateRevocationEntry(e.Subject, e.Scope, e.Status, RevocationAuth{DID: did, Basis: AuthPlatform, Proof: "x"}, e.Seq, "", other)
	if err != nil {
		t.Fatalf("CreateRevocationEntry: %v", err)
	}
	if err := c.Revoke(*forged); err == nil {
		t.Fatal("Revoke(forged) = nil, want rejection")
	}
}

func TestCacheSequenceRollback(t *testing.T) {
	key, did := genKey(t)
	c := NewMemoryRevocationCache()
	if err := c.Revoke(signedEntry(t, key, did, RevocationSubject{CID: "c"}, StatusSuspended, 5)); err != nil {
		t.Fatalf("Revoke seq 5: %v", err)
	}
	// A lower or equal sequence for the same subject is rejected.
	if err := c.Revoke(signedEntry(t, key, did, RevocationSubject{CID: "c"}, StatusReinstated, 5)); !errors.Is(err, ErrSequenceRollback) {
		t.Errorf("equal seq err = %v, want ErrSequenceRollback", err)
	}
	if err := c.Revoke(signedEntry(t, key, did, RevocationSubject{CID: "c"}, StatusRevoked, 4)); !errors.Is(err, ErrSequenceRollback) {
		t.Errorf("lower seq err = %v, want ErrSequenceRollback", err)
	}
	// A higher sequence supersedes.
	if err := c.Revoke(signedEntry(t, key, did, RevocationSubject{CID: "c"}, StatusRevoked, 6)); err != nil {
		t.Errorf("higher seq err = %v, want nil", err)
	}
}

func TestCacheReinstatedIsActive(t *testing.T) {
	key, did := genKey(t)
	c := NewMemoryRevocationCache()
	_ = c.Revoke(signedEntry(t, key, did, RevocationSubject{CID: "c"}, StatusSuspended, 1))
	_ = c.Revoke(signedEntry(t, key, did, RevocationSubject{CID: "c"}, StatusReinstated, 2))
	if got, _ := c.GetStatus("c"); got != nil {
		t.Errorf("reinstated subject status = %+v, want nil (active)", got)
	}
}

func TestCacheMissingSubject(t *testing.T) {
	c := NewMemoryRevocationCache()
	// Subject check precedes the signature check, so a subject-less entry reports
	// ErrMissingSubject regardless of signing.
	if err := c.Revoke(RevocationEntry{Status: StatusRevoked, Seq: 1}); !errors.Is(err, ErrMissingSubject) {
		t.Errorf("err = %v, want ErrMissingSubject", err)
	}
}

func TestCacheUpdateFromList(t *testing.T) {
	key, did := genKey(t)
	c := NewMemoryRevocationCache()

	list1, _ := CreateRevocationList(sampleEntries(t, key, did), did, "", 1, key)
	if err := c.UpdateFromList(list1, pubOf(key)); err != nil {
		t.Fatalf("UpdateFromList seq 1: %v", err)
	}
	if got, _ := c.GetStatus("bafkreione"); got == nil {
		t.Errorf("entry from list not applied")
	}

	// A list with sequence <= the cached list sequence is rejected.
	stale, _ := CreateRevocationList(nil, did, "", 1, key)
	if err := c.UpdateFromList(stale, pubOf(key)); !errors.Is(err, ErrSequenceRollback) {
		t.Errorf("stale list err = %v, want ErrSequenceRollback", err)
	}

	// A newer list is accepted.
	list2, _ := CreateRevocationList(nil, did, "", 2, key)
	if err := c.UpdateFromList(list2, pubOf(key)); err != nil {
		t.Errorf("UpdateFromList seq 2: %v", err)
	}
}

// TestCacheUpdateFromListRejectsForged proves a list not signed by the expected
// issuer is rejected before any entry is applied (Fix 7).
func TestCacheUpdateFromListRejectsForged(t *testing.T) {
	key, did := genKey(t)
	attacker, _ := genKey(t)
	c := NewMemoryRevocationCache()

	// List signed by the attacker but presented as if from did; verified under the
	// legitimate issuer key it must fail.
	forged, _ := CreateRevocationList(sampleEntries(t, key, did), did, "", 1, attacker)
	if err := c.UpdateFromList(forged, pubOf(key)); err == nil {
		t.Fatal("UpdateFromList(forged) = nil, want rejection")
	}
	if got, _ := c.GetStatus("bafkreione"); got != nil {
		t.Errorf("forged list must not apply any entry, got %+v", got)
	}
}
