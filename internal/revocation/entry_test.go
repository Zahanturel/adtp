package revocation

import (
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/Zahanturel/adtp/internal/signing"
)

func TestRevocationEntryRoundTrip(t *testing.T) {
	key, did := genKey(t)
	entry, err := CreateRevocationEntry(
		RevocationSubject{CID: "bafkreitarget"}, ScopeCredential, StatusRevoked,
		platformAuth(did), 1, "", key)
	if err != nil {
		t.Fatalf("CreateRevocationEntry: %v", err)
	}
	if entry.Typ != RevocationEntryTyp {
		t.Errorf("typ = %q", entry.Typ)
	}
	if err := VerifyRevocationEntry(entry, key.Public().(ed25519.PublicKey)); err != nil {
		t.Errorf("VerifyRevocationEntry: %v", err)
	}
}

func TestVerifyRevocationEntryRejects(t *testing.T) {
	key, did := genKey(t)
	entry, err := CreateRevocationEntry(
		RevocationSubject{CID: "bafkreitarget"}, ScopeCredential, StatusRevoked,
		platformAuth(did), 1, "", key)
	if err != nil {
		t.Fatalf("CreateRevocationEntry: %v", err)
	}

	t.Run("tampered subject", func(t *testing.T) {
		bad := *entry
		bad.Subject = RevocationSubject{CID: "bafkreiother"}
		if err := VerifyRevocationEntry(&bad, key.Public().(ed25519.PublicKey)); !errors.Is(err, signing.ErrVerification) {
			t.Errorf("err = %v, want ErrVerification", err)
		}
	})
	t.Run("wrong key", func(t *testing.T) {
		otherKey, _ := genKey(t)
		if err := VerifyRevocationEntry(entry, otherKey.Public().(ed25519.PublicKey)); !errors.Is(err, signing.ErrVerification) {
			t.Errorf("err = %v, want ErrVerification", err)
		}
	})
	t.Run("wrong typ", func(t *testing.T) {
		bad := *entry
		bad.Typ = "adtp/ucan/1"
		if err := VerifyRevocationEntry(&bad, key.Public().(ed25519.PublicKey)); !errors.Is(err, ErrNotRevocationEntry) {
			t.Errorf("err = %v, want ErrNotRevocationEntry", err)
		}
	})
}

func TestCreateRevocationEntryValidation(t *testing.T) {
	key, did := genKey(t)

	t.Run("authority cannot set status", func(t *testing.T) {
		auth := RevocationAuth{DID: did, Basis: AuthSubject}
		if _, err := CreateRevocationEntry(RevocationSubject{CID: "c"}, ScopeCredential, StatusSuspended, auth, 1, "", key); !errors.Is(err, ErrStatusNotPermitted) {
			t.Errorf("err = %v, want ErrStatusNotPermitted", err)
		}
	})
	t.Run("missing subject", func(t *testing.T) {
		if _, err := CreateRevocationEntry(RevocationSubject{}, ScopeCredential, StatusRevoked, platformAuth(did), 1, "", key); !errors.Is(err, ErrMissingSubject) {
			t.Errorf("err = %v, want ErrMissingSubject", err)
		}
	})
	t.Run("bad key", func(t *testing.T) {
		if _, err := CreateRevocationEntry(RevocationSubject{CID: "c"}, ScopeCredential, StatusRevoked, platformAuth(did), 1, "", ed25519.PrivateKey{1}); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("err = %v, want ErrInvalidKey", err)
		}
	})
}

func TestRevocationEntryHash(t *testing.T) {
	key, did := genKey(t)
	entry, err := CreateRevocationEntry(RevocationSubject{DID: "did:key:zAgent"}, ScopeIdentity, StatusCompromised, platformAuth(did), 1, "", key)
	if err != nil {
		t.Fatalf("CreateRevocationEntry: %v", err)
	}
	h1, err := entry.Hash()
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	h2, _ := entry.Hash()
	if h1 != h2 || h1 == "" {
		t.Errorf("Hash not deterministic/non-empty: %q %q", h1, h2)
	}
	if subjectKey := entry.Subject.Key(); subjectKey != "did:key:zAgent" {
		t.Errorf("Subject.Key() = %q", subjectKey)
	}
}
