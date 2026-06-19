package revocation

import (
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/adtp/adtp/internal/signing"
)

func sampleEntries(t *testing.T, key ed25519.PrivateKey, did string) []RevocationEntry {
	t.Helper()
	e1, err := CreateRevocationEntry(RevocationSubject{CID: "bafkreione"}, ScopeCredential, StatusRevoked, platformAuth(did), 1, "", key)
	if err != nil {
		t.Fatalf("entry: %v", err)
	}
	e2, err := CreateRevocationEntry(RevocationSubject{CID: "bafkreitwo"}, ScopeCredential, StatusRevoked, platformAuth(did), 1, "", key)
	if err != nil {
		t.Fatalf("entry: %v", err)
	}
	return []RevocationEntry{*e1, *e2}
}

func TestRevocationListRoundTrip(t *testing.T) {
	key, did := genKey(t)
	list, err := CreateRevocationList(sampleEntries(t, key, did), did, "", 1, key)
	if err != nil {
		t.Fatalf("CreateRevocationList: %v", err)
	}
	if list.Typ != RevocationListTyp || list.SchemaVersion != RevocationListSchemaVersion || list.ListID == "" {
		t.Errorf("list metadata = %+v", list)
	}
	if err := VerifyRevocationList(list, key.Public().(ed25519.PublicKey)); err != nil {
		t.Errorf("VerifyRevocationList: %v", err)
	}
}

func TestVerifyRevocationListRejects(t *testing.T) {
	key, did := genKey(t)
	list, err := CreateRevocationList(sampleEntries(t, key, did), did, "", 1, key)
	if err != nil {
		t.Fatalf("CreateRevocationList: %v", err)
	}

	t.Run("tampered sequence", func(t *testing.T) {
		bad := *list
		bad.Sequence = 999
		if err := VerifyRevocationList(&bad, key.Public().(ed25519.PublicKey)); !errors.Is(err, signing.ErrVerification) {
			t.Errorf("err = %v, want ErrVerification", err)
		}
	})
	t.Run("wrong key", func(t *testing.T) {
		otherKey, _ := genKey(t)
		if err := VerifyRevocationList(list, otherKey.Public().(ed25519.PublicKey)); !errors.Is(err, signing.ErrVerification) {
			t.Errorf("err = %v, want ErrVerification", err)
		}
	})
	t.Run("bad schema", func(t *testing.T) {
		bad := *list
		bad.SchemaVersion = "9.9"
		if err := VerifyRevocationList(&bad, key.Public().(ed25519.PublicKey)); !errors.Is(err, ErrNotRevocationList) {
			t.Errorf("err = %v, want ErrNotRevocationList", err)
		}
	})
	t.Run("missing typ", func(t *testing.T) {
		bad := *list
		bad.Typ = ""
		if err := VerifyRevocationList(&bad, key.Public().(ed25519.PublicKey)); !errors.Is(err, ErrNotRevocationList) {
			t.Errorf("err = %v, want ErrNotRevocationList", err)
		}
	})
	t.Run("wrong typ", func(t *testing.T) {
		bad := *list
		bad.Typ = "aitp/wrong/1"
		if err := VerifyRevocationList(&bad, key.Public().(ed25519.PublicKey)); !errors.Is(err, ErrNotRevocationList) {
			t.Errorf("err = %v, want ErrNotRevocationList", err)
		}
	})
	t.Run("bad key on create", func(t *testing.T) {
		if _, err := CreateRevocationList(nil, did, "", 1, ed25519.PrivateKey{1}); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("err = %v, want ErrInvalidKey", err)
		}
	})
}

func TestRevocationListHash(t *testing.T) {
	key, did := genKey(t)
	list, _ := CreateRevocationList(nil, did, "", 1, key)
	h, err := list.Hash()
	if err != nil || h == "" {
		t.Errorf("Hash = (%q, %v)", h, err)
	}
}
