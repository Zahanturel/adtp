package credential

import (
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/Zahanturel/adtp/internal/signing"
)

func sealAtt(t *testing.T) []Capability {
	t.Helper()
	c, err := NewCapability(CanResourceRead, "resource://db/customers")
	if err != nil {
		t.Fatalf("NewCapability: %v", err)
	}
	return []Capability{c}
}

func TestAttSealRoundTrip(t *testing.T) {
	signerKey, signerDID := agentKeyDID(t)
	att := sealAtt(t)
	parentCID := ComputeCID([]byte("parent"))

	seal, err := CreateAttSeal(att, "did:key:zChild", parentCID, signerKey)
	if err != nil {
		t.Fatalf("CreateAttSeal: %v", err)
	}
	if seal.Typ != AttSealTyp || seal.Aud != "did:key:zChild" || seal.Prf != parentCID {
		t.Errorf("seal fields = %+v", seal)
	}
	_ = signerDID

	if err := VerifyAttSeal(seal, att, signerKey.Public().(ed25519.PublicKey)); err != nil {
		t.Errorf("VerifyAttSeal: %v", err)
	}
}

func TestVerifyAttSealRejectsTamper(t *testing.T) {
	signerKey, _ := agentKeyDID(t)
	att := sealAtt(t)
	seal, err := CreateAttSeal(att, "did:key:zChild", ComputeCID([]byte("p")), signerKey)
	if err != nil {
		t.Fatalf("CreateAttSeal: %v", err)
	}

	t.Run("modified att", func(t *testing.T) {
		other, err := NewCapability(CanResourceWrite, "resource://db/customers")
		if err != nil {
			t.Fatalf("NewCapability: %v", err)
		}
		if err := VerifyAttSeal(seal, []Capability{other}, signerKey.Public().(ed25519.PublicKey)); !errors.Is(err, ErrSealDigestMismatch) {
			t.Errorf("err = %v, want ErrSealDigestMismatch", err)
		}
	})

	t.Run("wrong signer", func(t *testing.T) {
		otherKey, _ := agentKeyDID(t)
		if err := VerifyAttSeal(seal, att, otherKey.Public().(ed25519.PublicKey)); !errors.Is(err, signing.ErrVerification) {
			t.Errorf("err = %v, want signing.ErrVerification", err)
		}
	})

	t.Run("wrong typ", func(t *testing.T) {
		bad := *seal
		bad.Typ = "adtp/ucan/1"
		if err := VerifyAttSeal(&bad, att, signerKey.Public().(ed25519.PublicKey)); !errors.Is(err, ErrNotAttSeal) {
			t.Errorf("err = %v, want ErrNotAttSeal", err)
		}
	})
}

func TestCreateAttSealBadKey(t *testing.T) {
	if _, err := CreateAttSeal(sealAtt(t), "did:key:zC", "cid", ed25519.PrivateKey{1}); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("err = %v, want ErrInvalidKey", err)
	}
}
