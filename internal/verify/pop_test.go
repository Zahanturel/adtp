package verify

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/adtp/adtp/internal/signing"
)

func codeOf(err error) ErrorCode {
	var ve *VerificationError
	if errors.As(err, &ve) {
		return ve.Code
	}
	return ""
}

func resign(t *testing.T, inv *UCANInvocation, key ed25519.PrivateKey) {
	t.Helper()
	sig, err := signing.Sign(inv, key)
	if err != nil {
		t.Fatalf("re-sign: %v", err)
	}
	inv.Sig = signing.EncodeSignature(sig)
}

func TestVerifyInvocationValid(t *testing.T) {
	key, did := genKey(t)
	cache := NewMemoryNonceCache()
	inv, err := CreateInvocation("bafkreileaf", "tool/invoke", "tool://s/x", nil, key, "did:key:zVerifier", "")
	if err != nil {
		t.Fatalf("CreateInvocation: %v", err)
	}
	if err := VerifyInvocation(inv, "did:key:zVerifier", did, cache); err != nil {
		t.Errorf("VerifyInvocation: %v", err)
	}
}

func TestVerifyInvocationReplay(t *testing.T) {
	key, did := genKey(t)
	cache := NewMemoryNonceCache()
	inv, err := CreateInvocation("bafkreileaf", "tool/invoke", "tool://s/x", nil, key, "did:key:zVerifier", "")
	if err != nil {
		t.Fatalf("CreateInvocation: %v", err)
	}
	if err := VerifyInvocation(inv, "did:key:zVerifier", did, cache); err != nil {
		t.Fatalf("first VerifyInvocation: %v", err)
	}
	if err := VerifyInvocation(inv, "did:key:zVerifier", did, cache); codeOf(err) != CodePoPFailed {
		t.Errorf("replay err = %v, want PoP failed", err)
	}
}

func TestVerifyInvocationRejections(t *testing.T) {
	key, did := genKey(t)
	verifierDID := "did:key:zVerifier"

	tests := []struct {
		name     string
		mutate   func(inv *UCANInvocation)
		leafAud  string
		expected string
	}{
		{"stale iat", func(inv *UCANInvocation) {
			inv.Iat = time.Now().Unix() - 1000
			resign(t, inv, key)
		}, did, verifierDID},
		{"future iat", func(inv *UCANInvocation) {
			inv.Iat = time.Now().Unix() + 1000
			resign(t, inv, key)
		}, did, verifierDID},
		{"wrong presenter (leaf aud mismatch)", func(inv *UCANInvocation) {}, "did:key:zSomeoneElse", verifierDID},
		{"wrong verifier", func(inv *UCANInvocation) { inv.Aud = "did:key:zWrong" }, did, verifierDID},
		{"tampered signature", func(inv *UCANInvocation) {
			sig, _ := signing.DecodeSignature(inv.Sig)
			sig[0] ^= 0x01
			inv.Sig = signing.EncodeSignature(sig)
		}, did, verifierDID},
		{"tampered payload", func(inv *UCANInvocation) { inv.Run.Resource = "tool://s/evil" }, did, verifierDID},
		{"wrong typ", func(inv *UCANInvocation) {
			inv.Typ = "aitp/ucan/1"
			resign(t, inv, key)
		}, did, verifierDID},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := NewMemoryNonceCache()
			inv, err := CreateInvocation("bafkreileaf", "tool/invoke", "tool://s/x", nil, key, verifierDID, "")
			if err != nil {
				t.Fatalf("CreateInvocation: %v", err)
			}
			tt.mutate(inv)
			if err := VerifyInvocation(inv, tt.expected, tt.leafAud, cache); codeOf(err) != CodePoPFailed {
				t.Errorf("err = %v, want PoP failed", err)
			}
		})
	}
}

func TestNonceCacheInstanceID(t *testing.T) {
	a := NewMemoryNonceCache()
	b := NewMemoryNonceCache()
	if a.InstanceID() == "" {
		t.Errorf("empty instance id")
	}
	if a.InstanceID() == b.InstanceID() {
		t.Errorf("distinct caches share an instance id")
	}
}

func TestNonceCacheCheckAndStore(t *testing.T) {
	cache := NewMemoryNonceCache()
	seen, err := cache.CheckAndStore("nonce-1", time.Minute)
	if err != nil || seen {
		t.Fatalf("first = (%v, %v), want (false, nil)", seen, err)
	}
	seen, err = cache.CheckAndStore("nonce-1", time.Minute)
	if err != nil || !seen {
		t.Errorf("second = (%v, %v), want (true, nil)", seen, err)
	}
}
