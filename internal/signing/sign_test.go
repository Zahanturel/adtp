package signing

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

// signedObject mirrors the shape of a protocol SD-2 object: a typ tag, some
// payload fields, and a sig member.
type signedObject struct {
	Typ string `json:"typ"`
	Iss string `json:"iss"`
	N   int    `json:"n"`
	Sig string `json:"sig,omitempty"`
}

func TestSignatureInputExactBytes(t *testing.T) {
	obj := map[string]any{
		"typ": "adtp/cav/1",
		"b":   1,
		"a":   2,
	}
	got, err := SignatureInput(obj)
	if err != nil {
		t.Fatalf("SignatureInput: %v", err)
	}

	want := append([]byte(DomainPrefix), 0x00)
	want = append(want, []byte(`{"a":2,"b":1,"typ":"adtp/cav/1"}`)...)
	if !bytes.Equal(got, want) {
		t.Errorf("SignatureInput\n got: %q\nwant: %q", got, want)
	}
}

func TestSignatureInputExcludesSig(t *testing.T) {
	obj := signedObject{Typ: "adtp/cav/1", Iss: "did:key:zAlice", N: 7}

	withoutSig, err := SignatureInput(obj)
	if err != nil {
		t.Fatalf("SignatureInput (no sig): %v", err)
	}

	obj.Sig = "this-is-not-a-real-signature"
	withSig, err := SignatureInput(obj)
	if err != nil {
		t.Fatalf("SignatureInput (with sig): %v", err)
	}

	if !bytes.Equal(withoutSig, withSig) {
		t.Errorf("sig member affected signing input\n without: %q\n    with: %q", withoutSig, withSig)
	}
}

func TestSignatureInputStructAndMapAgree(t *testing.T) {
	obj := signedObject{Typ: "adtp/cav/1", Iss: "did:key:zAlice", N: 7}
	fromStruct, err := SignatureInput(obj)
	if err != nil {
		t.Fatalf("struct: %v", err)
	}
	fromMap, err := SignatureInput(map[string]any{
		"n": 7, "iss": "did:key:zAlice", "typ": "adtp/cav/1",
	})
	if err != nil {
		t.Fatalf("map: %v", err)
	}
	if !bytes.Equal(fromStruct, fromMap) {
		t.Errorf("struct and map disagree\n struct: %q\n    map: %q", fromStruct, fromMap)
	}
}

func TestSignatureInputErrors(t *testing.T) {
	tests := []struct {
		name    string
		obj     any
		wantErr error
	}{
		{"array", []int{1, 2, 3}, ErrNotObject},
		{"scalar", 42, ErrNotObject},
		{"string", "hello", ErrNotObject},
		{"float field", map[string]any{"amount": 1.5}, ErrNonInteger},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := SignatureInput(tt.obj)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("SignatureInput error = %v, want errors.Is %v", err, tt.wantErr)
			}
		})
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	obj := signedObject{Typ: "adtp/cav/1", Iss: "did:key:zAlice", N: 7}
	sig, err := Sign(obj, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("signature length = %d, want %d", len(sig), ed25519.SignatureSize)
	}

	// Verification succeeds whether or not the object carries its sig member.
	if err := Verify(obj, sig, pub); err != nil {
		t.Errorf("Verify (no sig member): %v", err)
	}
	obj.Sig = EncodeSignature(sig)
	if err := Verify(obj, sig, pub); err != nil {
		t.Errorf("Verify (with sig member): %v", err)
	}
}

func TestVerifyRejectsTamper(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	obj := signedObject{Typ: "adtp/cav/1", Iss: "did:key:zAlice", N: 7}
	sig, err := Sign(obj, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	t.Run("mutated field", func(t *testing.T) {
		tampered := obj
		tampered.N = 8
		if err := Verify(tampered, sig, pub); !errors.Is(err, ErrVerification) {
			t.Errorf("Verify(tampered) = %v, want ErrVerification", err)
		}
	})

	t.Run("wrong key", func(t *testing.T) {
		otherPub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		if err := Verify(obj, sig, otherPub); !errors.Is(err, ErrVerification) {
			t.Errorf("Verify(wrong key) = %v, want ErrVerification", err)
		}
	})

	t.Run("flipped signature bit", func(t *testing.T) {
		bad := bytes.Clone(sig)
		bad[0] ^= 0x01
		if err := Verify(obj, bad, pub); !errors.Is(err, ErrVerification) {
			t.Errorf("Verify(flipped sig) = %v, want ErrVerification", err)
		}
	})
}

func TestSignVerifyKeySizeErrors(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	obj := signedObject{Typ: "adtp/cav/1", N: 1}

	if _, err := Sign(obj, ed25519.PrivateKey{1, 2, 3}); !errors.Is(err, ErrInvalidPrivateKey) {
		t.Errorf("Sign(short key) = %v, want ErrInvalidPrivateKey", err)
	}

	sig, err := Sign(obj, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := Verify(obj, sig, ed25519.PublicKey{1, 2, 3}); !errors.Is(err, ErrInvalidPublicKey) {
		t.Errorf("Verify(short pub) = %v, want ErrInvalidPublicKey", err)
	}
	if err := Verify(obj, []byte{1, 2, 3}, pub); !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("Verify(short sig) = %v, want ErrInvalidSignature", err)
	}
}

func TestSignatureEncoding(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	sig, err := Sign(signedObject{Typ: "adtp/cav/1", N: 1}, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	encoded := EncodeSignature(sig)
	decoded, err := DecodeSignature(encoded)
	if err != nil {
		t.Fatalf("DecodeSignature: %v", err)
	}
	if !bytes.Equal(sig, decoded) {
		t.Errorf("signature round-trip mismatch")
	}
	if _, err := DecodeSignature("not valid base64url!!!"); !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("DecodeSignature(bad) = %v, want ErrInvalidSignature", err)
	}
}
