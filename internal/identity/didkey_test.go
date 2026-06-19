package identity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
)

func TestGenerateDIDRoundTrip(t *testing.T) {
	for i := 0; i < 50; i++ {
		did, priv, err := GenerateDID()
		if err != nil {
			t.Fatalf("GenerateDID: %v", err)
		}
		if !strings.HasPrefix(did, "did:key:z6Mk") {
			t.Errorf("did = %q, want prefix did:key:z6Mk (Ed25519 multicodec)", did)
		}
		pub, err := ParseDID(did)
		if err != nil {
			t.Fatalf("ParseDID(%q): %v", did, err)
		}
		if !pub.Equal(priv.Public().(ed25519.PublicKey)) {
			t.Errorf("parsed public key does not match generated key")
		}
		// ResolveDID is the offline equivalent of ParseDID for did:key.
		resolved, err := ResolveDID(did)
		if err != nil {
			t.Fatalf("ResolveDID(%q): %v", did, err)
		}
		if !bytes.Equal(resolved, pub) {
			t.Errorf("ResolveDID disagrees with ParseDID")
		}
	}
}

// TestEncodeDIDDeterministic pins the did:key for a fixed seed. The mapping is
// reproducible by anyone (ed25519.NewKeyFromSeed is deterministic) and guards
// against silent regressions in the encoding.
func TestEncodeDIDDeterministic(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	did := EncodeDID(priv.Public().(ed25519.PublicKey))

	const want = "did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd"
	if did != want {
		t.Errorf("EncodeDID(seed 0..31)\n got: %q\nwant: %q", did, want)
	}
}

func TestParseDIDMalformed(t *testing.T) {
	// Build a structurally valid did:key, then derive malformed variants.
	validBody := append([]byte{0xed, 0x01}, make([]byte, ed25519.PublicKeySize)...)

	wrongMulticodec := append([]byte{0xec, 0x01}, make([]byte, ed25519.PublicKeySize)...)
	tooShort := append([]byte{0xed, 0x01}, make([]byte, ed25519.PublicKeySize-1)...)
	tooLong := append([]byte{0xed, 0x01}, make([]byte, ed25519.PublicKeySize+1)...)

	tests := []struct {
		name    string
		did     string
		wantErr error
	}{
		{"empty string", "", ErrUnsupportedDIDMethod},
		{"did:web method", "did:web:example.com", ErrUnsupportedDIDMethod},
		{"missing method body", "did:key:", ErrMalformedDID},
		{"wrong multibase prefix", "did:key:Q" + base58Encode(validBody), ErrMalformedDID},
		{"invalid base58 character", "did:key:z0OIl", ErrMalformedDID},
		{"wrong multicodec", "did:key:z" + base58Encode(wrongMulticodec), ErrMalformedDID},
		{"key too short", "did:key:z" + base58Encode(tooShort), ErrMalformedDID},
		{"key too long", "did:key:z" + base58Encode(tooLong), ErrMalformedDID},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseDID(tt.did)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("ParseDID(%q) error = %v, want errors.Is %v", tt.did, err, tt.wantErr)
			}
		})
	}
}

func TestParseDIDAcceptsValidEncoding(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	did := EncodeDID(pub)
	got, err := ParseDID(did)
	if err != nil {
		t.Fatalf("ParseDID: %v", err)
	}
	if !bytes.Equal(got, pub) {
		t.Errorf("ParseDID returned wrong key")
	}
}
