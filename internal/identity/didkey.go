// Package identity implements AITP agent identity: did:key generation,
// parsing, and resolution over Ed25519 keys, plus key storage.
//
// A did:key encodes a public key directly in the identifier, so resolution is a
// purely local, offline operation — no network, no registry. AITP uses did:key
// for agents (short-lived leaves) and did:web with pinned root keys for
// organizations (specification Section 15.1; implemented in a later phase).
package identity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
)

const (
	// didKeyPrefix is the method prefix for did:key identifiers.
	didKeyPrefix = "did:key:"
	// base58BTCPrefix is the multibase code that precedes base58btc data.
	base58BTCPrefix = "z"
)

// ed25519MulticodecPrefix is the unsigned-varint multicodec code for an Ed25519
// public key. The code 0xed encodes as the two bytes 0xed 0x01. It is treated as
// an immutable constant; nothing mutates it.
var ed25519MulticodecPrefix = []byte{0xed, 0x01}

// Identifier errors.
var (
	// ErrUnsupportedDIDMethod reports a DID that is not a did:key.
	ErrUnsupportedDIDMethod = errors.New("unsupported DID method")
	// ErrMalformedDID reports a did:key whose multibase, multicodec, or key
	// length is invalid.
	ErrMalformedDID = errors.New("malformed did:key")
)

// GenerateDID creates a fresh Ed25519 key pair using crypto/rand and returns its
// did:key identifier together with the private key.
func GenerateDID() (string, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", nil, fmt.Errorf("aitp/identity: generate key: %w", err)
	}
	return EncodeDID(pub), priv, nil
}

// EncodeDID renders an Ed25519 public key as a did:key identifier:
//
//	did:key:z<base58btc( 0xed 0x01 || rawPublicKey )>
func EncodeDID(pub ed25519.PublicKey) string {
	buf := make([]byte, 0, len(ed25519MulticodecPrefix)+ed25519.PublicKeySize)
	buf = append(buf, ed25519MulticodecPrefix...)
	buf = append(buf, pub...)
	return didKeyPrefix + base58BTCPrefix + base58Encode(buf)
}

// ParseDID decodes a did:key identifier into its Ed25519 public key. It rejects
// any other DID method, a missing or wrong multibase prefix, a non-Ed25519
// multicodec, and any key whose length is not 32 bytes.
func ParseDID(did string) (ed25519.PublicKey, error) {
	rest, ok := strings.CutPrefix(did, didKeyPrefix)
	if !ok {
		return nil, fmt.Errorf("aitp/identity: %w: %q has no %q prefix", ErrUnsupportedDIDMethod, did, didKeyPrefix)
	}
	multibase, ok := strings.CutPrefix(rest, base58BTCPrefix)
	if !ok {
		return nil, fmt.Errorf("aitp/identity: %w: missing 'z' base58btc multibase prefix", ErrMalformedDID)
	}

	decoded, err := base58Decode(multibase)
	if err != nil {
		return nil, fmt.Errorf("aitp/identity: %w: %v", ErrMalformedDID, err)
	}

	wantLen := len(ed25519MulticodecPrefix) + ed25519.PublicKeySize
	if len(decoded) != wantLen {
		return nil, fmt.Errorf("aitp/identity: %w: decoded %d bytes, want %d", ErrMalformedDID, len(decoded), wantLen)
	}
	if !bytes.Equal(decoded[:len(ed25519MulticodecPrefix)], ed25519MulticodecPrefix) {
		return nil, fmt.Errorf("aitp/identity: %w: multicodec is not Ed25519 (0xed 0x01)", ErrMalformedDID)
	}

	pub := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(pub, decoded[len(ed25519MulticodecPrefix):])
	return pub, nil
}

// ResolveDID resolves a did:key to its Ed25519 verification key. For the did:key
// method this is a purely local operation identical to ParseDID; the distinct
// name marks the resolution seam at which network-resolved methods such as
// did:web attach in later phases.
func ResolveDID(did string) (ed25519.PublicKey, error) {
	return ParseDID(did)
}
