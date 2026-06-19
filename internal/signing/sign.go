package signing

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// DomainPrefix is the ASCII domain-separation tag prepended to every non-JWT
// signing input (SD-2). Together with the per-object typ field it ensures a
// signature produced for one kind of object can never be reinterpreted as a
// signature over another, and that no signing input is a raw concatenation of
// variable-length fields.
const DomainPrefix = "AITP1"

// sigField is the object member that carries the signature itself and is
// therefore excluded from the signing input.
const sigField = "sig"

// Signing-discipline errors.
var (
	// ErrNotObject reports that a value submitted for SD-2 signing is not a
	// JSON object. Every signed non-JWT structure is a single JSON object
	// (SD-1).
	ErrNotObject = errors.New("signed value is not a JSON object")
	// ErrInvalidPrivateKey reports a private key of the wrong size.
	ErrInvalidPrivateKey = errors.New("invalid ed25519 private key")
	// ErrInvalidPublicKey reports a public key of the wrong size.
	ErrInvalidPublicKey = errors.New("invalid ed25519 public key")
	// ErrInvalidSignature reports a signature of the wrong size.
	ErrInvalidSignature = errors.New("invalid ed25519 signature")
	// ErrVerification reports that a signature did not verify under the given
	// key and signing input.
	ErrVerification = errors.New("signature verification failed")
)

// SignatureInput returns the SD-2 canonical signing input for an object:
//
//	"AITP1" || 0x00 || JCS(object with its "sig" member removed)
//
// obj must marshal to a JSON object. Its "sig" member, if present, is removed
// before canonicalization so that signing and verification operate over
// identical bytes. The remaining members — including any not recognized by the
// caller (SD-7) — are canonicalized under the I-JSON profile, which also
// enforces integer-only numbers and rejects duplicate keys.
func SignatureInput(obj any) ([]byte, error) {
	marshaled, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("aitp/signing: marshal object: %w", err)
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(marshaled, &fields); err != nil {
		return nil, fmt.Errorf("aitp/signing: %w: %v", ErrNotObject, err)
	}
	delete(fields, sigField)

	stripped, err := json.Marshal(fields)
	if err != nil {
		return nil, fmt.Errorf("aitp/signing: re-marshal object: %w", err)
	}
	canon, err := Canonicalize(stripped)
	if err != nil {
		return nil, err
	}

	input := make([]byte, 0, len(DomainPrefix)+1+len(canon))
	input = append(input, DomainPrefix...)
	input = append(input, 0x00)
	input = append(input, canon...)
	return input, nil
}

// Sign computes the Ed25519 signature over SignatureInput(obj). The returned
// bytes are the raw 64-byte signature; callers place them in the object's "sig"
// member (see EncodeSignature).
func Sign(obj any, priv ed25519.PrivateKey) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("aitp/signing: %w: have %d bytes, want %d",
			ErrInvalidPrivateKey, len(priv), ed25519.PrivateKeySize)
	}
	input, err := SignatureInput(obj)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(priv, input), nil
}

// Verify recomputes SignatureInput(obj) — with obj's "sig" member excluded — and
// checks sig against it using pub. It returns nil on success and a non-nil error
// (ErrVerification on a cryptographic mismatch) otherwise.
func Verify(obj any, sig []byte, pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("aitp/signing: %w: have %d bytes, want %d",
			ErrInvalidPublicKey, len(pub), ed25519.PublicKeySize)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("aitp/signing: %w: have %d bytes, want %d",
			ErrInvalidSignature, len(sig), ed25519.SignatureSize)
	}
	input, err := SignatureInput(obj)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, input, sig) {
		return ErrVerification
	}
	return nil
}

// EncodeSignature renders a raw signature as base64url without padding, the
// encoding used for the "sig" member of SD-2 JSON objects (consistent with the
// JWS encoding used for JWT credentials).
func EncodeSignature(sig []byte) string {
	return base64.RawURLEncoding.EncodeToString(sig)
}

// DecodeSignature parses a base64url (unpadded) signature member back into raw
// bytes. It does not check the length; Verify does.
func DecodeSignature(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("aitp/signing: %w: %v", ErrInvalidSignature, err)
	}
	return b, nil
}
