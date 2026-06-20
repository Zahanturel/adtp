package credential

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/Zahanturel/adtp/internal/signing"
)

// AttSealTyp is the typ tag of an att_seal (SD-1).
const AttSealTyp = "adtp/seal/1"

// att_seal errors.
var (
	ErrNotAttSeal         = errors.New("not an att_seal")
	ErrSealDigestMismatch = errors.New("att_seal digest does not match capability set")
)

// AttSeal is the serialization-differential defense carried by a RESTATE hop
// (Section 9). It commits the hop issuer to the exact, canonicalized capability
// set of the child token. The seal does not extend the trust model — its signer
// is the hop issuer, the same key that signs the token — so RESTATE delegation
// integrity remains dependent on capability_leq. RESTRICT needs no seal.
type AttSeal struct {
	Typ    string `json:"typ"`
	Digest string `json:"d"`
	Aud    string `json:"aud"`
	Prf    string `json:"prf"`
	Sig    string `json:"sig"`
}

// attDigest computes base64url(SHA-256(JCS(att))).
func attDigest(att []Capability) (string, error) {
	if att == nil {
		att = []Capability{}
	}
	canonical, err := signing.CanonicalizeValue(att)
	if err != nil {
		return "", fmt.Errorf("adtp/credential: att digest: %w", err)
	}
	sum := sha256.Sum256(canonical)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// CreateAttSeal builds and signs an att_seal over childAtt. signerKey is the hop
// issuer's key (the delegator, i.e. the holder of the parent credential's
// audience key), which is also the key that signs the child token.
func CreateAttSeal(childAtt []Capability, childAud, parentCID string, signerKey ed25519.PrivateKey) (*AttSeal, error) {
	if len(signerKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("adtp/credential: %w", ErrInvalidKey)
	}
	if childAud == "" || parentCID == "" {
		return nil, fmt.Errorf("adtp/credential: %w: att_seal aud and prf", ErrMissingField)
	}
	digest, err := attDigest(childAtt)
	if err != nil {
		return nil, err
	}
	seal := &AttSeal{Typ: AttSealTyp, Digest: digest, Aud: childAud, Prf: parentCID}
	sig, err := signing.Sign(seal, signerKey)
	if err != nil {
		return nil, fmt.Errorf("adtp/credential: sign att_seal: %w", err)
	}
	seal.Sig = signing.EncodeSignature(sig)
	return seal, nil
}

// VerifyAttSeal verifies the seal's signature under signerPub (the hop issuer's
// key) and confirms that its digest matches childAtt. A mismatch means the
// parsed capability set is not what the issuer committed to.
func VerifyAttSeal(seal *AttSeal, childAtt []Capability, signerPub ed25519.PublicKey) error {
	if seal == nil {
		return fmt.Errorf("adtp/credential: %w: nil seal", ErrNotAttSeal)
	}
	if seal.Typ != AttSealTyp {
		return fmt.Errorf("adtp/credential: %w: typ %q", ErrNotAttSeal, seal.Typ)
	}
	sig, err := signing.DecodeSignature(seal.Sig)
	if err != nil {
		return err
	}
	if err := signing.Verify(seal, sig, signerPub); err != nil {
		return err
	}
	digest, err := attDigest(childAtt)
	if err != nil {
		return err
	}
	if digest != seal.Digest {
		return fmt.Errorf("adtp/credential: %w", ErrSealDigestMismatch)
	}
	return nil
}
