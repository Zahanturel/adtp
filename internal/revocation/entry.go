package revocation

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/Zahanturel/adtp/internal/identity"
	"github.com/Zahanturel/adtp/internal/signing"
)

// RevocationEntryTyp is the typ tag of a revocation entry (SD-1).
const RevocationEntryTyp = "adtp/rev/1"

// Entry errors.
var (
	ErrNotRevocationEntry = errors.New("not a revocation entry")
	ErrMissingSubject     = errors.New("revocation entry has no subject")
	ErrInvalidKey         = errors.New("invalid ed25519 key")
)

// RevocationSubject identifies what is being revoked — a credential CID or a
// principal DID.
type RevocationSubject struct {
	CID string `json:"cid,omitempty"`
	DID string `json:"did,omitempty"`
}

// Key returns the subject's lookup key (CID if present, else DID).
func (s RevocationSubject) Key() string {
	if s.CID != "" {
		return s.CID
	}
	return s.DID
}

// RevocationAuth records who authorized a revocation and on what basis.
type RevocationAuth struct {
	DID   string              `json:"did"`
	Basis RevocationAuthority `json:"basis"`
	Proof string              `json:"proof"`
}

// RevocationEntry is a single signed revocation record (Section 13.2). Highest
// seq per subject wins.
type RevocationEntry struct {
	Typ       string            `json:"typ"`
	Seq       int64             `json:"seq"`
	Subject   RevocationSubject `json:"subject"`
	Scope     RevocationScope   `json:"scope"`
	Status    RevocationStatus  `json:"status"`
	Authority RevocationAuth    `json:"authority"`
	Iat       int64             `json:"iat"`
	Prev      string            `json:"prev"`
	Sig       string            `json:"sig"`
}

// CreateRevocationEntry builds and SD-2-signs a revocation entry, validating
// that the authority is permitted to set the status with the scope.
func CreateRevocationEntry(subject RevocationSubject, scope RevocationScope, status RevocationStatus, authority RevocationAuth, seq int64, prevHash string, signerKey ed25519.PrivateKey) (*RevocationEntry, error) {
	if len(signerKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("adtp/revocation: %w", ErrInvalidKey)
	}
	if subject.CID == "" && subject.DID == "" {
		return nil, fmt.Errorf("adtp/revocation: %w", ErrMissingSubject)
	}
	if err := ValidateAuthority(authority.Basis, status, scope); err != nil {
		return nil, err
	}

	entry := &RevocationEntry{
		Typ:       RevocationEntryTyp,
		Seq:       seq,
		Subject:   subject,
		Scope:     scope,
		Status:    status,
		Authority: authority,
		Iat:       time.Now().Unix(),
		Prev:      prevHash,
	}
	sig, err := signing.Sign(entry, signerKey)
	if err != nil {
		return nil, fmt.Errorf("adtp/revocation: sign entry: %w", err)
	}
	entry.Sig = signing.EncodeSignature(sig)
	return entry, nil
}

// VerifyRevocationEntry checks the entry's typ, authority model, and SD-2
// signature under pub.
func VerifyRevocationEntry(entry *RevocationEntry, pub ed25519.PublicKey) error {
	if entry.Typ != RevocationEntryTyp {
		return fmt.Errorf("adtp/revocation: %w: typ %q", ErrNotRevocationEntry, entry.Typ)
	}
	if err := ValidateAuthority(entry.Authority.Basis, entry.Status, entry.Scope); err != nil {
		return err
	}
	sig, err := signing.DecodeSignature(entry.Sig)
	if err != nil {
		return err
	}
	return signing.Verify(entry, sig, pub)
}

// VerifyEntrySelfSignature resolves the entry's authority DID as a did:key and
// verifies the entry's SD-2 signature under it. It is the apply-time authenticity
// check: a store must reject any entry not validly signed by the authority it
// names, so a forged entry (e.g. a spurious REINSTATED) cannot be applied.
// (did:web authorities would require a resolver; this build issues did:key.)
func VerifyEntrySelfSignature(e *RevocationEntry) error {
	pub, err := identity.ParseDID(e.Authority.DID)
	if err != nil {
		return fmt.Errorf("adtp/revocation: %w: cannot resolve authority %q: %v", ErrNotRevocationEntry, e.Authority.DID, err)
	}
	return VerifyRevocationEntry(e, pub)
}

// Hash returns the hex SHA-256 of the entry's canonical form, used as the prev
// link of the next entry.
func (e *RevocationEntry) Hash() (string, error) {
	canonical, err := signing.CanonicalizeValue(e)
	if err != nil {
		return "", fmt.Errorf("adtp/revocation: hash entry: %w", err)
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}
