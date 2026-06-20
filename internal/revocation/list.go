package revocation

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/Zahanturel/adtp/internal/signing"
)

// RevocationListSchemaVersion is the supported list schema.
const RevocationListSchemaVersion = "1.0"

// RevocationListTyp is the SD-1 typ tag of a revocation list. Like every other
// signed object it carries a typ so a signature can never be reinterpreted as a
// signature over a different object kind.
const RevocationListTyp = "adtp/revlist/1"

// defaultListValidity is how long a freshly issued list is valid, in seconds.
const defaultListValidity = 900

// List errors.
var (
	ErrNotRevocationList = errors.New("not a revocation list")
	ErrSequenceRollback  = errors.New("revocation list sequence rollback")
)

// RevocationList is a signed, sequenced batch of revocation entries (Section
// 13.4). Verifiers reject any list whose sequence is not greater than the last
// one they accepted.
type RevocationList struct {
	Typ           string            `json:"typ"`
	SchemaVersion string            `json:"schema_version"`
	IssuedAt      int64             `json:"issued_at"`
	ExpiresAt     int64             `json:"expires_at"`
	Issuer        string            `json:"issuer"`
	ListID        string            `json:"list_id"`
	Sequence      int64             `json:"sequence"`
	Entries       []RevocationEntry `json:"entries"`
	PrevListHash  string            `json:"previous_list_hash"`
	Sig           string            `json:"sig"`
}

// CreateRevocationList builds and SD-2-signs a revocation list.
func CreateRevocationList(entries []RevocationEntry, issuerDID, prevHash string, seq int64, signerKey ed25519.PrivateKey) (*RevocationList, error) {
	if len(signerKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("adtp/revocation: %w", ErrInvalidKey)
	}
	if entries == nil {
		entries = []RevocationEntry{}
	}
	now := time.Now().Unix()
	list := &RevocationList{
		Typ:           RevocationListTyp,
		SchemaVersion: RevocationListSchemaVersion,
		IssuedAt:      now,
		ExpiresAt:     now + defaultListValidity,
		Issuer:        issuerDID,
		ListID:        listID(issuerDID, seq),
		Sequence:      seq,
		Entries:       entries,
		PrevListHash:  prevHash,
	}
	sig, err := signing.Sign(list, signerKey)
	if err != nil {
		return nil, fmt.Errorf("adtp/revocation: sign list: %w", err)
	}
	list.Sig = signing.EncodeSignature(sig)
	return list, nil
}

// VerifyRevocationList checks the list's schema and SD-2 signature under
// issuerPub. Sequence monotonicity is enforced by the consumer when the list is
// applied (see MemoryRevocationCache.UpdateFromList).
func VerifyRevocationList(list *RevocationList, issuerPub ed25519.PublicKey) error {
	if list.Typ != RevocationListTyp {
		return fmt.Errorf("adtp/revocation: %w: typ %q", ErrNotRevocationList, list.Typ)
	}
	if list.SchemaVersion != RevocationListSchemaVersion {
		return fmt.Errorf("adtp/revocation: %w: schema %q", ErrNotRevocationList, list.SchemaVersion)
	}
	sig, err := signing.DecodeSignature(list.Sig)
	if err != nil {
		return err
	}
	return signing.Verify(list, sig, issuerPub)
}

// Hash returns the hex SHA-256 of the list's canonical form, used as the prev
// link of the next list.
func (l *RevocationList) Hash() (string, error) {
	canonical, err := signing.CanonicalizeValue(l)
	if err != nil {
		return "", fmt.Errorf("adtp/revocation: hash list: %w", err)
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func listID(issuer string, seq int64) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", issuer, seq)))
	return "rl_" + hex.EncodeToString(sum[:12])
}
