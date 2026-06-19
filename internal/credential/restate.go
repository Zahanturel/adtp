package credential

import (
	"crypto/ed25519"
	"fmt"
)

// CreateRestateHop issues a RESTATE delegation (Section 8.3): a child UCAN whose
// att is a restated subset of the parent's, linked by prf to the parent's CID
// and carrying an att_seal in its header. RESTATE is the v0.2-compatibility mode
// and is deprecated for new chains in favor of RESTRICT; its delegation
// integrity depends on capability_leq at verification.
//
// signerKey is the delegator's key — the holder of the parent credential's
// audience key — and must therefore correspond to parent.Aud. The returned
// token's iss is parent.Aud and its validity window is inherited from the
// parent (a hop never widens it).
func CreateRestateHop(parent *UCAN, childAud string, attSubset []Capability, signerKey ed25519.PrivateKey) (string, error) {
	if parent == nil {
		return "", fmt.Errorf("aitp/credential: %w: nil parent", ErrMissingField)
	}
	if len(signerKey) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("aitp/credential: %w", ErrInvalidKey)
	}
	if childAud == "" {
		return "", fmt.Errorf("aitp/credential: %w: audience", ErrMissingField)
	}
	if len(attSubset) == 0 {
		return "", fmt.Errorf("aitp/credential: %w: RESTATE hop must restate at least one capability", ErrMissingField)
	}
	for i, c := range attSubset {
		if err := c.Validate(); err != nil {
			return "", fmt.Errorf("aitp/credential: att[%d]: %w", i, err)
		}
	}

	parentCID := parent.CID()
	seal, err := CreateAttSeal(attSubset, childAud, parentCID, signerKey)
	if err != nil {
		return "", err
	}

	payload := UCANPayload{
		Iss: parent.Payload.Aud,
		Aud: childAud,
		Att: attSubset,
		Prf: []string{parentCID},
		Exp: parent.Payload.Exp,
		Nbf: parent.Payload.Nbf,
		Iat: parent.Payload.Iat,
	}
	header := UCANHeader{Typ: UCANTyp, Alg: UCANAlg, Ucv: UCANVersion, Seal: seal}
	return createUCAN(header, payload, signerKey)
}
