package credential

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/adtp/adtp/internal/signing"
)

// RestrictBlockTyp is the typ tag of a RESTRICT attenuation block (SD-1).
const RestrictBlockTyp = "aitp/cav/1"

// MaxCaveatsPerBlock bounds the caveat list of a single block (Section 7.9).
const MaxCaveatsPerBlock = 50

// Caveat type discriminators introduced for RESTRICT blocks, in addition to the
// constraint types shared with capabilities (time_window, budget, param_limit).
const (
	ConstraintResourceRestrict ConstraintType = "resource_restrict"
	ConstraintMethodRestrict   ConstraintType = "method_restrict"
	ConstraintMaxCalls         ConstraintType = "max_calls"
	ConstraintDelegationDepth  ConstraintType = "delegation_depth"
)

// Caveat is a restriction carried in a RESTRICT block. Caveats and capability
// constraints share one type system; see Constraint.
type Caveat = Constraint

// RESTRICT errors.
var (
	ErrNotRestrictBlock    = errors.New("not a RESTRICT block")
	ErrNoCaveats           = errors.New("RESTRICT block must carry at least one caveat")
	ErrTooManyCaveats      = errors.New("RESTRICT block exceeds the caveat limit")
	ErrDepthNotReduced     = errors.New("delegation depth-left was not strictly reduced")
	ErrExpiryEscalation    = errors.New("child exp exceeds parent exp")
	ErrNotBeforeRegression = errors.New("child nbf precedes parent nbf")
	ErrIssuerMismatch      = errors.New("block issuer does not equal parent audience")
)

// RestrictBlock is a signed, restriction-only delegation object (Section 8.2).
// It adds caveats to a parent credential without restating the capability set,
// which is what makes RESTRICT structurally escalation-free: there is no
// capability comparison anywhere in its verification.
type RestrictBlock struct {
	Typ  string      `json:"typ"`
	Iss  string      `json:"iss"`
	Aud  string      `json:"aud"`
	Prf  string      `json:"prf"`
	Nbf  int64       `json:"nbf"`
	Exp  int64       `json:"exp"`
	DL   int         `json:"dl"`
	Cav  Constraints `json:"cav"`
	Crit []string    `json:"crit,omitempty"`
	Sig  string      `json:"sig"`
}

// DelegationParent captures the parent fields a delegation reads: the parent's
// CID (becomes the child's prf), its audience (becomes the child's iss), its
// validity window, and its delegation depth-left.
type DelegationParent struct {
	CID string
	Aud string
	Exp int64
	Nbf int64
	DL  int
}

// CreateRestrictBlock builds and signs a RESTRICT block delegating from parent
// to audDID with the given caveats. The child inherits the parent's validity
// window (a hop never widens it) and carries depth-left childDL, which must be
// strictly below the parent's. It returns the block and its canonical bytes (the
// JCS form including the signature, over which the CID is computed per SD-5).
func CreateRestrictBlock(parent DelegationParent, audDID string, childDL int, caveats Constraints, signerKey ed25519.PrivateKey) (*RestrictBlock, []byte, error) {
	if len(signerKey) != ed25519.PrivateKeySize {
		return nil, nil, fmt.Errorf("aitp/credential: %w", ErrInvalidKey)
	}
	if parent.CID == "" || parent.Aud == "" {
		return nil, nil, fmt.Errorf("aitp/credential: %w: parent CID and audience", ErrMissingField)
	}
	if audDID == "" {
		return nil, nil, fmt.Errorf("aitp/credential: %w: audience", ErrMissingField)
	}
	if len(caveats) == 0 {
		return nil, nil, fmt.Errorf("aitp/credential: %w", ErrNoCaveats)
	}
	if len(caveats) > MaxCaveatsPerBlock {
		return nil, nil, fmt.Errorf("aitp/credential: %w: %d > %d", ErrTooManyCaveats, len(caveats), MaxCaveatsPerBlock)
	}
	if childDL >= parent.DL {
		return nil, nil, fmt.Errorf("aitp/credential: %w: child dl %d not below parent dl %d", ErrDepthNotReduced, childDL, parent.DL)
	}
	if childDL < 0 {
		return nil, nil, fmt.Errorf("aitp/credential: %w: negative dl", ErrDepthNotReduced)
	}
	for i, c := range caveats {
		if c == nil {
			return nil, nil, fmt.Errorf("aitp/credential: %w: nil caveat at %d", ErrInvalidConstraint, i)
		}
		if err := c.Validate(); err != nil {
			return nil, nil, fmt.Errorf("aitp/credential: caveat %d (%s): %w", i, c.Kind(), err)
		}
	}

	block := &RestrictBlock{
		Typ: RestrictBlockTyp,
		Iss: parent.Aud,
		Aud: audDID,
		Prf: parent.CID,
		Nbf: parent.Nbf,
		Exp: parent.Exp,
		DL:  childDL,
		Cav: caveats,
	}

	sig, err := signing.Sign(block, signerKey)
	if err != nil {
		return nil, nil, fmt.Errorf("aitp/credential: sign block: %w", err)
	}
	block.Sig = signing.EncodeSignature(sig)

	raw, err := signing.CanonicalizeValue(block)
	if err != nil {
		return nil, nil, fmt.Errorf("aitp/credential: canonicalize block: %w", err)
	}
	return block, raw, nil
}

// ParseRestrictBlock decodes and structurally validates a RESTRICT block. It
// enforces the I-JSON profile (SD-3) and the typ tag but does not verify the
// signature; use Verify for that.
func ParseRestrictBlock(raw []byte) (*RestrictBlock, error) {
	if err := signing.ValidateIJSON(raw); err != nil {
		return nil, fmt.Errorf("aitp/credential: %w: %v", ErrNotRestrictBlock, err)
	}
	var block RestrictBlock
	if err := json.Unmarshal(raw, &block); err != nil {
		return nil, fmt.Errorf("aitp/credential: %w: %v", ErrNotRestrictBlock, err)
	}
	if block.Typ != RestrictBlockTyp {
		return nil, fmt.Errorf("aitp/credential: %w: typ %q", ErrNotRestrictBlock, block.Typ)
	}
	if block.Iss == "" || block.Aud == "" || block.Prf == "" {
		return nil, fmt.Errorf("aitp/credential: %w: iss, aud, and prf are required", ErrMissingField)
	}
	if block.Sig == "" {
		return nil, fmt.Errorf("aitp/credential: %w: sig", ErrMissingField)
	}
	return &block, nil
}

// Verify checks the block's SD-2 signature against pub (the issuer's key).
func (b *RestrictBlock) Verify(pub ed25519.PublicKey) error {
	sig, err := signing.DecodeSignature(b.Sig)
	if err != nil {
		return err
	}
	return signing.Verify(b, sig, pub)
}

// CanonicalBytes returns the JCS serialization of the block including its
// signature — the bytes over which the CID is computed (SD-5).
func (b *RestrictBlock) CanonicalBytes() ([]byte, error) {
	return signing.CanonicalizeValue(b)
}

// CID returns the block's content identifier.
func (b *RestrictBlock) CID() (string, error) {
	raw, err := b.CanonicalBytes()
	if err != nil {
		return "", err
	}
	return ComputeCID(raw), nil
}

// ValidateAgainstParent enforces the linkage rules a block must satisfy relative
// to its parent (Section 8.2): the issuer equals the parent's audience, the
// validity window does not widen, depth-left strictly decreases, and at least
// one caveat is present.
func (b *RestrictBlock) ValidateAgainstParent(parent DelegationParent) error {
	if b.Iss != parent.Aud {
		return fmt.Errorf("aitp/credential: %w: iss %q, parent aud %q", ErrIssuerMismatch, b.Iss, parent.Aud)
	}
	if b.Prf != parent.CID {
		return fmt.Errorf("aitp/credential: %w: prf %q, parent CID %q", ErrNotRestrictBlock, b.Prf, parent.CID)
	}
	if b.Exp > parent.Exp {
		return fmt.Errorf("aitp/credential: %w: %d > %d", ErrExpiryEscalation, b.Exp, parent.Exp)
	}
	if b.Nbf < parent.Nbf {
		return fmt.Errorf("aitp/credential: %w: %d < %d", ErrNotBeforeRegression, b.Nbf, parent.Nbf)
	}
	if b.DL >= parent.DL {
		return fmt.Errorf("aitp/credential: %w: %d not below %d", ErrDepthNotReduced, b.DL, parent.DL)
	}
	if len(b.Cav) == 0 {
		return fmt.Errorf("aitp/credential: %w", ErrNoCaveats)
	}
	return nil
}

// ResourceRestrictConstraint narrows the resource URI a capability may target.
// At invocation it requires the requested resource to be covered by Resource.
type ResourceRestrictConstraint struct {
	Type     ConstraintType `json:"type"`
	Resource string         `json:"resource"`
}

func (c ResourceRestrictConstraint) Kind() string { return string(ConstraintResourceRestrict) }

func (c ResourceRestrictConstraint) Validate() error {
	if c.Type != ConstraintResourceRestrict {
		return fmt.Errorf("%w: resource_restrict has type %q", ErrInvalidConstraint, c.Type)
	}
	canonical, err := CanonicalizeURI(c.Resource)
	if err != nil {
		return fmt.Errorf("%w: resource_restrict resource: %v", ErrInvalidConstraint, err)
	}
	if canonical != c.Resource {
		return fmt.Errorf("%w: resource_restrict resource is not canonical", ErrInvalidConstraint)
	}
	return nil
}

// MethodRestrictConstraint restricts the allowed methods or operations.
type MethodRestrictConstraint struct {
	Type    ConstraintType `json:"type"`
	Methods []string       `json:"methods"`
}

func (c MethodRestrictConstraint) Kind() string { return string(ConstraintMethodRestrict) }

func (c MethodRestrictConstraint) Validate() error {
	if c.Type != ConstraintMethodRestrict {
		return fmt.Errorf("%w: method_restrict has type %q", ErrInvalidConstraint, c.Type)
	}
	if len(c.Methods) == 0 {
		return fmt.Errorf("%w: method_restrict requires at least one method", ErrInvalidConstraint)
	}
	return nil
}

// MaxCallsConstraint rate-limits invocations. A nil Window means the credential
// lifetime. Enforcement is cumulative and performed by the metering layer; at
// verification time it is satisfied structurally.
type MaxCallsConstraint struct {
	Type   ConstraintType `json:"type"`
	Limit  int64          `json:"limit"`
	Window *TimeWindow    `json:"window"`
}

func (c MaxCallsConstraint) Kind() string { return string(ConstraintMaxCalls) }

func (c MaxCallsConstraint) Validate() error {
	if c.Type != ConstraintMaxCalls {
		return fmt.Errorf("%w: max_calls has type %q", ErrInvalidConstraint, c.Type)
	}
	if c.Limit < 0 {
		return fmt.Errorf("%w: max_calls limit must be non-negative", ErrInvalidConstraint)
	}
	if c.Window != nil {
		return c.Window.Validate()
	}
	return nil
}

// DelegationDepthConstraint bounds further delegation. On a root credential's
// agent/delegate capability it sets the initial depth-left (Section 8.1).
type DelegationDepthConstraint struct {
	Type ConstraintType `json:"type"`
	Max  int            `json:"max"`
}

func (c DelegationDepthConstraint) Kind() string { return string(ConstraintDelegationDepth) }

func (c DelegationDepthConstraint) Validate() error {
	if c.Type != ConstraintDelegationDepth {
		return fmt.Errorf("%w: delegation_depth has type %q", ErrInvalidConstraint, c.Type)
	}
	if c.Max < 0 {
		return fmt.Errorf("%w: delegation_depth max must be non-negative", ErrInvalidConstraint)
	}
	return nil
}
