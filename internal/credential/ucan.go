package credential

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/Zahanturel/adtp/internal/signing"
)

// UCAN header constants. JWT credentials retain JWS compact form for ecosystem
// compatibility; the header carries the ADTP typ and version (specification
// SD-4, Section 8.1).
const (
	UCANTyp     = "adtp/ucan/1"
	UCANAlg     = "EdDSA"
	UCANVersion = "0.1.0"

	// MaxCapabilities is the per-token cap on the att array (Section 7.9).
	MaxCapabilities = 100
)

// supportedUCANVersions enumerates the ucv values this implementation accepts.
var supportedUCANVersions = map[string]struct{}{
	UCANVersion: {},
}

// UCAN errors.
var (
	ErrMalformedToken        = errors.New("malformed UCAN token")
	ErrUnsupportedHeader     = errors.New("unsupported UCAN header")
	ErrMissingExpiry         = errors.New("UCAN is missing the mandatory exp claim")
	ErrTooManyCapabilities   = errors.New("UCAN att exceeds the capability limit")
	ErrMissingField          = errors.New("UCAN is missing a required field")
	ErrInvalidExpiry         = errors.New("UCAN has an invalid validity window")
	ErrInvalidKey            = errors.New("invalid ed25519 key")
	ErrSignatureVerification = errors.New("UCAN signature verification failed")
)

// UCANHeader is the JWS header of an ADTP UCAN. A RESTATE hop additionally
// carries its att_seal here (Section 9); root credentials omit it.
type UCANHeader struct {
	Typ  string   `json:"typ"`
	Alg  string   `json:"alg"`
	Ucv  string   `json:"ucv"`
	Seal *AttSeal `json:"seal,omitempty"`
}

// UCANPayload is the claim set of an ADTP UCAN. All timestamps are integer UNIX
// seconds. For a root credential prf is the empty array.
type UCANPayload struct {
	Iss string       `json:"iss"`
	Aud string       `json:"aud"`
	Att []Capability `json:"att"`
	Prf []string     `json:"prf"`
	Exp int64        `json:"exp"`
	Nbf int64        `json:"nbf"`
	Iat int64        `json:"iat"`
}

// UCAN is a parsed, structurally valid UCAN. Its signature has not necessarily
// been verified; call Verify with the issuer's public key.
type UCAN struct {
	Header    UCANHeader
	Payload   UCANPayload
	Signature []byte

	// signingInput is the exact received "base64url(header).base64url(payload)"
	// byte sequence, retained so verification operates over the bytes that were
	// signed rather than a re-encoding (SD-6).
	signingInput []byte
	// raw is the complete compact token, over which the CID is computed (SD-5).
	raw string
}

// CreateUCAN builds, canonicalizes, signs, and serializes a UCAN as a JWS
// compact token. The header and payload are serialized through JCS, so the
// token — and therefore its CID — is a deterministic function of the claims.
func CreateUCAN(payload UCANPayload, priv ed25519.PrivateKey) (string, error) {
	return createUCAN(UCANHeader{Typ: UCANTyp, Alg: UCANAlg, Ucv: UCANVersion}, payload, priv)
}

// createUCAN serializes, signs, and assembles a UCAN with the given header. The
// header and payload are canonicalized through JCS so the token is a
// deterministic function of its contents.
func createUCAN(header UCANHeader, payload UCANPayload, priv ed25519.PrivateKey) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("adtp/credential: %w: private key length %d, want %d",
			ErrInvalidKey, len(priv), ed25519.PrivateKeySize)
	}
	if err := payload.validateForIssuance(); err != nil {
		return "", err
	}

	// Normalize optional collections so they serialize as arrays, never null.
	if payload.Att == nil {
		payload.Att = []Capability{}
	}
	if payload.Prf == nil {
		payload.Prf = []string{}
	}

	headerJCS, err := signing.CanonicalizeValue(header)
	if err != nil {
		return "", fmt.Errorf("adtp/credential: canonicalize header: %w", err)
	}
	payloadJCS, err := signing.CanonicalizeValue(payload)
	if err != nil {
		return "", fmt.Errorf("adtp/credential: canonicalize payload: %w", err)
	}

	signingInput := b64.EncodeToString(headerJCS) + "." + b64.EncodeToString(payloadJCS)
	sig := ed25519.Sign(priv, []byte(signingInput))
	return signingInput + "." + b64.EncodeToString(sig), nil
}

// ParseUCAN decodes and structurally validates a compact UCAN token. It checks
// the JWS structure, header typ/alg/ucv, the mandatory exp claim, the
// capability limit, and the signature length, but does not verify the
// signature; call Verify for that.
func ParseUCAN(token string) (*UCAN, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("adtp/credential: %w: expected 3 dot-separated segments", ErrMalformedToken)
	}

	headerBytes, err := b64.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("adtp/credential: %w: header is not base64url: %v", ErrMalformedToken, err)
	}
	payloadBytes, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("adtp/credential: %w: payload is not base64url: %v", ErrMalformedToken, err)
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("adtp/credential: %w: signature is not base64url: %v", ErrMalformedToken, err)
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("adtp/credential: %w: signature length %d, want %d",
			ErrMalformedToken, len(sig), ed25519.SignatureSize)
	}

	// Enforce the I-JSON profile (no duplicate keys, integers only) on both
	// segments before decoding into typed structures.
	if err := signing.ValidateIJSON(headerBytes); err != nil {
		return nil, fmt.Errorf("adtp/credential: %w: header: %v", ErrMalformedToken, err)
	}
	if err := signing.ValidateIJSON(payloadBytes); err != nil {
		return nil, fmt.Errorf("adtp/credential: %w: payload: %v", ErrMalformedToken, err)
	}

	var header UCANHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("adtp/credential: %w: header: %v", ErrMalformedToken, err)
	}
	if header.Typ != UCANTyp {
		return nil, fmt.Errorf("adtp/credential: %w: typ %q, want %q", ErrUnsupportedHeader, header.Typ, UCANTyp)
	}
	if header.Alg != UCANAlg {
		return nil, fmt.Errorf("adtp/credential: %w: alg %q, want %q", ErrUnsupportedHeader, header.Alg, UCANAlg)
	}
	if _, ok := supportedUCANVersions[header.Ucv]; !ok {
		return nil, fmt.Errorf("adtp/credential: %w: unsupported ucv %q", ErrUnsupportedHeader, header.Ucv)
	}

	// exp is mandatory; detect its presence (a zero value is not absence).
	var present map[string]json.RawMessage
	if err := json.Unmarshal(payloadBytes, &present); err != nil {
		return nil, fmt.Errorf("adtp/credential: %w: payload: %v", ErrMalformedToken, err)
	}
	if _, ok := present["exp"]; !ok {
		return nil, fmt.Errorf("adtp/credential: %w", ErrMissingExpiry)
	}

	var payload UCANPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("adtp/credential: %w: payload: %v", ErrMalformedToken, err)
	}
	if len(payload.Att) > MaxCapabilities {
		return nil, fmt.Errorf("adtp/credential: %w: %d > %d", ErrTooManyCapabilities, len(payload.Att), MaxCapabilities)
	}

	return &UCAN{
		Header:       header,
		Payload:      payload,
		Signature:    sig,
		signingInput: []byte(parts[0] + "." + parts[1]),
		raw:          token,
	}, nil
}

// Verify checks the UCAN's Ed25519 signature against pub over the exact received
// signing input (SD-6).
func (u *UCAN) Verify(pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("adtp/credential: %w: public key length %d, want %d",
			ErrInvalidKey, len(pub), ed25519.PublicKeySize)
	}
	if !ed25519.Verify(pub, u.signingInput, u.Signature) {
		return ErrSignatureVerification
	}
	return nil
}

// CID returns the credential's content identifier, computed over the complete
// compact token bytes (SD-5).
func (u *UCAN) CID() string {
	return ComputeCID([]byte(u.raw))
}

// String returns the compact token.
func (u *UCAN) String() string {
	return u.raw
}

// b64 is the JWS base64url encoding: URL-safe alphabet, no padding.
var b64 = base64.RawURLEncoding

func (p UCANPayload) validateForIssuance() error {
	if p.Iss == "" {
		return fmt.Errorf("adtp/credential: %w: iss", ErrMissingField)
	}
	if p.Aud == "" {
		return fmt.Errorf("adtp/credential: %w: aud", ErrMissingField)
	}
	if p.Exp <= 0 {
		return fmt.Errorf("adtp/credential: %w: exp must be a positive timestamp", ErrMissingExpiry)
	}
	if p.Nbf < 0 || p.Iat < 0 {
		return fmt.Errorf("adtp/credential: %w: nbf and iat must be non-negative", ErrInvalidExpiry)
	}
	if p.Nbf > 0 && p.Exp <= p.Nbf {
		return fmt.Errorf("adtp/credential: %w: exp (%d) must be after nbf (%d)", ErrInvalidExpiry, p.Exp, p.Nbf)
	}
	if len(p.Att) > MaxCapabilities {
		return fmt.Errorf("adtp/credential: %w: %d > %d", ErrTooManyCapabilities, len(p.Att), MaxCapabilities)
	}
	for i, c := range p.Att {
		if err := c.Validate(); err != nil {
			return fmt.Errorf("adtp/credential: att[%d]: %w", i, err)
		}
	}
	return nil
}
