package verify

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"github.com/adtp/adtp/internal/identity"
	"github.com/adtp/adtp/internal/signing"
)

// InvocationTyp is the typ tag of a UCANInvocation (SD-1).
const InvocationTyp = "aitp/inv/1"

const (
	// invocationLifetime is the maximum exp - iat for an invocation (Section 10).
	invocationLifetime = 300
	// invocationFreshness bounds how far in the past iat may be.
	invocationFreshness = 60
	// invocationClockSkew bounds how far in the future iat may be.
	invocationClockSkew = 60
)

// OnBehalfOf is the dual-principal authorization carried by an invocation made
// for a distinct principal (Section 10.1).
type OnBehalfOf struct {
	Principal        string `json:"principal"`
	AuthorizationCID string `json:"chain"`
	Scope            struct {
		Action   string `json:"action"`
		Resource string `json:"resource"`
	} `json:"scope"`
}

// InvocationRun is the action an invocation requests.
type InvocationRun struct {
	DelegationCID string         `json:"delegation"`
	Action        string         `json:"action"`
	Resource      string         `json:"resource"`
	Parameters    map[string]any `json:"parameters"`
}

// UCANInvocation is a channel-bound, signed proof-of-possession over a leaf
// credential (Section 10).
type UCANInvocation struct {
	Typ   string        `json:"typ"`
	Iss   string        `json:"iss"`
	Aud   string        `json:"aud"`
	Iat   int64         `json:"iat"`
	Exp   int64         `json:"exp"`
	Nonce string        `json:"nonce"`
	CB    string        `json:"cb,omitempty"`
	OBO   *OnBehalfOf   `json:"obo,omitempty"`
	Run   InvocationRun `json:"run"`
	Sig   string        `json:"sig"`
}

// NonceCache records spent invocation nonces to defeat replay (Section 10.5).
type NonceCache interface {
	// CheckAndStore atomically reports whether nonce was already present and
	// records it for ttl if not.
	CheckAndStore(nonce string, ttl time.Duration) (alreadySeen bool, err error)
	// InstanceID identifies this cache instance; a change signals a restart.
	InstanceID() string
}

// MemoryNonceCache is an in-memory, fail-closed NonceCache.
type MemoryNonceCache struct {
	m          sync.Map // nonce -> time.Time expiry
	instanceID string
}

// NewMemoryNonceCache returns a cache with a fresh 128-bit instance identifier.
func NewMemoryNonceCache() *MemoryNonceCache {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		// crypto/rand failure is fatal for a security component.
		panic("aitp/verify: cannot initialize nonce cache instance id: " + err.Error())
	}
	return &MemoryNonceCache{instanceID: base64.RawURLEncoding.EncodeToString(id)}
}

func (c *MemoryNonceCache) CheckAndStore(nonce string, ttl time.Duration) (bool, error) {
	expiry := time.Now().Add(ttl)
	prev, loaded := c.m.LoadOrStore(nonce, expiry)
	if loaded {
		if time.Now().Before(prev.(time.Time)) {
			return true, nil // still within its validity window: a replay
		}
		// The stored nonce had expired; refresh it and treat as fresh.
		c.m.Store(nonce, expiry)
	}
	return false, nil
}

func (c *MemoryNonceCache) InstanceID() string { return c.instanceID }

// CreateInvocation builds and signs an invocation over leafCID. The presenter's
// DID (iss) is derived from presenterKey and must equal the leaf credential's
// audience.
func CreateInvocation(leafCID, action, resource string, params map[string]any, presenterKey ed25519.PrivateKey, verifierDID, channelBinding string) (*UCANInvocation, error) {
	if len(presenterKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("aitp/verify: invalid presenter key")
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("aitp/verify: nonce: %w", err)
	}
	now := time.Now().Unix()
	inv := &UCANInvocation{
		Typ:   InvocationTyp,
		Iss:   identity.EncodeDID(presenterKey.Public().(ed25519.PublicKey)),
		Aud:   verifierDID,
		Iat:   now,
		Exp:   now + invocationLifetime,
		Nonce: base64.RawURLEncoding.EncodeToString(nonce),
		CB:    channelBinding,
		Run: InvocationRun{
			DelegationCID: leafCID,
			Action:        action,
			Resource:      resource,
			Parameters:    params,
		},
	}
	sig, err := signing.Sign(inv, presenterKey)
	if err != nil {
		return nil, fmt.Errorf("aitp/verify: sign invocation: %w", err)
	}
	inv.Sig = signing.EncodeSignature(sig)
	return inv, nil
}

// VerifyInvocation performs the proof-of-possession checks (Section 10, the core
// of verification step 10): correct typ, presenter equal to the leaf audience,
// correct verifier audience, temporal freshness, a valid signature under the
// presenter's key, and an unseen nonce. The nonce is consumed only after the
// signature verifies, so forged invocations cannot exhaust the cache.
func VerifyInvocation(inv *UCANInvocation, expectedAudDID, leafAudDID string, nonceCache NonceCache) error {
	if inv.Typ != InvocationTyp {
		return verr(10, CodePoPFailed, nil, "unexpected typ %q", inv.Typ)
	}
	// On-behalf-of (dual-principal) authorization is not yet enforced. Rather than
	// silently ignoring the field — which could mislead a caller into believing it
	// is honored — reject any invocation that carries it (fail closed).
	if inv.OBO != nil {
		return verr(10, CodePoPFailed, nil, "on_behalf_of validation not yet implemented — reject invocations carrying OBO until v1.0")
	}
	if inv.Iss != leafAudDID {
		return verr(10, CodePoPFailed, nil, "presenter %q is not the leaf audience %q", inv.Iss, leafAudDID)
	}
	if inv.Aud != expectedAudDID {
		return verr(10, CodePoPFailed, nil, "invocation audience %q is not this verifier %q", inv.Aud, expectedAudDID)
	}

	now := time.Now().Unix()
	if inv.Iat > now+invocationClockSkew {
		return verr(10, CodePoPFailed, nil, "iat %d is in the future", inv.Iat)
	}
	if now-inv.Iat > invocationFreshness {
		return verr(10, CodePoPFailed, nil, "iat %d is stale", inv.Iat)
	}
	if inv.Exp < now {
		return verr(10, CodePoPFailed, nil, "invocation expired at %d", inv.Exp)
	}
	if inv.Exp > inv.Iat+invocationLifetime {
		return verr(10, CodePoPFailed, nil, "exp %d exceeds iat+%d", inv.Exp, invocationLifetime)
	}

	pub, err := identity.ParseDID(inv.Iss)
	if err != nil {
		return verr(10, CodePoPFailed, err, "cannot resolve presenter DID %q", inv.Iss)
	}
	sig, err := signing.DecodeSignature(inv.Sig)
	if err != nil {
		return verr(10, CodePoPFailed, err, "signature decode")
	}
	if err := signing.Verify(inv, sig, pub); err != nil {
		return verr(10, CodePoPFailed, err, "invocation signature")
	}

	ttl := time.Duration(inv.Exp-now) * time.Second
	if ttl <= 0 {
		ttl = time.Second
	}
	seen, err := nonceCache.CheckAndStore(inv.Nonce, ttl)
	if err != nil {
		return verr(10, CodePoPFailed, err, "nonce cache")
	}
	if seen {
		return verr(10, CodePoPFailed, nil, "nonce replay")
	}
	return nil
}
