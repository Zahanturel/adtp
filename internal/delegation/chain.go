// Package delegation builds and issues ADTP delegation chains: walking prf
// links from a leaf to its root, and minting RESTRICT blocks and RESTATE hops.
package delegation

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/Zahanturel/adtp/internal/credential"
)

// Chain construction limits (specification Sections 8, 7.9, 11).
const (
	// DefaultMaxDepth is the default cap on delegation hops.
	DefaultMaxDepth = 10
	// HardMaxDepth is the absolute cap, enforced regardless of policy.
	HardMaxDepth = 100
	// MaxChainCapsCaveats caps capabilities plus caveats across the whole chain.
	MaxChainCapsCaveats = 1000
)

// Delegation modes.
const (
	ModeRoot     = "root"
	ModeRestrict = "restrict"
	ModeRestate  = "restate"
)

// Chain-building errors. The verify package maps these to the AGENT_ERR_V_*
// taxonomy; keeping them as sentinels here decouples chain construction from
// verification.
var (
	ErrProofNotFound        = errors.New("referenced credential not found in proof store")
	ErrCIDMismatch          = errors.New("stored bytes do not match their CID")
	ErrCircularChain        = errors.New("circular delegation: CID seen twice")
	ErrChainTooDeep         = errors.New("delegation chain exceeds maximum depth")
	ErrChainTooWide         = errors.New("delegation chain exceeds capability+caveat limit")
	ErrChainBroken          = errors.New("delegation chain is broken or malformed")
	ErrBranchingUnsupported = errors.New("multi-proof (branching) chains are unsupported")
	ErrModeMixing           = errors.New("RESTATE after RESTRICT is prohibited")
)

// ProofStore resolves a credential or block by its CID. Bytes returned are the
// exact serialized form the CID was computed over (JWS compact for UCANs, JCS
// for blocks).
type ProofStore interface {
	Get(ctx context.Context, cid string) ([]byte, error)
}

// ChainElement is one credential in a chain. Exactly one of Token or Block is
// non-nil.
type ChainElement struct {
	Token  *credential.UCAN
	Block  *credential.RestrictBlock
	CID    string
	IsRoot bool
	Mode   string
}

// Chain is an ordered delegation chain: Elements[0] is the leaf and the last
// element is the root. Depth is the number of delegation hops (len-1).
type Chain struct {
	Elements []ChainElement
	Depth    int
}

// Leaf returns the leaf element (the credential being exercised).
func (c *Chain) Leaf() ChainElement { return c.Elements[0] }

// Root returns the root element (the platform-issued credential).
func (c *Chain) Root() ChainElement { return c.Elements[len(c.Elements)-1] }

// BuildChain resolves and assembles the chain rooted at leafCID by walking prf
// links. It rejects cycles (before any signature work), over-deep and over-wide
// chains, branching, CID-mismatched proofs, and illegal mode mixing. It does not
// verify signatures or temporal validity; those are later verification steps.
func BuildChain(ctx context.Context, leafCID string, store ProofStore, maxDepth int) (*Chain, error) {
	if maxDepth <= 0 {
		maxDepth = DefaultMaxDepth
	}
	if maxDepth > HardMaxDepth {
		maxDepth = HardMaxDepth
	}

	seen := make(map[string]struct{})
	var elements []ChainElement
	totalCapsCaveats := 0

	cid := leafCID
	for {
		if cid == "" {
			return nil, fmt.Errorf("adtp/delegation: %w: empty CID reference", ErrChainBroken)
		}
		if _, dup := seen[cid]; dup {
			return nil, fmt.Errorf("adtp/delegation: %w: %s", ErrCircularChain, cid)
		}
		seen[cid] = struct{}{}

		raw, err := store.Get(ctx, cid)
		if err != nil {
			return nil, fmt.Errorf("adtp/delegation: %w: %s: %v", ErrProofNotFound, cid, err)
		}

		// SD-5 / Section 10.2: the verifier MUST verify the CID over the fetched
		// bytes. Without this the chain would trust the store's key->content
		// mapping; a poisoned cache or dishonest CAS could substitute a different
		// (but validly signed) credential under the requested CID.
		if !credential.VerifyCID(raw, cid) {
			return nil, fmt.Errorf("adtp/delegation: %w: %s", ErrCIDMismatch, cid)
		}

		elem, parentCID, weight, err := parseElement(raw, cid)
		if err != nil {
			return nil, err
		}
		elements = append(elements, elem)

		totalCapsCaveats += weight
		if totalCapsCaveats > MaxChainCapsCaveats {
			return nil, fmt.Errorf("adtp/delegation: %w: %d", ErrChainTooWide, totalCapsCaveats)
		}
		if len(elements)-1 > maxDepth {
			return nil, fmt.Errorf("adtp/delegation: %w: %d > %d", ErrChainTooDeep, len(elements)-1, maxDepth)
		}

		if elem.IsRoot {
			break
		}
		cid = parentCID
	}

	if err := checkModeMixing(elements); err != nil {
		return nil, err
	}
	return &Chain{Elements: elements, Depth: len(elements) - 1}, nil
}

// parseElement decodes one stored credential, returning its chain element, the
// CID of its parent ("" for a root), and its capability+caveat weight.
func parseElement(raw []byte, cid string) (ChainElement, string, int, error) {
	if trimmed := bytes.TrimSpace(raw); len(trimmed) > 0 && trimmed[0] == '{' {
		block, err := credential.ParseRestrictBlock(raw)
		if err != nil {
			return ChainElement{}, "", 0, fmt.Errorf("adtp/delegation: %w: %v", ErrChainBroken, err)
		}
		return ChainElement{Block: block, CID: cid, Mode: ModeRestrict}, block.Prf, len(block.Cav), nil
	}

	token, err := credential.ParseUCAN(string(raw))
	if err != nil {
		return ChainElement{}, "", 0, fmt.Errorf("adtp/delegation: %w: %v", ErrChainBroken, err)
	}
	weight := len(token.Payload.Att)
	for _, c := range token.Payload.Att {
		weight += len(c.Constraints)
	}

	switch len(token.Payload.Prf) {
	case 0:
		return ChainElement{Token: token, CID: cid, IsRoot: true, Mode: ModeRoot}, "", weight, nil
	case 1:
		return ChainElement{Token: token, CID: cid, Mode: ModeRestate}, token.Payload.Prf[0], weight, nil
	default:
		return ChainElement{}, "", 0, fmt.Errorf("adtp/delegation: %w: %d proofs", ErrBranchingUnsupported, len(token.Payload.Prf))
	}
}

// checkModeMixing enforces Section 8.4: walking in delegation order (root to
// leaf), once a RESTRICT hop appears no later hop may be RESTATE.
func checkModeMixing(elements []ChainElement) error {
	restrictSeen := false
	for i := len(elements) - 1; i >= 0; i-- {
		switch elements[i].Mode {
		case ModeRestrict:
			restrictSeen = true
		case ModeRestate:
			if restrictSeen {
				return fmt.Errorf("adtp/delegation: %w", ErrModeMixing)
			}
		}
	}
	return nil
}

// MemoryProofStore is an in-memory, concurrency-safe ProofStore.
type MemoryProofStore struct {
	mu sync.RWMutex
	m  map[string][]byte
}

// NewMemoryProofStore returns an empty store.
func NewMemoryProofStore() *MemoryProofStore {
	return &MemoryProofStore{m: make(map[string][]byte)}
}

// Put stores raw under its CID and returns that CID.
func (s *MemoryProofStore) Put(raw []byte) string {
	cid := credential.ComputeCID(raw)
	owned := bytes.Clone(raw)
	s.mu.Lock()
	s.m[cid] = owned
	s.mu.Unlock()
	return cid
}

// PutVerified stores raw only if it hashes to claimedCID — the check required
// when populating the store from untrusted sources (SD-5, cache-poisoning
// defense). It returns ErrCIDMismatch on a mismatch.
func (s *MemoryProofStore) PutVerified(raw []byte, claimedCID string) error {
	if credential.ComputeCID(raw) != claimedCID {
		return fmt.Errorf("adtp/delegation: %w: %s", ErrCIDMismatch, claimedCID)
	}
	s.Put(raw)
	return nil
}

// Get returns the bytes stored under cid, or ErrProofNotFound.
func (s *MemoryProofStore) Get(_ context.Context, cid string) ([]byte, error) {
	s.mu.RLock()
	raw, ok := s.m[cid]
	s.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("adtp/delegation: %w: %s", ErrProofNotFound, cid)
	}
	return bytes.Clone(raw), nil
}
