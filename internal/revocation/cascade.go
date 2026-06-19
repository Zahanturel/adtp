package revocation

import (
	"crypto/ed25519"
	"fmt"
	"sort"
	"sync"

	"github.com/adtp/adtp/internal/audit"
	"github.com/adtp/adtp/internal/identity"
)

// RegistrationIndex finds the credentials whose delegation chain contains a
// given CID — the chain_contains_cid relation that makes cascade complete
// (Section 13.6).
type RegistrationIndex interface {
	FindDescendants(cid string) ([]string, error)
}

// RevocationService accepts new revocation entries and reports per-subject
// sequence state.
type RevocationService interface {
	Revoke(entry RevocationEntry) error
	CurrentSeq(subject string) int64
}

// EmergencyChannel propagates high-urgency revocations out of band (Section
// 13.4). A nil channel disables emergency push.
type EmergencyChannel interface {
	Push(entries []RevocationEntry) error
}

// CascadeReport summarizes an executed cascade.
type CascadeReport struct {
	CompromisedCID  string
	PrimaryEntry    RevocationEntry
	CascadeEntries  []RevocationEntry
	DescendantCount int
}

// ExecuteCascade performs the explicit cascade for a compromised credential
// (Section 13.6): it posts the primary COMPROMISED entry, enumerates the
// credential's registered descendants, posts a CASCADE entry for each, pushes
// the batch to the emergency channel, and audits the event. The signer's DID is
// recorded as the platform authority.
func ExecuteCascade(
	compromisedCID string,
	registrationIndex RegistrationIndex,
	revocationService RevocationService,
	emergency EmergencyChannel,
	auditLog audit.AuditLog,
	signerKey ed25519.PrivateKey,
) (*CascadeReport, error) {
	if len(signerKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("aitp/revocation: %w", ErrInvalidKey)
	}
	authorityDID := identity.EncodeDID(signerKey.Public().(ed25519.PublicKey))
	auth := RevocationAuth{DID: authorityDID, Basis: AuthPlatform, Proof: compromisedCID}

	// 1. Primary COMPROMISED entry (subtree scope triggers the cascade).
	primary, err := CreateRevocationEntry(
		RevocationSubject{CID: compromisedCID}, ScopeSubtree, StatusCompromised,
		auth, revocationService.CurrentSeq(compromisedCID)+1, "", signerKey)
	if err != nil {
		return nil, err
	}
	if err := revocationService.Revoke(*primary); err != nil {
		return nil, err
	}
	if err := appendAudit(auditLog, audit.EventRevocationPosted, compromisedCID, map[string]any{
		"status": string(StatusCompromised), "scope": string(ScopeSubtree),
	}); err != nil {
		return nil, err
	}

	// 2. Enumerate descendants.
	descendants, err := registrationIndex.FindDescendants(compromisedCID)
	if err != nil {
		return nil, fmt.Errorf("aitp/revocation: find descendants: %w", err)
	}

	// 3. CASCADE entry per descendant (Authority.Proof links to the origin).
	cascadeEntries := make([]RevocationEntry, 0, len(descendants))
	for _, d := range descendants {
		entry, err := CreateRevocationEntry(
			RevocationSubject{CID: d}, ScopeCredential, StatusCascade,
			auth, revocationService.CurrentSeq(d)+1, "", signerKey)
		if err != nil {
			return nil, err
		}
		if err := revocationService.Revoke(*entry); err != nil {
			return nil, err
		}
		cascadeEntries = append(cascadeEntries, *entry)
	}

	// 4. Emergency push.
	if emergency != nil {
		batch := append([]RevocationEntry{*primary}, cascadeEntries...)
		if err := emergency.Push(batch); err != nil {
			return nil, fmt.Errorf("aitp/revocation: emergency push: %w", err)
		}
	}

	// 5. Audit the cascade.
	if err := appendAudit(auditLog, audit.EventCompromiseCascade, compromisedCID, map[string]any{
		"compromised": compromisedCID, "descendants": len(descendants),
	}); err != nil {
		return nil, err
	}

	return &CascadeReport{
		CompromisedCID:  compromisedCID,
		PrimaryEntry:    *primary,
		CascadeEntries:  cascadeEntries,
		DescendantCount: len(descendants),
	}, nil
}

func appendAudit(log audit.AuditLog, eventType, credCID string, payload map[string]any) error {
	if log == nil {
		return nil
	}
	return log.Append(audit.AuditEntry{EventType: eventType, CredCID: credCID, Payload: payload})
}

// MemoryRegistrationIndex maps each chain CID to the credentials whose chain
// contains it.
type MemoryRegistrationIndex struct {
	mu    sync.RWMutex
	index map[string]map[string]struct{}
}

// NewMemoryRegistrationIndex returns an empty index.
func NewMemoryRegistrationIndex() *MemoryRegistrationIndex {
	return &MemoryRegistrationIndex{index: make(map[string]map[string]struct{})}
}

// Register records that credentialCID's chain contains each of chainCIDs. The
// in-memory index never fails; the error return matches the RegistrationStore
// contract that durable backends need.
func (r *MemoryRegistrationIndex) Register(credentialCID string, chainCIDs []string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range chainCIDs {
		if r.index[c] == nil {
			r.index[c] = make(map[string]struct{})
		}
		r.index[c][credentialCID] = struct{}{}
	}
	return nil
}

// FindDescendants returns the credentials whose chain contains cid, excluding
// cid itself, in deterministic order.
func (r *MemoryRegistrationIndex) FindDescendants(cid string) ([]string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []string
	for c := range r.index[cid] {
		if c != cid {
			out = append(out, c)
		}
	}
	sort.Strings(out)
	return out, nil
}

// MemoryEmergencyChannel records pushed batches for inspection.
type MemoryEmergencyChannel struct {
	mu      sync.Mutex
	Batches [][]RevocationEntry
}

// Push records a batch.
func (c *MemoryEmergencyChannel) Push(entries []RevocationEntry) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Batches = append(c.Batches, entries)
	return nil
}
