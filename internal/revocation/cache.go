package revocation

import (
	"crypto/ed25519"
	"fmt"
	"sync"
)

// MemoryRevocationCache holds the latest revocation entry per subject and the
// highest list sequence seen. It satisfies the verifier's revocation-lookup
// interface via GetStatus.
type MemoryRevocationCache struct {
	mu      sync.RWMutex
	entries map[string]RevocationEntry // subject key -> latest entry
	listSeq int64
}

// NewMemoryRevocationCache returns an empty cache.
func NewMemoryRevocationCache() *MemoryRevocationCache {
	return &MemoryRevocationCache{entries: make(map[string]RevocationEntry)}
}

// GetStatus returns the latest revocation entry for a subject (a credential CID
// or principal DID), or nil if the subject is not currently revoked. A latest
// status of REINSTATED reports the subject as active.
func (c *MemoryRevocationCache) GetStatus(subject string) (*RevocationEntry, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[subject]
	if !ok || e.Status == StatusReinstated {
		return nil, nil
	}
	out := e
	return &out, nil
}

// Revoke applies a single entry, rejecting an entry that is not validly signed by
// the authority it names, an entry with no subject, and a per-subject sequence
// rollback.
func (c *MemoryRevocationCache) Revoke(entry RevocationEntry) error {
	key := entry.Subject.Key()
	if key == "" {
		return fmt.Errorf("aitp/revocation: %w", ErrMissingSubject)
	}
	if err := VerifyEntrySelfSignature(&entry); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if existing, ok := c.entries[key]; ok && entry.Seq <= existing.Seq {
		return fmt.Errorf("aitp/revocation: %w: seq %d <= %d for %s", ErrSequenceRollback, entry.Seq, existing.Seq, key)
	}
	c.entries[key] = entry
	return nil
}

// UpdateFromList applies every entry in a signed list. The list's signature is
// verified under issuerPub before anything is applied, so a forged or tampered
// list (including one injecting a spurious REINSTATED) is rejected outright. The
// list sequence must exceed the highest previously applied; per-subject, the
// highest-seq entry wins and older entries within an accepted list are silently
// superseded.
func (c *MemoryRevocationCache) UpdateFromList(list *RevocationList, issuerPub ed25519.PublicKey) error {
	if err := VerifyRevocationList(list, issuerPub); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if list.Sequence <= c.listSeq {
		return fmt.Errorf("aitp/revocation: %w: list seq %d <= cached %d", ErrSequenceRollback, list.Sequence, c.listSeq)
	}
	for i := range list.Entries {
		e := list.Entries[i]
		key := e.Subject.Key()
		if key == "" {
			continue
		}
		if existing, ok := c.entries[key]; ok && e.Seq <= existing.Seq {
			continue
		}
		c.entries[key] = e
	}
	c.listSeq = list.Sequence
	return nil
}

// Entries returns a snapshot of the latest entry per subject, for building a
// revocation list.
func (c *MemoryRevocationCache) Entries() []RevocationEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]RevocationEntry, 0, len(c.entries))
	for _, e := range c.entries {
		out = append(out, e)
	}
	return out
}

// CurrentSeq returns the highest sequence number recorded for a subject, or 0.
func (c *MemoryRevocationCache) CurrentSeq(subject string) int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if e, ok := c.entries[subject]; ok {
		return e.Seq
	}
	return 0
}
