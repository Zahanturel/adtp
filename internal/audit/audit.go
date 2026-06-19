// Package audit implements the hash-linked audit log (specification Section 14):
// an append-only sequence of entries chained by SHA-256 so that any truncation
// or modification of history is detectable.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/adtp/adtp/internal/signing"
)

// Audit event types.
const (
	EventDelegationIssued        = "DELEGATION_ISSUED"
	EventCapabilityInvoked       = "CAPABILITY_INVOKED"
	EventCapabilityDenied        = "CAPABILITY_DENIED"
	EventAgentRegistered         = "AGENT_REGISTERED"
	EventAgentStateChange        = "AGENT_STATE_CHANGE"
	EventRevocationPosted        = "REVOCATION_POSTED"
	EventCompromiseCascade       = "COMPROMISE_CASCADE"
	EventReconciliationCompleted = "RECONCILIATION_COMPLETED"
	EventNonceCacheRestart       = "NONCE_CACHE_RESTART"
	EventSlowVerification        = "SLOW_VERIFICATION"
)

// ErrChainTampered reports that the audit chain's hash linkage is broken.
var ErrChainTampered = errors.New("audit chain integrity check failed")

// AuditEntry is one hash-linked audit record. Seq, Ts, PrevHash, EntryHash, and
// EntryID are assigned by Append; callers populate the event content.
type AuditEntry struct {
	EntryID   string         `json:"entry_id"`
	Seq       int64          `json:"seq"`
	Ts        int64          `json:"ts"`
	EventType string         `json:"event_type"`
	AgentID   string         `json:"agent_id"`
	CredCID   string         `json:"cred_cid,omitempty"`
	ChainHash string         `json:"chain_hash,omitempty"`
	Payload   map[string]any `json:"payload"`
	PrevHash  string         `json:"prev_hash"`
	EntryHash string         `json:"entry_hash"`
}

// AuditFilter selects entries in a Query.
type AuditFilter struct {
	EventType string
	AgentID   string
	Since     int64
}

// AuditLog is an append-only, integrity-verifiable audit log.
type AuditLog interface {
	Append(entry AuditEntry) error
	Query(filter AuditFilter) ([]AuditEntry, error)
	VerifyChain() error
}

// MemoryAuditLog is an in-memory AuditLog.
type MemoryAuditLog struct {
	mu       sync.Mutex
	entries  []AuditEntry
	lastHash string
	seq      int64
}

var _ AuditLog = (*MemoryAuditLog)(nil)

// NewMemoryAuditLog returns an empty log.
func NewMemoryAuditLog() *MemoryAuditLog {
	return &MemoryAuditLog{}
}

// ComputeEntryHash exposes the hash-linking function so durable backends can
// compute an entry's hash in Go before insert (Section 14). It is the same
// computation Append performs.
func ComputeEntryHash(seq, ts int64, prevHash, eventType, agentID, credCID, chainHash string, payload map[string]any) (string, error) {
	return entryHash(seq, ts, prevHash, eventType, agentID, credCID, chainHash, payload)
}

// entryHash computes SHA-256 over the canonical JSON of every semantic field —
// seq, ts, prev_hash, event_type, agent_id, cred_cid, chain_hash, and payload —
// so that tampering with any of them (not just payload or the linkage) is
// detectable. Excluding event_type/agent_id/cred_cid would let an adversary with
// storage access rewrite who did what while the chain still verified.
func entryHash(seq, ts int64, prevHash, eventType, agentID, credCID, chainHash string, payload map[string]any) (string, error) {
	if payload == nil {
		payload = map[string]any{}
	}
	canonical, err := signing.CanonicalizeValue(map[string]any{
		"seq":        seq,
		"ts":         ts,
		"prev_hash":  prevHash,
		"event_type": eventType,
		"agent_id":   agentID,
		"cred_cid":   credCID,
		"chain_hash": chainHash,
		"payload":    payload,
	})
	if err != nil {
		return "", fmt.Errorf("aitp/audit: hash entry: %w", err)
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// Append assigns the next sequence number, links the entry to the previous one
// by hash, and stores it.
func (l *MemoryAuditLog) Append(entry AuditEntry) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.seq++
	entry.Seq = l.seq
	if entry.Ts == 0 {
		entry.Ts = time.Now().Unix()
	}
	if entry.Payload == nil {
		entry.Payload = map[string]any{}
	}
	entry.PrevHash = l.lastHash

	hash, err := entryHash(entry.Seq, entry.Ts, entry.PrevHash, entry.EventType, entry.AgentID, entry.CredCID, entry.ChainHash, entry.Payload)
	if err != nil {
		return err
	}
	entry.EntryHash = hash
	entry.EntryID = fmt.Sprintf("ae_%d_%s", entry.Seq, hash[:12])

	l.entries = append(l.entries, entry)
	l.lastHash = hash
	return nil
}

// Query returns entries matching filter, in order.
func (l *MemoryAuditLog) Query(filter AuditFilter) ([]AuditEntry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	var out []AuditEntry
	for _, e := range l.entries {
		if filter.EventType != "" && e.EventType != filter.EventType {
			continue
		}
		if filter.AgentID != "" && e.AgentID != filter.AgentID {
			continue
		}
		if filter.Since != 0 && e.Ts < filter.Since {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

// VerifyChain recomputes every entry's hash and checks the prev-hash linkage,
// detecting any truncation or in-place modification.
func (l *MemoryAuditLog) VerifyChain() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	prev := ""
	for i, e := range l.entries {
		if e.PrevHash != prev {
			return fmt.Errorf("aitp/audit: %w: entry %d prev_hash break", ErrChainTampered, i)
		}
		hash, err := entryHash(e.Seq, e.Ts, e.PrevHash, e.EventType, e.AgentID, e.CredCID, e.ChainHash, e.Payload)
		if err != nil {
			return err
		}
		if hash != e.EntryHash {
			return fmt.Errorf("aitp/audit: %w: entry %d hash mismatch", ErrChainTampered, i)
		}
		prev = e.EntryHash
	}
	return nil
}

// Len returns the number of entries (for tests and metrics).
func (l *MemoryAuditLog) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}
