// Package memory provides a unified in-memory storage backend that satisfies
// the agent, credential, proof, registration, and revocation interfaces used
// across the daemon. It is the default for single-node deployments and the
// backend for tests.
package memory

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"

	"github.com/adtp/adtp/internal/audit"
	"github.com/adtp/adtp/internal/credential"
	"github.com/adtp/adtp/internal/delegation"
	"github.com/adtp/adtp/internal/lifecycle"
	"github.com/adtp/adtp/internal/revocation"
	"github.com/adtp/adtp/store"
)

// Store errors.
var (
	ErrAgentNotFound      = errors.New("agent not found")
	ErrCredentialNotFound = errors.New("credential not found")
	ErrInvalidAgent       = errors.New("invalid agent")
)

// AgentStore persists agents and their lifecycle state.
type AgentStore interface {
	PutAgent(agent *lifecycle.Agent) error
	GetAgent(did string) (*lifecycle.Agent, error)
}

// MemoryStore is the composed in-memory backend.
type MemoryStore struct {
	mu          sync.RWMutex
	agents      map[string]*lifecycle.Agent
	credentials map[string][]byte
	credOrder   []string

	registrations *revocation.MemoryRegistrationIndex
	revocations   *revocation.MemoryRevocationCache
	auditLog      *audit.MemoryAuditLog
}

// Interface conformance.
var (
	_ AgentStore                   = (*MemoryStore)(nil)
	_ delegation.ProofStore        = (*MemoryStore)(nil)
	_ revocation.CredentialStore   = (*MemoryStore)(nil)
	_ revocation.RegistrationIndex = (*MemoryStore)(nil)
	_ revocation.RegistrationStore = (*MemoryStore)(nil)
	_ revocation.RevocationService = (*MemoryStore)(nil)
	_ store.Store                  = (*MemoryStore)(nil)
)

// New returns an empty store.
func New() *MemoryStore {
	return &MemoryStore{
		agents:        make(map[string]*lifecycle.Agent),
		credentials:   make(map[string][]byte),
		registrations: revocation.NewMemoryRegistrationIndex(),
		revocations:   revocation.NewMemoryRevocationCache(),
		auditLog:      audit.NewMemoryAuditLog(),
	}
}

// --- agents ---

// PutAgent stores or replaces an agent.
func (s *MemoryStore) PutAgent(agent *lifecycle.Agent) error {
	if agent == nil || agent.DID == "" {
		return fmt.Errorf("aitp/store: %w: missing DID", ErrInvalidAgent)
	}
	s.mu.Lock()
	s.agents[agent.DID] = agent
	s.mu.Unlock()
	return nil
}

// GetAgent returns the agent for did, or ErrAgentNotFound.
func (s *MemoryStore) GetAgent(did string) (*lifecycle.Agent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.agents[did]
	if !ok {
		return nil, fmt.Errorf("aitp/store: %w: %s", ErrAgentNotFound, did)
	}
	return a, nil
}

// --- credentials / proof store ---

// PutCredential stores raw under its CID and returns that CID.
func (s *MemoryStore) PutCredential(raw []byte) (string, error) {
	cid := credential.ComputeCID(raw)
	s.mu.Lock()
	if _, exists := s.credentials[cid]; !exists {
		s.credOrder = append(s.credOrder, cid)
	}
	s.credentials[cid] = append([]byte(nil), raw...)
	s.mu.Unlock()
	return cid, nil
}

// Get returns the bytes stored under cid (delegation.ProofStore and
// revocation.CredentialStore).
func (s *MemoryStore) Get(cid string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	raw, ok := s.credentials[cid]
	if !ok {
		return nil, fmt.Errorf("aitp/store: %w: %s", ErrCredentialNotFound, cid)
	}
	return append([]byte(nil), raw...), nil
}

// ListCredentials returns all stored credential CIDs in insertion order.
func (s *MemoryStore) ListCredentials() ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]string(nil), s.credOrder...), nil
}

// --- registration index ---

// Register records that credentialCID's chain contains each of chainCIDs.
func (s *MemoryStore) Register(credentialCID string, chainCIDs []string) error {
	return s.registrations.Register(credentialCID, chainCIDs)
}

// FindDescendants returns the credentials whose chain contains cid.
func (s *MemoryStore) FindDescendants(cid string) ([]string, error) {
	return s.registrations.FindDescendants(cid)
}

// Contains reports whether credentialCID's chain is recorded as containing
// chainCID.
func (s *MemoryStore) Contains(credentialCID, chainCID string) bool {
	return s.registrations.Contains(credentialCID, chainCID)
}

// --- revocation ---

// GetStatus returns the latest revocation entry for a subject, or nil.
func (s *MemoryStore) GetStatus(subject string) (*revocation.RevocationEntry, error) {
	return s.revocations.GetStatus(subject)
}

// Revoke applies a revocation entry.
func (s *MemoryStore) Revoke(entry revocation.RevocationEntry) error {
	return s.revocations.Revoke(entry)
}

// CurrentSeq returns the highest sequence recorded for a subject.
func (s *MemoryStore) CurrentSeq(subject string) int64 {
	return s.revocations.CurrentSeq(subject)
}

// UpdateFromList applies a signed revocation list after verifying its signature
// under issuerPub.
func (s *MemoryStore) UpdateFromList(list *revocation.RevocationList, issuerPub ed25519.PublicKey) error {
	return s.revocations.UpdateFromList(list, issuerPub)
}

// RevocationEntries snapshots the latest revocation entry per subject.
func (s *MemoryStore) RevocationEntries() ([]revocation.RevocationEntry, error) {
	return s.revocations.Entries(), nil
}

// --- audit ---

// Audit returns the store's audit log.
func (s *MemoryStore) Audit() audit.AuditLog {
	return s.auditLog
}

// Close releases resources. The in-memory store holds none.
func (s *MemoryStore) Close() error { return nil }
