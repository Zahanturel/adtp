// Package memory provides a unified in-memory storage backend that satisfies
// the agent, credential, proof, registration, and revocation interfaces used
// across the daemon. It is the default for single-node deployments and the
// backend for tests.
package memory

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"

	"github.com/Zahanturel/adtp/internal/audit"
	"github.com/Zahanturel/adtp/internal/credential"
	"github.com/Zahanturel/adtp/internal/delegation"
	"github.com/Zahanturel/adtp/internal/lifecycle"
	"github.com/Zahanturel/adtp/internal/revocation"
	"github.com/Zahanturel/adtp/store"
)

// Store errors.
var (
	ErrAgentNotFound     = errors.New("agent not found")
	ErrCredentialNotFound = errors.New("credential not found")
	ErrInvalidAgent      = errors.New("invalid agent")
)

// AgentStore persists agents and their lifecycle state.
type AgentStore interface {
	PutAgent(ctx context.Context, agent *lifecycle.Agent) error
	GetAgent(ctx context.Context, did string) (*lifecycle.Agent, error)
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

// PutAgent stores a defensive copy of the agent.
func (s *MemoryStore) PutAgent(_ context.Context, agent *lifecycle.Agent) error {
	if agent == nil || agent.DID == "" {
		return fmt.Errorf("adtp/store: %w: missing DID", ErrInvalidAgent)
	}
	cp := *agent
	s.mu.Lock()
	s.agents[agent.DID] = &cp
	s.mu.Unlock()
	return nil
}

// GetAgent returns a defensive copy of the agent for did, or ErrAgentNotFound.
func (s *MemoryStore) GetAgent(_ context.Context, did string) (*lifecycle.Agent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.agents[did]
	if !ok {
		return nil, fmt.Errorf("adtp/store: %w: %s", ErrAgentNotFound, did)
	}
	cp := *a
	return &cp, nil
}

// --- credentials / proof store ---

// PutCredential stores raw under its CID and returns that CID.
func (s *MemoryStore) PutCredential(_ context.Context, raw []byte) (string, error) {
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
func (s *MemoryStore) Get(_ context.Context, cid string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	raw, ok := s.credentials[cid]
	if !ok {
		return nil, fmt.Errorf("adtp/store: %w: %s", ErrCredentialNotFound, cid)
	}
	return append([]byte(nil), raw...), nil
}

// ListCredentials returns all stored credential CIDs in insertion order.
func (s *MemoryStore) ListCredentials(_ context.Context) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]string(nil), s.credOrder...), nil
}

// --- registration index ---

// Register records that credentialCID's chain contains each of chainCIDs.
func (s *MemoryStore) Register(ctx context.Context, credentialCID string, chainCIDs []string) error {
	return s.registrations.Register(ctx, credentialCID, chainCIDs)
}

// FindDescendants returns the credentials whose chain contains cid.
func (s *MemoryStore) FindDescendants(ctx context.Context, cid string) ([]string, error) {
	return s.registrations.FindDescendants(ctx, cid)
}

// Contains reports whether credentialCID's chain is recorded as containing
// chainCID.
func (s *MemoryStore) Contains(ctx context.Context, credentialCID, chainCID string) bool {
	return s.registrations.Contains(ctx, credentialCID, chainCID)
}

// --- revocation ---

// GetStatus returns the latest revocation entry for a subject, or nil.
func (s *MemoryStore) GetStatus(ctx context.Context, subject string) (*revocation.RevocationEntry, error) {
	return s.revocations.GetStatus(ctx, subject)
}

// Revoke applies a revocation entry.
func (s *MemoryStore) Revoke(ctx context.Context, entry revocation.RevocationEntry) error {
	return s.revocations.Revoke(ctx, entry)
}

// CurrentSeq returns the highest sequence recorded for a subject.
func (s *MemoryStore) CurrentSeq(ctx context.Context, subject string) (int64, error) {
	return s.revocations.CurrentSeq(ctx, subject)
}

// UpdateFromList applies a signed revocation list after verifying its signature
// under issuerPub.
func (s *MemoryStore) UpdateFromList(list *revocation.RevocationList, issuerPub ed25519.PublicKey) error {
	return s.revocations.UpdateFromList(list, issuerPub)
}

// RevocationEntries snapshots the latest revocation entry per subject.
func (s *MemoryStore) RevocationEntries(_ context.Context) ([]revocation.RevocationEntry, error) {
	return s.revocations.Entries(), nil
}

// --- audit ---

// Audit returns the store's audit log.
func (s *MemoryStore) Audit() audit.AuditLog {
	return s.auditLog
}

// Close releases resources. The in-memory store holds none.
func (s *MemoryStore) Close() error { return nil }
