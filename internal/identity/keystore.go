package identity

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"sort"
	"sync"
)

// KeyStore errors.
var (
	// ErrKeyNotFound reports a Load or Delete for a DID with no stored key.
	ErrKeyNotFound = errors.New("key not found")
	// ErrEmptyDID reports a Store with an empty DID.
	ErrEmptyDID = errors.New("empty DID")
	// ErrInvalidPrivateKey reports a private key of the wrong size.
	ErrInvalidPrivateKey = errors.New("invalid ed25519 private key")
)

// KeyStore persists Ed25519 private keys indexed by DID. Implementations must be
// safe for concurrent use.
type KeyStore interface {
	// Store saves priv under did, replacing any existing key for that DID.
	Store(did string, priv ed25519.PrivateKey) error
	// Load returns the private key for did, or ErrKeyNotFound.
	Load(did string) (ed25519.PrivateKey, error)
	// Delete removes the key for did, or returns ErrKeyNotFound.
	Delete(did string) error
	// List returns the stored DIDs in ascending order.
	List() []string
}

// MemoryKeyStore is an in-memory KeyStore backed by a sync.Map. Private keys are
// copied on store and on load so that a caller mutating its slice cannot alter
// stored key material, and vice versa.
type MemoryKeyStore struct {
	keys sync.Map // did string -> ed25519.PrivateKey (owned copy)
}

// Compile-time assertion that MemoryKeyStore satisfies KeyStore.
var _ KeyStore = (*MemoryKeyStore)(nil)

// NewMemoryKeyStore returns an empty MemoryKeyStore.
func NewMemoryKeyStore() *MemoryKeyStore {
	return &MemoryKeyStore{}
}

func (s *MemoryKeyStore) Store(did string, priv ed25519.PrivateKey) error {
	if did == "" {
		return fmt.Errorf("aitp/identity: %w", ErrEmptyDID)
	}
	if len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("aitp/identity: %w: have %d bytes, want %d",
			ErrInvalidPrivateKey, len(priv), ed25519.PrivateKeySize)
	}
	owned := make(ed25519.PrivateKey, ed25519.PrivateKeySize)
	copy(owned, priv)
	s.keys.Store(did, owned)
	return nil
}

func (s *MemoryKeyStore) Load(did string) (ed25519.PrivateKey, error) {
	v, ok := s.keys.Load(did)
	if !ok {
		return nil, fmt.Errorf("aitp/identity: %w: %s", ErrKeyNotFound, did)
	}
	stored := v.(ed25519.PrivateKey)
	out := make(ed25519.PrivateKey, len(stored))
	copy(out, stored)
	return out, nil
}

func (s *MemoryKeyStore) Delete(did string) error {
	if _, ok := s.keys.LoadAndDelete(did); !ok {
		return fmt.Errorf("aitp/identity: %w: %s", ErrKeyNotFound, did)
	}
	return nil
}

func (s *MemoryKeyStore) List() []string {
	var dids []string
	s.keys.Range(func(k, _ any) bool {
		dids = append(dids, k.(string))
		return true
	})
	sort.Strings(dids)
	return dids
}
