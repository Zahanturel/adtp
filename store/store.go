// Package store defines the unified storage interface the daemon depends on.
// Both the in-memory and PostgreSQL backends implement it.
package store

import (
	"github.com/adtp/adtp/internal/audit"
	"github.com/adtp/adtp/internal/lifecycle"
	"github.com/adtp/adtp/internal/revocation"
)

// Store is the daemon's storage backend. It composes the credential, proof,
// registration, and revocation stores and exposes agents and the audit log.
//
// A Store value satisfies several engine interfaces directly, so it can be
// passed without adapters:
//   - delegation.ProofStore         (via Get)
//   - verify.RevocationCache        (via GetStatus)
//   - revocation.CredentialStore    (embedded)
//   - revocation.RegistrationStore  (embedded)
//   - revocation.RegistrationIndex  (via the embedded RegistrationStore)
//   - revocation.RevocationService  (embedded)
type Store interface {
	revocation.CredentialStore   // ListCredentials, Get
	revocation.RegistrationStore // FindDescendants, Register, Contains
	revocation.RevocationService // Revoke, CurrentSeq

	// PutAgent stores or replaces an agent; GetAgent retrieves one.
	PutAgent(agent *lifecycle.Agent) error
	GetAgent(did string) (*lifecycle.Agent, error)

	// PutCredential stores raw credential bytes and returns the CID.
	PutCredential(raw []byte) (string, error)

	// GetStatus returns the latest revocation entry for a subject, or nil.
	GetStatus(subject string) (*revocation.RevocationEntry, error)

	// RevocationEntries snapshots the latest entry per subject for list
	// publication.
	RevocationEntries() ([]revocation.RevocationEntry, error)

	// Audit returns the hash-linked audit log.
	Audit() audit.AuditLog

	// Close releases backend resources.
	Close() error
}
