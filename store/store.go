// Package store defines the unified storage interface the daemon depends on.
// Both the in-memory and PostgreSQL backends implement it.
package store

import (
	"context"

	"github.com/Zahanturel/adtp/internal/audit"
	"github.com/Zahanturel/adtp/internal/lifecycle"
	"github.com/Zahanturel/adtp/internal/revocation"
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
	PutAgent(ctx context.Context, agent *lifecycle.Agent) error
	GetAgent(ctx context.Context, did string) (*lifecycle.Agent, error)

	// PutCredential stores raw credential bytes and returns the CID.
	PutCredential(ctx context.Context, raw []byte) (string, error)

	// GetStatus returns the latest revocation entry for a subject, or nil.
	GetStatus(ctx context.Context, subject string) (*revocation.RevocationEntry, error)

	// RevocationEntries snapshots the latest entry per subject for list
	// publication.
	RevocationEntries(ctx context.Context) ([]revocation.RevocationEntry, error)

	// Audit returns the hash-linked audit log.
	Audit() audit.AuditLog

	// Close releases backend resources.
	Close() error
}
