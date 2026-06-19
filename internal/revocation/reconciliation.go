package revocation

import (
	"fmt"

	"github.com/adtp/adtp/internal/audit"
	"github.com/adtp/adtp/internal/delegation"
)

// CredentialStore enumerates registered credentials and resolves their bytes.
// Its Get method also satisfies delegation.ProofStore, so chains can be walked.
type CredentialStore interface {
	ListCredentials() ([]string, error)
	Get(cid string) ([]byte, error)
}

// RegistrationStore is a registration index that can be queried and repaired.
type RegistrationStore interface {
	FindDescendants(cid string) ([]string, error)
	Register(credentialCID string, chainCIDs []string) error
	Contains(credentialCID, chainCID string) bool
}

// ReconciliationReport summarizes a reconciliation pass.
type ReconciliationReport struct {
	CredentialsWalked int
	RepairsApplied    int
	Errors            int
}

// Contains reports whether the index records that credentialCID's chain contains
// chainCID.
func (r *MemoryRegistrationIndex) Contains(credentialCID, chainCID string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	set, ok := r.index[chainCID]
	if !ok {
		return false
	}
	_, ok = set[credentialCID]
	return ok
}

// Reconcile walks every registered credential, reconstructs its chain, and
// backfills any missing chain_contains_cid entries in the registration index
// (Section 13.7). It is idempotent: a second pass over a repaired index applies
// zero repairs. Re-running cascades for compromised subjects touched by repairs
// is the caller's responsibility, since that requires the revocation service.
func Reconcile(credStore CredentialStore, index RegistrationStore, auditLog audit.AuditLog) (*ReconciliationReport, error) {
	cids, err := credStore.ListCredentials()
	if err != nil {
		return nil, fmt.Errorf("aitp/revocation: list credentials: %w", err)
	}

	report := &ReconciliationReport{}
	for _, cid := range cids {
		report.CredentialsWalked++
		chain, err := delegation.BuildChain(cid, credStore, delegation.HardMaxDepth)
		if err != nil {
			report.Errors++
			continue
		}
		for _, element := range chain.Elements {
			if index.Contains(cid, element.CID) {
				continue
			}
			if err := index.Register(cid, []string{element.CID}); err != nil {
				report.Errors++
				continue
			}
			report.RepairsApplied++
		}
	}

	if auditLog != nil {
		if err := auditLog.Append(audit.AuditEntry{
			EventType: audit.EventReconciliationCompleted,
			Payload: map[string]any{
				"credentials_walked": report.CredentialsWalked,
				"repairs_applied":    report.RepairsApplied,
				"errors":             report.Errors,
			},
		}); err != nil {
			return nil, err
		}
	}
	return report, nil
}
