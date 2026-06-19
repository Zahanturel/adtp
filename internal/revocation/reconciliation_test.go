package revocation

import (
	"testing"

	"github.com/adtp/adtp/internal/audit"
	"github.com/adtp/adtp/internal/delegation"
)

func registerCredential(t *testing.T, store *testCredStore, index *MemoryRegistrationIndex, cid string) {
	t.Helper()
	chain, err := delegation.BuildChain(cid, store, delegation.HardMaxDepth)
	if err != nil {
		t.Fatalf("BuildChain(%s): %v", cid, err)
	}
	var chainCIDs []string
	for _, e := range chain.Elements {
		chainCIDs = append(chainCIDs, e.CID)
	}
	index.Register(cid, chainCIDs)
}

func TestReconcileNoRepairs(t *testing.T) {
	store, rootCID, midCID, leafCID := buildSampleChain(t)
	index := NewMemoryRegistrationIndex()
	for _, cid := range []string{rootCID, midCID, leafCID} {
		registerCredential(t, store, index, cid)
	}

	report, err := Reconcile(store, index, audit.NewMemoryAuditLog())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if report.CredentialsWalked != 3 {
		t.Errorf("walked = %d, want 3", report.CredentialsWalked)
	}
	if report.RepairsApplied != 0 {
		t.Errorf("repairs = %d, want 0", report.RepairsApplied)
	}
}

func TestReconcileBackfillsMissing(t *testing.T) {
	store, rootCID, midCID, leafCID := buildSampleChain(t)
	index := NewMemoryRegistrationIndex()
	// Register root and mid, but not the leaf — its chain registrations are missing.
	registerCredential(t, store, index, rootCID)
	registerCredential(t, store, index, midCID)

	log := audit.NewMemoryAuditLog()
	report, err := Reconcile(store, index, log)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if report.RepairsApplied == 0 {
		t.Errorf("expected repairs for the unregistered leaf")
	}
	if !index.Contains(leafCID, midCID) || !index.Contains(leafCID, rootCID) {
		t.Errorf("leaf chain links not backfilled")
	}

	// Reconciliation is idempotent: a second pass repairs nothing.
	report2, err := Reconcile(store, index, log)
	if err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	if report2.RepairsApplied != 0 {
		t.Errorf("second run repairs = %d, want 0", report2.RepairsApplied)
	}

	// The reconciliation events were audited.
	done, _ := log.Query(audit.AuditFilter{EventType: audit.EventReconciliationCompleted})
	if len(done) != 2 {
		t.Errorf("reconciliation audit events = %d, want 2", len(done))
	}
}
