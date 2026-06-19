package v1

import (
	"sync"
	"testing"

	"github.com/adtp/adtp/internal/audit"
	"github.com/adtp/adtp/store/memory"
)

type recordingExporter struct {
	mu  sync.Mutex
	got []audit.AuditEntry
}

func (r *recordingExporter) Enqueue(e audit.AuditEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.got = append(r.got, e)
}

func (r *recordingExporter) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.got)
}

func TestServiceAuditLogTee(t *testing.T) {
	rec := &recordingExporter{}
	svc := &Service{Store: memory.New(), SIEM: rec}

	log := svc.auditLog()
	if _, ok := log.(siemAuditLog); !ok {
		t.Fatalf("auditLog() = %T, want siemAuditLog tee", log)
	}
	if err := log.Append(audit.AuditEntry{EventType: audit.EventCapabilityInvoked, AgentID: "did:key:zA"}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if rec.count() != 1 {
		t.Errorf("exporter received %d entries, want 1", rec.count())
	}
	// Reads and chain verification delegate to the durable primary log.
	if entries, err := log.Query(audit.AuditFilter{}); err != nil || len(entries) != 1 {
		t.Errorf("Query = (%d, %v)", len(entries), err)
	}
	if err := log.VerifyChain(); err != nil {
		t.Errorf("VerifyChain: %v", err)
	}
}

func TestServiceAuditLogNoTeeWithoutSIEM(t *testing.T) {
	svc := &Service{Store: memory.New()}
	if _, ok := svc.auditLog().(siemAuditLog); ok {
		t.Errorf("auditLog() returned a tee without a SIEM exporter configured")
	}
}
