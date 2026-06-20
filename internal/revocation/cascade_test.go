package revocation

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/Zahanturel/adtp/internal/audit"
)

func TestExecuteCascadeWithDescendants(t *testing.T) {
	key, _ := genKey(t)
	cache := NewMemoryRevocationCache()
	index := NewMemoryRegistrationIndex()
	auditLog := audit.NewMemoryAuditLog()
	emergency := &MemoryEmergencyChannel{}

	const midCID, rootCID = "bafkreimid", "bafkreiroot"
	descendants := []string{"bafkreid1", "bafkreid2", "bafkreid3", "bafkreid4", "bafkreid5"}
	for _, d := range descendants {
		index.Register(context.Background(), d, []string{d, midCID, rootCID})
	}
	index.Register(context.Background(), midCID, []string{midCID, rootCID})

	report, err := ExecuteCascade(context.Background(), midCID, index, cache, emergency, auditLog, key)
	if err != nil {
		t.Fatalf("ExecuteCascade: %v", err)
	}
	if report.DescendantCount != 5 {
		t.Errorf("descendant count = %d, want 5", report.DescendantCount)
	}

	// The compromised credential is COMPROMISED.
	if s, _ := cache.GetStatus(context.Background(), midCID); s == nil || s.Status != StatusCompromised {
		t.Errorf("mid status = %+v, want COMPROMISED", s)
	}
	// Cascade completeness: every descendant is CASCADE-revoked.
	for _, d := range descendants {
		if s, _ := cache.GetStatus(context.Background(), d); s == nil || s.Status != StatusCascade {
			t.Errorf("descendant %s status = %+v, want CASCADE", d, s)
		}
	}
	// The emergency channel received the primary plus all cascade entries.
	if len(emergency.Batches) != 1 || len(emergency.Batches[0]) != 6 {
		t.Errorf("emergency batches = %v", emergency.Batches)
	}
	// Both audit events are present.
	rev, _ := auditLog.Query(audit.AuditFilter{EventType: audit.EventRevocationPosted})
	casc, _ := auditLog.Query(audit.AuditFilter{EventType: audit.EventCompromiseCascade})
	if len(rev) != 1 || len(casc) != 1 {
		t.Errorf("audit events: revocation=%d cascade=%d", len(rev), len(casc))
	}
}

func TestExecuteCascadeNoDescendants(t *testing.T) {
	key, _ := genKey(t)
	cache := NewMemoryRevocationCache()
	index := NewMemoryRegistrationIndex()
	const cid = "bafkreilonely"
	index.Register(context.Background(), cid, []string{cid})

	report, err := ExecuteCascade(context.Background(), cid, index, cache, nil, audit.NewMemoryAuditLog(), key)
	if err != nil {
		t.Fatalf("ExecuteCascade: %v", err)
	}
	if report.DescendantCount != 0 {
		t.Errorf("descendant count = %d, want 0", report.DescendantCount)
	}
	if s, _ := cache.GetStatus(context.Background(), cid); s == nil || s.Status != StatusCompromised {
		t.Errorf("status = %+v, want COMPROMISED", s)
	}
}

func TestExecuteCascadeBadKey(t *testing.T) {
	_, err := ExecuteCascade(context.Background(), "c", NewMemoryRegistrationIndex(), NewMemoryRevocationCache(), nil, audit.NewMemoryAuditLog(), ed25519.PrivateKey{1})
	if !errors.Is(err, ErrInvalidKey) {
		t.Errorf("err = %v, want ErrInvalidKey", err)
	}
}
