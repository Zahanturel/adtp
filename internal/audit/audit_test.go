package audit

import (
	"errors"
	"testing"
)

func TestAppendAndChainLinkage(t *testing.T) {
	log := NewMemoryAuditLog()
	for i := 0; i < 5; i++ {
		if err := log.Append(AuditEntry{EventType: EventCapabilityInvoked, AgentID: "did:key:zA", Payload: map[string]any{"n": i}}); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	all, _ := log.Query(AuditFilter{})
	if len(all) != 5 {
		t.Fatalf("len = %d, want 5", len(all))
	}
	if all[0].PrevHash != "" {
		t.Errorf("first entry prev_hash should be empty, got %q", all[0].PrevHash)
	}
	for i := 1; i < len(all); i++ {
		if all[i].PrevHash != all[i-1].EntryHash {
			t.Errorf("entry %d prev_hash does not link to previous entry_hash", i)
		}
		if all[i].Seq != int64(i+1) {
			t.Errorf("entry %d seq = %d, want %d", i, all[i].Seq, i+1)
		}
	}
	if err := log.VerifyChain(); err != nil {
		t.Errorf("VerifyChain: %v", err)
	}
}

func TestVerifyChainDetectsTamper(t *testing.T) {
	log := NewMemoryAuditLog()
	for i := 0; i < 3; i++ {
		if err := log.Append(AuditEntry{EventType: EventRevocationPosted, Payload: map[string]any{"i": i}}); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	if err := log.VerifyChain(); err != nil {
		t.Fatalf("clean chain failed: %v", err)
	}

	t.Run("payload tamper", func(t *testing.T) {
		log.entries[1].Payload["i"] = 99
		if err := log.VerifyChain(); !errors.Is(err, ErrChainTampered) {
			t.Errorf("VerifyChain = %v, want ErrChainTampered", err)
		}
		log.entries[1].Payload["i"] = 1 // restore
	})

	t.Run("hash forge breaks linkage", func(t *testing.T) {
		orig := log.entries[1].EntryHash
		log.entries[1].EntryHash = "deadbeef"
		if err := log.VerifyChain(); !errors.Is(err, ErrChainTampered) {
			t.Errorf("VerifyChain = %v, want ErrChainTampered", err)
		}
		log.entries[1].EntryHash = orig
	})

	t.Run("truncation detectable", func(t *testing.T) {
		// Removing a middle entry breaks the next entry's prev_hash link.
		saved := log.entries
		log.entries = []AuditEntry{saved[0], saved[2]}
		if err := log.VerifyChain(); !errors.Is(err, ErrChainTampered) {
			t.Errorf("VerifyChain = %v, want ErrChainTampered", err)
		}
		log.entries = saved
	})
}

func TestVerifyChainDetectsSemanticFieldTamper(t *testing.T) {
	mk := func() *MemoryAuditLog {
		log := NewMemoryAuditLog()
		for i := 0; i < 3; i++ {
			if err := log.Append(AuditEntry{
				EventType: EventCapabilityInvoked, AgentID: "did:key:zVictim",
				CredCID: "bafkreivictim", Payload: map[string]any{"result": "ALLOW"},
			}); err != nil {
				t.Fatalf("Append: %v", err)
			}
		}
		if err := log.VerifyChain(); err != nil {
			t.Fatalf("clean chain failed: %v", err)
		}
		return log
	}

	cases := []struct {
		name   string
		mutate func(*AuditEntry)
	}{
		{"agent_id", func(e *AuditEntry) { e.AgentID = "did:key:zAttacker" }},
		{"event_type", func(e *AuditEntry) { e.EventType = "NOTHING_HAPPENED" }},
		{"cred_cid", func(e *AuditEntry) { e.CredCID = "bafkreiforged" }},
		{"chain_hash", func(e *AuditEntry) { e.ChainHash = "deadbeef" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			log := mk()
			c.mutate(&log.entries[1])
			if err := log.VerifyChain(); !errors.Is(err, ErrChainTampered) {
				t.Errorf("VerifyChain after %s tamper = %v, want ErrChainTampered", c.name, err)
			}
		})
	}
}

func TestQueryFilters(t *testing.T) {
	log := NewMemoryAuditLog()
	_ = log.Append(AuditEntry{EventType: EventAgentRegistered, AgentID: "did:key:zA", Ts: 100})
	_ = log.Append(AuditEntry{EventType: EventDelegationIssued, AgentID: "did:key:zA", Ts: 200})
	_ = log.Append(AuditEntry{EventType: EventDelegationIssued, AgentID: "did:key:zB", Ts: 300})

	byType, _ := log.Query(AuditFilter{EventType: EventDelegationIssued})
	if len(byType) != 2 {
		t.Errorf("by type = %d, want 2", len(byType))
	}
	byAgent, _ := log.Query(AuditFilter{AgentID: "did:key:zA"})
	if len(byAgent) != 2 {
		t.Errorf("by agent = %d, want 2", len(byAgent))
	}
	since, _ := log.Query(AuditFilter{Since: 250})
	if len(since) != 1 {
		t.Errorf("since = %d, want 1", len(since))
	}
}

func TestEmptyChainVerifies(t *testing.T) {
	if err := NewMemoryAuditLog().VerifyChain(); err != nil {
		t.Errorf("empty chain VerifyChain = %v, want nil", err)
	}
}
