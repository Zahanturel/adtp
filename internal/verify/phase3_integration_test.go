package verify_test

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/adtp/adtp/internal/audit"
	"github.com/adtp/adtp/internal/credential"
	"github.com/adtp/adtp/internal/identity"
	"github.com/adtp/adtp/internal/lifecycle"
	"github.com/adtp/adtp/internal/revocation"
	"github.com/adtp/adtp/internal/verify"
	"github.com/adtp/adtp/store/memory"
)

func key(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	did, priv, err := identity.GenerateDID()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return priv, did
}

// TestPhase3FullLifecycle proves the complete control plane end to end:
// identity -> credentials -> delegation -> verification -> revocation ->
// cascade -> audit.
func TestPhase3FullLifecycle(t *testing.T) {
	now := time.Now().Unix()
	st := memory.New()
	auditLog := st.Audit()

	platformKey, platformDID := key(t)
	agentKey, agentDID := key(t)
	subKey, subDID := key(t)
	leafKey, leafDID := key(t)
	_, verifierDID := key(t)

	// 1. Register an agent and activate it (REGISTERED -> ACTIVE).
	agent := lifecycle.NewAgent(agentDID, platformDID)
	if err := lifecycle.Transition(agent, lifecycle.StateActive, platformDID, "credential issued"); err != nil {
		t.Fatalf("activate agent: %v", err)
	}
	if err := st.PutAgent(agent); err != nil {
		t.Fatalf("PutAgent: %v", err)
	}
	mustAudit(t, auditLog, audit.AuditEntry{EventType: audit.EventAgentRegistered, AgentID: agentDID})

	// 2. Issue the root credential.
	delegateCap := mustCap(t, credential.CanAgentDelegate, "agent://platform/agents",
		credential.DelegationDepthConstraint{Type: credential.ConstraintDelegationDepth, Max: 5})
	toolCap := mustCap(t, credential.CanToolInvoke, "tool://server/*")
	rootToken, err := credential.CreateUCAN(credential.UCANPayload{
		Iss: platformDID, Aud: agentDID,
		Att: []credential.Capability{delegateCap, toolCap},
		Prf: []string{}, Exp: now + 3600, Nbf: now - 60, Iat: now,
	}, platformKey)
	if err != nil {
		t.Fatalf("CreateUCAN: %v", err)
	}
	rootCID, _ := st.PutCredential([]byte(rootToken))
	st.Register(rootCID, []string{rootCID})

	// 3. Delegate twice in RESTRICT mode.
	caveats := credential.Constraints{credential.NewTimeWindow(now-100, now+3600)}
	_, midRaw, err := credential.CreateRestrictBlock(
		credential.DelegationParent{CID: rootCID, Aud: agentDID, Exp: now + 3600, Nbf: now - 60, DL: 5},
		subDID, 4, caveats, agentKey)
	if err != nil {
		t.Fatalf("mid delegation: %v", err)
	}
	midCID, _ := st.PutCredential(midRaw)
	st.Register(midCID, []string{midCID, rootCID})
	mustAudit(t, auditLog, audit.AuditEntry{EventType: audit.EventDelegationIssued, AgentID: subDID, CredCID: midCID})

	_, leafRaw, err := credential.CreateRestrictBlock(
		credential.DelegationParent{CID: midCID, Aud: subDID, Exp: now + 3600, Nbf: now - 60, DL: 4},
		leafDID, 3, caveats, subKey)
	if err != nil {
		t.Fatalf("leaf delegation: %v", err)
	}
	leafCID, _ := st.PutCredential(leafRaw)
	st.Register(leafCID, []string{leafCID, midCID, rootCID})
	mustAudit(t, auditLog, audit.AuditEntry{EventType: audit.EventDelegationIssued, AgentID: leafDID, CredCID: leafCID})

	config := &verify.VerifierConfig{
		VerifierDID:     verifierDID,
		TrustedRootDIDs: map[string]bool{platformDID: true},
		MaxChainDepth:   10,
		ProofStore:      st,
		RevocationCache: st,
		AuditLog:        auditLog,
		NonceCache:      verify.NewMemoryNonceCache(),
	}

	// 4. Verify the leaf successfully.
	inv1, err := verify.CreateInvocation(leafCID, credential.CanToolInvoke, "tool://server/search", nil, leafKey, verifierDID, "")
	if err != nil {
		t.Fatalf("CreateInvocation: %v", err)
	}
	if res := verify.Verify(nil, inv1, config); !res.OK {
		t.Fatalf("initial verification failed: %v", res.Error)
	}

	// 5 + 6. Compromise the middle credential and cascade to its descendants.
	report, err := revocation.ExecuteCascade(midCID, st, st, nil, auditLog, platformKey)
	if err != nil {
		t.Fatalf("ExecuteCascade: %v", err)
	}
	if report.DescendantCount != 1 {
		t.Errorf("descendant count = %d, want 1 (the leaf)", report.DescendantCount)
	}

	// 7. Verifying the leaf must now fail at step 6.
	inv2, err := verify.CreateInvocation(leafCID, credential.CanToolInvoke, "tool://server/search", nil, leafKey, verifierDID, "")
	if err != nil {
		t.Fatalf("CreateInvocation: %v", err)
	}
	res2 := verify.Verify(nil, inv2, config)
	if res2.OK {
		t.Fatal("leaf verified after compromise cascade")
	}
	if res2.Error.Step != 6 {
		t.Errorf("failed at step %d, want 6", res2.Error.Step)
	}
	if res2.Error.Code != verify.CodeCompromised {
		t.Errorf("code = %s, want V006", res2.Error.Code)
	}

	// 8. Reconciliation reports no repairs — the cascade was complete.
	rec, err := revocation.Reconcile(st, st, auditLog)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if rec.RepairsApplied != 0 {
		t.Errorf("reconciliation repairs = %d, want 0", rec.RepairsApplied)
	}

	// 9. The audit log captured the full sequence and remains hash-intact.
	for _, evt := range []string{
		audit.EventAgentRegistered,
		audit.EventCapabilityInvoked,
		audit.EventRevocationPosted,
		audit.EventCompromiseCascade,
	} {
		if got, _ := auditLog.Query(audit.AuditFilter{EventType: evt}); len(got) < 1 {
			t.Errorf("audit log missing event %s", evt)
		}
	}
	if deleg, _ := auditLog.Query(audit.AuditFilter{EventType: audit.EventDelegationIssued}); len(deleg) != 2 {
		t.Errorf("DELEGATION_ISSUED count = %d, want 2", len(deleg))
	}
	if err := auditLog.VerifyChain(); err != nil {
		t.Errorf("audit chain integrity: %v", err)
	}
}

func mustAudit(t *testing.T, log audit.AuditLog, entry audit.AuditEntry) {
	t.Helper()
	if err := log.Append(entry); err != nil {
		t.Fatalf("audit append: %v", err)
	}
}

func mustCap(t *testing.T, can, with string, cs ...credential.Constraint) credential.Capability {
	t.Helper()
	c, err := credential.NewCapability(can, with, cs...)
	if err != nil {
		t.Fatalf("NewCapability: %v", err)
	}
	return c
}
