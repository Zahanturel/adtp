//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

// Scenario 1: "First day at a startup"
// A developer clones ADTP, starts the daemon, registers their first agent,
// issues a credential, and verifies it works.
func TestScenario_GoldenPath(t *testing.T) {
	d := startDaemon(t)

	// Health check — daemon is alive and has a platform DID.
	var health struct {
		Status      string `json:"status"`
		PlatformDID string `json:"platform_did"`
	}
	code := d.doJSON(t, "GET", "/health", nil, &health)
	if code != http.StatusOK {
		t.Fatalf("health: got %d, want 200", code)
	}
	if health.Status != "ok" {
		t.Fatalf("health status = %q, want ok", health.Status)
	}
	if health.PlatformDID == "" {
		t.Fatal("health: empty platform DID")
	}
	platformDID := health.PlatformDID
	t.Logf("platform DID: %s", platformDID)

	// Register an agent.
	agentDID := d.registerAgent(t, "sponsor@startup.com")
	t.Logf("agent DID: %s", agentDID)

	// Confirm agent is retrievable and ACTIVE.
	var agent struct {
		DID   string `json:"did"`
		State string `json:"state"`
	}
	code = d.doJSON(t, "GET", "/v1/agents/"+agentDID, nil, &agent)
	if code != http.StatusOK {
		t.Fatalf("get agent: got %d, want 200", code)
	}
	if agent.State != "ACTIVE" {
		t.Fatalf("agent state = %q, want ACTIVE", agent.State)
	}

	// Issue a root credential.
	rootCID, _ := d.issueCredential(t, agentDID, []map[string]any{
		toolInvokeCap("tool://server/search"),
	}, 3600)
	t.Logf("root CID: %s", rootCID)

	// Verify the credential authorizes tool/invoke.
	ok, depth, errCode := d.verify(t, rootCID, "tool/invoke", "tool://server/search", nil)
	if !ok {
		t.Fatalf("verify: authorized=false, errCode=%s", errCode)
	}
	if depth != 1 {
		t.Fatalf("verify: chain_depth=%d, want 1", depth)
	}
	t.Log("golden path: PASS")
}

// Scenario 2: "Delegation chain"
// Platform issues to Agent A, Agent A delegates (RESTRICT) to Agent B.
func TestScenario_DelegationChain(t *testing.T) {
	d := startDaemon(t)

	agentA := d.registerAgent(t, "devops@company.com")
	agentB := d.registerAgent(t, "devops@company.com")
	t.Logf("Agent A: %s", agentA)
	t.Logf("Agent B: %s", agentB)

	rootCID, _ := d.issueCredential(t, agentA, []map[string]any{
		toolInvokeCap("tool://server/search"),
		delegateCap("tool://server/*", 5),
	}, 3600)

	// Agent A delegates to Agent B with RESTRICT mode.
	// RESTRICT requires at least one caveat (you're adding restrictions).
	now := time.Now().Unix()
	code, delegatedCID := d.delegate(t, rootCID, agentB, "restrict", 4, []map[string]any{
		timeWindowCaveat(now-60, now+3600),
	})
	if code != http.StatusCreated {
		t.Fatalf("delegate: got %d (%s), want 201", code, delegatedCID)
	}
	t.Logf("delegated CID: %s", delegatedCID)

	// Verify Agent B's credential works.
	ok, depth, errCode := d.verify(t, delegatedCID, "tool/invoke", "tool://server/search", nil)
	if !ok {
		t.Fatalf("verify delegated: authorized=false, errCode=%s", errCode)
	}
	if depth != 2 {
		t.Fatalf("verify: chain_depth=%d, want 2", depth)
	}
	t.Log("delegation chain: PASS")
}

// Scenario 3: "Revocation kills the chain"
// Build a 3-level chain, revoke the middle, verify the leaf is dead.
func TestScenario_CascadeRevocation(t *testing.T) {
	d := startDaemon(t)

	agentA := d.registerAgent(t, "platform@zerith.sh")
	agentB := d.registerAgent(t, "platform@zerith.sh")
	agentC := d.registerAgent(t, "platform@zerith.sh")

	// Platform -> Agent A (must include agent/delegate for sub-delegation)
	rootCID, _ := d.issueCredential(t, agentA, []map[string]any{
		toolInvokeCap("tool://server/*"),
		delegateCap("tool://server/*", 5),
	}, 3600)

	// Agent A -> Agent B (RESTRICT requires at least one caveat)
	now := time.Now().Unix()
	codeAB, cidAB := d.delegate(t, rootCID, agentB, "restrict", 4, []map[string]any{
		timeWindowCaveat(now-60, now+3600),
	})
	if codeAB != http.StatusCreated {
		t.Fatalf("A->B delegation failed: %d %s", codeAB, cidAB)
	}

	// Agent B -> Agent C
	codeBC, cidBC := d.delegate(t, cidAB, agentC, "restrict", 3, []map[string]any{
		timeWindowCaveat(now-60, now+3600),
	})
	if codeBC != http.StatusCreated {
		t.Fatalf("B->C delegation failed: %d %s", codeBC, cidBC)
	}

	// Sanity: Agent C can act.
	ok, _, errCode := d.verify(t, cidBC, "tool/invoke", "tool://server/search", nil)
	if !ok {
		t.Fatalf("pre-revocation: Agent C should be authorized, errCode=%s", errCode)
	}

	// Revoke Agent A's credential as COMPROMISED — triggers cascade.
	rcode := d.revoke(t, rootCID, "subtree", "COMPROMISED")
	if rcode != http.StatusOK {
		t.Fatalf("revoke: got %d, want 200", rcode)
	}

	// Agent C's credential should now be denied.
	ok, _, errCode = d.verify(t, cidBC, "tool/invoke", "tool://server/search", nil)
	if ok {
		t.Fatal("post-revocation: Agent C should be denied")
	}
	t.Logf("Agent C denied with code: %s", errCode)

	// Confirm revocation status on A-B and B-C.
	revoked, status := d.getStatus(t, rootCID)
	if !revoked {
		t.Fatal("root credential should be revoked")
	}
	t.Logf("root status: %s", status)

	revoked, status = d.getStatus(t, cidAB)
	if !revoked {
		t.Fatal("A->B credential should be cascade-revoked")
	}
	t.Logf("A->B status: %s", status)

	revoked, status = d.getStatus(t, cidBC)
	if !revoked {
		t.Fatal("B->C credential should be cascade-revoked")
	}
	t.Logf("B->C status: %s", status)

	t.Log("cascade revocation: PASS")
}

// Scenario 4: "Escalation attempt"
// An agent tries to delegate with a higher depth_left than it received.
func TestScenario_EscalationBlocked(t *testing.T) {
	d := startDaemon(t)

	agentA := d.registerAgent(t, "admin@corp.com")
	agentB := d.registerAgent(t, "admin@corp.com")

	// Issue with depth_left implied by UCAN (the root has whatever dl the
	// platform sets). The daemon's CreateRestrictBlock enforces childDL < parentDL.
	rootCID, _ := d.issueCredential(t, agentA, []map[string]any{
		toolInvokeCap("tool://server/*"),
		delegateCap("tool://server/*", 5),
	}, 3600)

	// Delegate with RESTRICT at dl=3.
	now := time.Now().Unix()
	baseCaveats := []map[string]any{timeWindowCaveat(now-60, now+3600)}
	code, cidAB := d.delegate(t, rootCID, agentB, "restrict", 3, baseCaveats)
	if code != http.StatusCreated {
		t.Fatalf("first delegation failed: %d %s", code, cidAB)
	}

	// Now Agent B tries to sub-delegate with dl=5 (escalation: 5 > parent's 3).
	agentC := d.registerAgent(t, "admin@corp.com")
	code, errMsg := d.delegate(t, cidAB, agentC, "restrict", 5, baseCaveats)
	if code == http.StatusCreated {
		t.Fatal("escalation should be blocked, but delegation succeeded")
	}
	t.Logf("escalation blocked: %d %s", code, errMsg)

	// A valid sub-delegation at dl=2 should work.
	code, cidBC := d.delegate(t, cidAB, agentC, "restrict", 2, baseCaveats)
	if code != http.StatusCreated {
		t.Fatalf("valid sub-delegation failed: %d %s", code, cidBC)
	}
	t.Log("escalation blocked: PASS")
}

// Scenario 5: "Auth matters"
// Unauthenticated requests must be rejected; public endpoints must work.
func TestScenario_AuthEnforcement(t *testing.T) {
	d := startDaemon(t)

	// No auth header — must be rejected.
	code, _ := d.doWithKey(t, "POST", "/v1/agents", map[string]string{"sponsor_did": "test"}, "")
	if code != http.StatusUnauthorized {
		t.Fatalf("no auth: got %d, want 401", code)
	}

	// Wrong API key — must be rejected.
	code, _ = d.doWithKey(t, "POST", "/v1/agents", map[string]string{"sponsor_did": "test"}, "wrong-key")
	if code != http.StatusUnauthorized {
		t.Fatalf("wrong key: got %d, want 401", code)
	}

	// Health is exempt from auth.
	code, _ = d.doWithKey(t, "GET", "/health", nil, "")
	if code != http.StatusOK {
		t.Fatalf("health without auth: got %d, want 200", code)
	}

	// Revocation list is public.
	code, _ = d.doWithKey(t, "GET", "/v1/revocation/list", nil, "")
	if code != http.StatusOK {
		t.Fatalf("revocation list without auth: got %d, want 200", code)
	}

	// GET agent requires auth.
	code, _ = d.doWithKey(t, "GET", "/v1/agents/did:key:zFake", nil, "")
	if code != http.StatusUnauthorized {
		t.Fatalf("get agent without auth: got %d, want 401", code)
	}

	// Verify endpoint requires auth.
	code, _ = d.doWithKey(t, "POST", "/v1/verify", map[string]any{
		"chain": []string{"fake"}, "action": "x", "resource": "y",
	}, "")
	if code != http.StatusUnauthorized {
		t.Fatalf("verify without auth: got %d, want 401", code)
	}

	t.Log("auth enforcement: PASS")
}

// Scenario 6: "Expired credentials don't work"
// Issue a short-lived credential, wait for it to expire, verify it's denied.
func TestScenario_ExpiredCredential(t *testing.T) {
	d := startDaemon(t)

	agent := d.registerAgent(t, "ephemeral@test.com")
	cid, _ := d.issueCredential(t, agent, []map[string]any{
		toolInvokeCap("tool://server/search"),
	}, 1) // 1 second expiry

	// Should work immediately.
	ok, _, _ := d.verify(t, cid, "tool/invoke", "tool://server/search", nil)
	if !ok {
		t.Fatal("credential should be valid immediately after issuance")
	}

	// Wait for expiry (plus clock skew buffer).
	// The daemon has clock_skew_seconds=5, so we need to wait beyond that.
	time.Sleep(7 * time.Second)

	// Should be denied now.
	ok, _, errCode := d.verify(t, cid, "tool/invoke", "tool://server/search", nil)
	if ok {
		t.Fatal("expired credential should be denied")
	}
	t.Logf("expired credential denied with code: %s", errCode)
	t.Log("expiry enforcement: PASS")
}

// Scenario 7: "Multi-level delegation with caveat accumulation"
// Caveats from every hop in the chain must all be enforced.
func TestScenario_CaveatAccumulation(t *testing.T) {
	d := startDaemon(t)

	agentA := d.registerAgent(t, "ops@zerith.sh")
	agentB := d.registerAgent(t, "ops@zerith.sh")
	agentC := d.registerAgent(t, "ops@zerith.sh")

	// Platform -> Agent A (broad capability + delegation rights)
	rootCID, _ := d.issueCredential(t, agentA, []map[string]any{
		toolInvokeCap("tool://server/*"),
		delegateCap("tool://server/*", 5),
	}, 3600)

	// Agent A -> Agent B with resource_restrict caveat
	now := time.Now().Unix()
	code, cidAB := d.delegate(t, rootCID, agentB, "restrict", 4, []map[string]any{
		resourceRestrictCaveat("tool://server/*"),
		timeWindowCaveat(now-60, now+1800),
	})
	if code != http.StatusCreated {
		t.Fatalf("A->B delegation failed: %d %s", code, cidAB)
	}

	// Agent B -> Agent C with method_restrict caveat
	code, cidBC := d.delegate(t, cidAB, agentC, "restrict", 3, []map[string]any{
		methodRestrictCaveat("GET"),
	})
	if code != http.StatusCreated {
		t.Fatalf("B->C delegation failed: %d %s", code, cidBC)
	}

	// Verify Agent C for valid request (must include method since B->C restricts methods).
	ok, depth, errCode := d.verify(t, cidBC, "tool/invoke", "tool://server/search", map[string]any{"method": "GET"})
	if !ok {
		t.Fatalf("Agent C should be authorized for tool://server/search with method=GET, errCode=%s", errCode)
	}
	if depth != 3 {
		t.Fatalf("chain_depth=%d, want 3", depth)
	}

	// Verify denied: wrong method (POST not in method_restrict from B->C).
	ok, _, errCode = d.verify(t, cidBC, "tool/invoke", "tool://server/search", map[string]any{"method": "POST"})
	if ok {
		t.Fatal("method POST should be denied by method_restrict caveat")
	}
	t.Logf("method POST denied with code: %s", errCode)

	// Verify denied: wrong resource (resource_restrict from A->B limits to tool://server/*).
	ok, _, errCode = d.verify(t, cidBC, "tool/invoke", "tool://other/x", map[string]any{"method": "GET"})
	if ok {
		t.Fatal("resource tool://other/x should be denied by resource_restrict caveat")
	}
	t.Logf("resource tool://other/x denied with code: %s", errCode)

	// Verify denied: no method parameter (method_restrict requires it).
	ok, _, errCode = d.verify(t, cidBC, "tool/invoke", "tool://server/search", nil)
	if ok {
		t.Fatal("missing method parameter should be denied by method_restrict caveat")
	}
	t.Logf("missing method denied with code: %s", errCode)

	t.Log("caveat accumulation: PASS")
}

// Bonus Scenario: "Double revoke is idempotent"
// Revoking a credential twice shouldn't crash or produce inconsistency.
func TestScenario_DoubleRevoke(t *testing.T) {
	d := startDaemon(t)

	agent := d.registerAgent(t, "ops@zerith.sh")
	cid, _ := d.issueCredential(t, agent, []map[string]any{
		toolInvokeCap("tool://server/search"),
	}, 3600)

	// First revoke.
	code := d.revoke(t, cid, "credential", "REVOKED")
	if code != http.StatusOK {
		t.Fatalf("first revoke: got %d, want 200", code)
	}

	// Second revoke — should not crash.
	code2, raw := d.do(t, "POST", "/v1/revoke", map[string]string{
		"subject_cid": cid,
		"scope":       "credential",
		"status":      "REVOKED",
	})
	t.Logf("second revoke: status=%d body=%s", code2, raw)

	// Verify the credential is still denied.
	ok, _, _ := d.verify(t, cid, "tool/invoke", "tool://server/search", nil)
	if ok {
		t.Fatal("revoked credential should still be denied after double revoke")
	}

	t.Log("double revoke: PASS")
}

// Scenario: "Admin reconciliation endpoint"
// Trigger manual reconciliation and verify it returns sane numbers.
func TestScenario_AdminReconcile(t *testing.T) {
	d := startDaemon(t)

	agent := d.registerAgent(t, "ops@zerith.sh")
	d.issueCredential(t, agent, []map[string]any{
		toolInvokeCap("tool://server/search"),
	}, 3600)

	var resp struct {
		CredentialsWalked int `json:"credentials_walked"`
		RepairsApplied    int `json:"repairs_applied"`
		Errors            int `json:"errors"`
	}
	code := d.doJSON(t, "POST", "/v1/admin/reconcile", nil, &resp)
	if code != http.StatusOK {
		t.Fatalf("admin reconcile: got %d, want 200", code)
	}
	if resp.CredentialsWalked < 1 {
		t.Fatalf("expected at least 1 credential walked, got %d", resp.CredentialsWalked)
	}
	if resp.Errors != 0 {
		t.Fatalf("reconciliation errors: %d", resp.Errors)
	}
	t.Logf("reconcile: walked=%d repairs=%d errors=%d", resp.CredentialsWalked, resp.RepairsApplied, resp.Errors)
	t.Log("admin reconcile: PASS")
}

// Bonus Scenario: "Revocation list is signed and public"
func TestScenario_RevocationList(t *testing.T) {
	d := startDaemon(t)

	agent := d.registerAgent(t, "ops@zerith.sh")
	cid, _ := d.issueCredential(t, agent, []map[string]any{
		toolInvokeCap("tool://x"),
	}, 3600)

	// Revoke one credential.
	d.revoke(t, cid, "credential", "REVOKED")

	// Fetch the public revocation list (no auth).
	code, raw := d.doWithKey(t, "GET", "/v1/revocation/list", nil, "")
	if code != http.StatusOK {
		t.Fatalf("revocation list: got %d", code)
	}

	var list struct {
		Issuer  string `json:"issuer"`
		Entries []struct {
			Subject struct {
				CID string `json:"cid"`
			} `json:"subject"`
			Status string `json:"status"`
		} `json:"entries"`
		Sig string `json:"sig"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatalf("unmarshal revocation list: %v", err)
	}
	if list.Issuer == "" {
		t.Fatal("revocation list: empty issuer")
	}
	if list.Sig == "" {
		t.Fatal("revocation list: not signed")
	}
	if len(list.Entries) == 0 {
		t.Fatal("revocation list: should have at least 1 entry")
	}
	t.Logf("revocation list: %d entries, signed by %s", len(list.Entries), list.Issuer)
	t.Log("revocation list: PASS")
}
