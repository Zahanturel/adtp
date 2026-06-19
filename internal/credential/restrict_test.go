package credential

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"

	"github.com/adtp/adtp/internal/identity"
)

func agentKeyDID(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	did, priv, err := identity.GenerateDID()
	if err != nil {
		t.Fatalf("GenerateDID: %v", err)
	}
	return priv, did
}

func sampleCaveats(t *testing.T) Constraints {
	t.Helper()
	return Constraints{
		NewTimeWindow(1000, 5000),
		ResourceRestrictConstraint{Type: ConstraintResourceRestrict, Resource: "tool://server/search"},
		MethodRestrictConstraint{Type: ConstraintMethodRestrict, Methods: []string{"GET"}},
	}
}

func delegableParent(t *testing.T, agentDID string) DelegationParent {
	t.Helper()
	return DelegationParent{
		CID: ComputeCID([]byte("parent-credential")),
		Aud: agentDID,
		Exp: 5000,
		Nbf: 1000,
		DL:  5,
	}
}

func TestCreateRestrictBlockValid(t *testing.T) {
	agentKey, agentDID := agentKeyDID(t)
	delegateDID := "did:key:zDelegate"
	parent := delegableParent(t, agentDID)

	block, raw, err := CreateRestrictBlock(parent, delegateDID, parent.DL-1, sampleCaveats(t), agentKey)
	if err != nil {
		t.Fatalf("CreateRestrictBlock: %v", err)
	}
	if block.Typ != RestrictBlockTyp {
		t.Errorf("typ = %q", block.Typ)
	}
	if block.Iss != agentDID {
		t.Errorf("iss = %q, want parent aud %q", block.Iss, agentDID)
	}
	if block.Aud != delegateDID {
		t.Errorf("aud = %q", block.Aud)
	}
	if block.Prf != parent.CID {
		t.Errorf("prf = %q, want %q", block.Prf, parent.CID)
	}
	if block.DL != parent.DL-1 {
		t.Errorf("dl = %d, want %d", block.DL, parent.DL-1)
	}

	// The signature verifies under the issuer's key.
	if err := block.Verify(agentKey.Public().(ed25519.PublicKey)); err != nil {
		t.Errorf("Verify: %v", err)
	}
	// And fails under a different key.
	otherKey, _ := agentKeyDID(t)
	if err := block.Verify(otherKey.Public().(ed25519.PublicKey)); err == nil {
		t.Errorf("Verify(wrong key) succeeded, want failure")
	}

	// The canonical bytes round-trip through the parser.
	parsed, err := ParseRestrictBlock(raw)
	if err != nil {
		t.Fatalf("ParseRestrictBlock: %v", err)
	}
	if parsed.Iss != block.Iss || parsed.Aud != block.Aud || parsed.DL != block.DL || len(parsed.Cav) != len(block.Cav) {
		t.Errorf("round-trip mismatch: %+v vs %+v", parsed, block)
	}
	if err := parsed.Verify(agentKey.Public().(ed25519.PublicKey)); err != nil {
		t.Errorf("parsed Verify: %v", err)
	}
}

func TestCreateRestrictBlockRejects(t *testing.T) {
	agentKey, agentDID := agentKeyDID(t)
	parent := delegableParent(t, agentDID)

	t.Run("zero caveats", func(t *testing.T) {
		_, _, err := CreateRestrictBlock(parent, "did:key:zB", parent.DL-1, Constraints{}, agentKey)
		if !errors.Is(err, ErrNoCaveats) {
			t.Errorf("err = %v, want ErrNoCaveats", err)
		}
	})
	t.Run("dl not decremented", func(t *testing.T) {
		_, _, err := CreateRestrictBlock(parent, "did:key:zB", parent.DL, sampleCaveats(t), agentKey)
		if !errors.Is(err, ErrDepthNotReduced) {
			t.Errorf("err = %v, want ErrDepthNotReduced", err)
		}
	})
	t.Run("dl above parent", func(t *testing.T) {
		_, _, err := CreateRestrictBlock(parent, "did:key:zB", parent.DL+1, sampleCaveats(t), agentKey)
		if !errors.Is(err, ErrDepthNotReduced) {
			t.Errorf("err = %v, want ErrDepthNotReduced", err)
		}
	})
	t.Run("bad signer key", func(t *testing.T) {
		_, _, err := CreateRestrictBlock(parent, "did:key:zB", parent.DL-1, sampleCaveats(t), ed25519.PrivateKey{1, 2, 3})
		if !errors.Is(err, ErrInvalidKey) {
			t.Errorf("err = %v, want ErrInvalidKey", err)
		}
	})
	t.Run("invalid caveat", func(t *testing.T) {
		bad := Constraints{ResourceRestrictConstraint{Type: ConstraintResourceRestrict, Resource: "TOOL://Server/X"}}
		_, _, err := CreateRestrictBlock(parent, "did:key:zB", parent.DL-1, bad, agentKey)
		if !errors.Is(err, ErrInvalidConstraint) {
			t.Errorf("err = %v, want ErrInvalidConstraint", err)
		}
	})
}

func TestRestrictBlockValidateAgainstParent(t *testing.T) {
	agentKey, agentDID := agentKeyDID(t)
	parent := delegableParent(t, agentDID)
	block, _, err := CreateRestrictBlock(parent, "did:key:zB", parent.DL-1, sampleCaveats(t), agentKey)
	if err != nil {
		t.Fatalf("CreateRestrictBlock: %v", err)
	}

	if err := block.ValidateAgainstParent(parent); err != nil {
		t.Errorf("ValidateAgainstParent(valid): %v", err)
	}

	tests := []struct {
		name    string
		mutate  func(b *RestrictBlock)
		wantErr error
	}{
		{"expiry escalation", func(b *RestrictBlock) { b.Exp = parent.Exp + 1 }, ErrExpiryEscalation},
		{"nbf regression", func(b *RestrictBlock) { b.Nbf = parent.Nbf - 1 }, ErrNotBeforeRegression},
		{"issuer mismatch", func(b *RestrictBlock) { b.Iss = "did:key:zStranger" }, ErrIssuerMismatch},
		{"dl not reduced", func(b *RestrictBlock) { b.DL = parent.DL }, ErrDepthNotReduced},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := *block
			tt.mutate(&b)
			if err := b.ValidateAgainstParent(parent); !errors.Is(err, tt.wantErr) {
				t.Errorf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseRestrictBlockMalformed(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{"not json", "not-json"},
		{"wrong typ", `{"typ":"aitp/ucan/1","iss":"a","aud":"b","prf":"c","sig":"d"}`},
		{"missing iss", `{"typ":"aitp/cav/1","aud":"b","prf":"c","sig":"d"}`},
		{"missing sig", `{"typ":"aitp/cav/1","iss":"a","aud":"b","prf":"c"}`},
		{"duplicate key", `{"typ":"aitp/cav/1","typ":"x","iss":"a","aud":"b","prf":"c","sig":"d"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseRestrictBlock([]byte(tt.raw)); err == nil {
				t.Errorf("ParseRestrictBlock(%s) = nil error, want failure", tt.raw)
			}
		})
	}
}

func TestCaveatRoundTrip(t *testing.T) {
	window := TimeWindow{Start: 1, End: 2}
	caveats := Constraints{
		NewTimeWindow(10, 20),
		ResourceRestrictConstraint{Type: ConstraintResourceRestrict, Resource: "tool://server/run"},
		MethodRestrictConstraint{Type: ConstraintMethodRestrict, Methods: []string{"GET", "POST"}},
		ParamLimitConstraint{Type: ConstraintParamLimit, Field: "rows", Max: 100},
		BudgetConstraint{Type: ConstraintBudget, Dim: "calls", Limit: 1000, Scope: BudgetScopeChain, Meter: BudgetMeterVerifier},
		MaxCallsConstraint{Type: ConstraintMaxCalls, Limit: 60, Window: &window},
		DelegationDepthConstraint{Type: ConstraintDelegationDepth, Max: 3},
	}
	encoded, err := json.Marshal(caveats)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded Constraints
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(decoded) != len(caveats) {
		t.Fatalf("decoded %d, want %d", len(decoded), len(caveats))
	}
	for i := range caveats {
		if decoded[i].Kind() != caveats[i].Kind() {
			t.Errorf("caveat %d kind = %q, want %q", i, decoded[i].Kind(), caveats[i].Kind())
		}
		if err := decoded[i].Validate(); err != nil {
			t.Errorf("caveat %d Validate: %v", i, err)
		}
	}
}

func TestNewCaveatValidate(t *testing.T) {
	tests := []struct {
		name    string
		c       Constraint
		wantErr bool
	}{
		{"resource_restrict ok", ResourceRestrictConstraint{Type: ConstraintResourceRestrict, Resource: "tool://s/x"}, false},
		{"resource_restrict non-canonical", ResourceRestrictConstraint{Type: ConstraintResourceRestrict, Resource: "TOOL://S/x"}, true},
		{"resource_restrict wrong type", ResourceRestrictConstraint{Type: "x", Resource: "tool://s/x"}, true},
		{"method_restrict ok", MethodRestrictConstraint{Type: ConstraintMethodRestrict, Methods: []string{"GET"}}, false},
		{"method_restrict empty", MethodRestrictConstraint{Type: ConstraintMethodRestrict}, true},
		{"max_calls ok", MaxCallsConstraint{Type: ConstraintMaxCalls, Limit: 10}, false},
		{"max_calls negative", MaxCallsConstraint{Type: ConstraintMaxCalls, Limit: -1}, true},
		{"delegation_depth ok", DelegationDepthConstraint{Type: ConstraintDelegationDepth, Max: 3}, false},
		{"delegation_depth negative", DelegationDepthConstraint{Type: ConstraintDelegationDepth, Max: -1}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.c.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("Validate() = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
