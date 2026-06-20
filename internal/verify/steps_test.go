package verify

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/Zahanturel/adtp/internal/credential"
	"github.com/Zahanturel/adtp/internal/delegation"
	"github.com/Zahanturel/adtp/internal/revocation"
)

func TestVerificationErrorExternal(t *testing.T) {
	cause := errors.New("underlying")
	e := verr(5, CodeExpired, cause, "expired at %d", 100)
	if e.Error() == "" {
		t.Errorf("empty Error()")
	}
	if !errors.Is(e, cause) {
		t.Errorf("Unwrap lost the cause")
	}
	if bare := verr(1, CodeMalformed, nil, ""); bare.Error() == "" {
		t.Errorf("empty Error() for detail-less error")
	}

	cases := map[ErrorCode]string{
		CodeMalformed:        ExtMalformed,
		CodeChainBroken:      ExtMalformed,
		CodeCircular:         ExtMalformed,
		CodeBranching:        ExtMalformed,
		CodeCIDMismatch:      ExtMalformed,
		CodeRevoked:          ExtRevoked,
		CodeSuspended:        ExtRevoked,
		CodeCompromised:      ExtRevoked,
		CodeRevocUnavailable: ExtRetry,
		CodeProofCacheMiss:   ExtRetry,
		CodeTrustUnavailable: ExtRetry,
		CodeExpired:          ExtDenied,
		CodeSigInvalid:       ExtDenied,
		CodePoPFailed:        ExtDenied,
		CodeAttenuation:      ExtDenied,
		CodeUntrustedRoot:    ExtDenied,
	}
	for code, want := range cases {
		if got := (&VerificationError{Code: code}).External(); got != want {
			t.Errorf("External(%s) = %s, want %s", code, got, want)
		}
	}
}

func TestRiskTierString(t *testing.T) {
	for tier, want := range map[RiskTier]string{
		TierHigh:      "HIGH",
		TierMedium:    "MEDIUM",
		TierLow:       "LOW",
		TierAnalytics: "ANALYTICS",
	} {
		if got := tier.String(); got != want {
			t.Errorf("%d.String() = %q, want %q", tier, got, want)
		}
	}
}

func TestMapChainError(t *testing.T) {
	cases := []struct {
		in   error
		want ErrorCode
	}{
		{delegation.ErrCircularChain, CodeCircular},
		{delegation.ErrChainTooDeep, CodeChainTooDeep},
		{delegation.ErrChainTooWide, CodeMalformed},
		{delegation.ErrBranchingUnsupported, CodeBranching},
		{delegation.ErrProofNotFound, CodeProofCacheMiss},
		{delegation.ErrModeMixing, CodeChainBroken},
		{delegation.ErrCIDMismatch, CodeCIDMismatch},
		{errors.New("unexpected"), CodeChainBroken},
	}
	for _, c := range cases {
		if got := mapChainError(c.in).Code; got != c.want {
			t.Errorf("mapChainError(%v) = %s, want %s", c.in, got, c.want)
		}
	}
}

func TestStatusError(t *testing.T) {
	cases := []struct {
		status revocation.RevocationStatus
		code   ErrorCode
		isNil  bool
	}{
		{revocation.StatusReinstated, "", true},
		{revocation.StatusRevoked, CodeRevoked, false},
		{revocation.StatusDecommissioned, CodeRevoked, false},
		{revocation.StatusSuspended, CodeSuspended, false},
		{revocation.StatusCompromised, CodeCompromised, false},
		{revocation.StatusCascade, CodeCompromised, false},
	}
	for _, c := range cases {
		e := statusError(c.status)
		if c.isNil {
			if e != nil {
				t.Errorf("statusError(%s) = %v, want nil", c.status, e)
			}
			continue
		}
		if e == nil || e.Code != c.code {
			t.Errorf("statusError(%s) = %v, want %s", c.status, e, c.code)
		}
	}
}

func TestEvaluateConstraint(t *testing.T) {
	base := InvocationContext{
		Resource:   "tool://s/x",
		Parameters: map[string]any{"method": "GET", "rows": 5},
		Now:        1000,
	}
	noMethod := InvocationContext{Resource: "tool://s/x", Parameters: map[string]any{}, Now: 1000}

	// metered mirrors base but with a metering/enforcement backend available.
	metered := base
	metered.MeteringEnabled = true

	// floatCtx carries JSON-style numeric params (float64), as the real
	// invocation path does.
	floatTrunc := InvocationContext{Parameters: map[string]any{"amount": float64(10.9)}, Now: 1000}
	floatOverflow := InvocationContext{Parameters: map[string]any{"amount": float64(1e30)}, Now: 1000}
	floatExact := InvocationContext{Parameters: map[string]any{"amount": float64(10)}, Now: 1000}
	floatNeg := InvocationContext{Parameters: map[string]any{"amount": float64(-5)}, Now: 1000}

	good := credential.TimeWindow{Start: 1, End: 2}
	tests := []struct {
		name    string
		c       credential.Constraint
		ctx     InvocationContext
		wantErr bool
	}{
		{"time_window within", credential.NewTimeWindow(500, 2000), base, false},
		{"time_window before start", credential.NewTimeWindow(2000, 3000), base, true},
		{"time_window at end is excluded", credential.NewTimeWindow(100, 1000), base, true},
		{"resource covered", credential.ResourceRestrictConstraint{Type: credential.ConstraintResourceRestrict, Resource: "tool://s/*"}, base, false},
		{"resource not covered", credential.ResourceRestrictConstraint{Type: credential.ConstraintResourceRestrict, Resource: "tool://s/y"}, base, true},
		{"method allowed", credential.MethodRestrictConstraint{Type: credential.ConstraintMethodRestrict, Methods: []string{"GET", "POST"}}, base, false},
		{"method denied", credential.MethodRestrictConstraint{Type: credential.ConstraintMethodRestrict, Methods: []string{"POST"}}, base, true},
		{"method missing", credential.MethodRestrictConstraint{Type: credential.ConstraintMethodRestrict, Methods: []string{"GET"}}, noMethod, true},
		{"param under limit", credential.ParamLimitConstraint{Type: credential.ConstraintParamLimit, Field: "rows", Max: 10}, base, false},
		{"param over limit", credential.ParamLimitConstraint{Type: credential.ConstraintParamLimit, Field: "rows", Max: 3}, base, true},
		{"param absent passes", credential.ParamLimitConstraint{Type: credential.ConstraintParamLimit, Field: "cols", Max: 3}, base, false},
		{"param non-numeric fails", credential.ParamLimitConstraint{Type: credential.ConstraintParamLimit, Field: "method", Max: 3}, base, true},
		// Fix 4: float params must be bounded honestly, not truncated/overflowed.
		{"param float truncation denied", credential.ParamLimitConstraint{Type: credential.ConstraintParamLimit, Field: "amount", Max: 10}, floatTrunc, true},
		{"param float overflow denied", credential.ParamLimitConstraint{Type: credential.ConstraintParamLimit, Field: "amount", Max: 10}, floatOverflow, true},
		{"param float exact allowed", credential.ParamLimitConstraint{Type: credential.ConstraintParamLimit, Field: "amount", Max: 10}, floatExact, false},
		{"param float negative allowed", credential.ParamLimitConstraint{Type: credential.ConstraintParamLimit, Field: "amount", Max: 10}, floatNeg, false},
		// Fix 5: cumulative/enforcement caveats fail closed without a backend.
		{"budget denied without metering", credential.BudgetConstraint{Type: credential.ConstraintBudget, Dim: "calls", Limit: 10, Scope: credential.BudgetScopeLeaf, Meter: credential.BudgetMeterVerifier}, base, true},
		{"budget allowed with metering", credential.BudgetConstraint{Type: credential.ConstraintBudget, Dim: "calls", Limit: 10, Scope: credential.BudgetScopeLeaf, Meter: credential.BudgetMeterVerifier}, metered, false},
		{"max_calls denied without metering", credential.MaxCallsConstraint{Type: credential.ConstraintMaxCalls, Limit: 10, Window: &good}, base, true},
		{"max_calls allowed with metering", credential.MaxCallsConstraint{Type: credential.ConstraintMaxCalls, Limit: 10, Window: &good}, metered, false},
		{"delegation_depth passes at verify", credential.DelegationDepthConstraint{Type: credential.ConstraintDelegationDepth, Max: 3}, base, false},
		{"parameter_schema denied without metering", credential.ParameterSchemaConstraint{Type: credential.ConstraintParameterSchema, Schema: json.RawMessage(`{"a":1}`)}, base, true},
		{"parameter_schema allowed with metering", credential.ParameterSchemaConstraint{Type: credential.ConstraintParameterSchema, Schema: json.RawMessage(`{"a":1}`)}, metered, false},
		{"unknown fails closed", credential.RawConstraint{TypeName: "exotic", Raw: json.RawMessage(`{"type":"exotic"}`)}, base, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := evaluateConstraint(tt.c, tt.ctx); (err != nil) != tt.wantErr {
				t.Errorf("evaluateConstraint = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNumericParam(t *testing.T) {
	cases := []struct {
		in   any
		want int64
		ok   bool
	}{
		{int(5), 5, true},
		{int64(7), 7, true},
		{float64(9), 9, true},
		{float64(-5), -5, true},
		{float64(10.9), 0, false}, // non-integer: fail closed (no truncation)
		{float64(1e30), 0, false}, // out of int64 range: fail closed (no overflow)
		{float64(-1e30), 0, false},
		{"x", 0, false},
		{nil, 0, false},
	}
	for _, c := range cases {
		got, ok := numericParam(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("numericParam(%v) = (%d, %v), want (%d, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

// errRevCache always fails the revocation lookup, to exercise step 6's
// fail-closed (HIGH) vs degrade-accept (lower tier) behavior.
type errRevCache struct{}

func (errRevCache) GetStatus(context.Context, string) (*revocation.RevocationEntry, error) {
	return nil, errors.New("revocation backend unavailable")
}

func TestStep6RevocationFailClosedAtHigh(t *testing.T) {
	chain := &delegation.Chain{Elements: []delegation.ChainElement{
		{Block: &credential.RestrictBlock{Aud: "did:key:zX", Exp: 100}, CID: "bafkreileaf", Mode: delegation.ModeRestrict},
	}}

	// HIGH tier: a lookup error must DENY (fail closed).
	if err := step6Revocation(context.Background(), chain, errRevCache{}, TierHigh, nil); err == nil {
		t.Errorf("HIGH tier with cache error = nil, want denial")
	} else if ve := asVErr(err); ve == nil || ve.Code != CodeRevocUnavailable {
		t.Errorf("HIGH tier error = %v, want O001 REVOC_UNAVAILABLE", err)
	}

	// MEDIUM tier: degrade-accept (fail open) — proceeds despite the error.
	if err := step6Revocation(context.Background(), chain, errRevCache{}, TierMedium, nil); err != nil {
		t.Errorf("MEDIUM tier with cache error = %v, want nil (degrade-accept)", err)
	}
}

func TestStep2Linkage(t *testing.T) {
	parent := delegation.ChainElement{
		Token: &credential.UCAN{Payload: credential.UCANPayload{
			Aud: "did:key:zAgent", Exp: 1000, Nbf: 100,
			Att: []credential.Capability{{
				Can: credential.CanAgentDelegate, With: "agent://p/a",
				Constraints: credential.Constraints{credential.DelegationDepthConstraint{Type: credential.ConstraintDelegationDepth, Max: 5}},
			}},
		}},
		CID: "parentCID", IsRoot: true, Mode: delegation.ModeRoot,
	}
	childBlock := func(mut func(*credential.RestrictBlock)) delegation.ChainElement {
		b := &credential.RestrictBlock{Iss: "did:key:zAgent", Prf: "parentCID", Exp: 1000, Nbf: 100, DL: 4}
		mut(b)
		return delegation.ChainElement{Block: b, CID: "childCID", Mode: delegation.ModeRestrict}
	}

	tests := []struct {
		name     string
		mutate   func(*credential.RestrictBlock)
		wantCode ErrorCode
		ok       bool
	}{
		{"valid", func(*credential.RestrictBlock) {}, "", true},
		{"iss mismatch", func(b *credential.RestrictBlock) { b.Iss = "did:key:zStranger" }, CodeChainBroken, false},
		{"prf mismatch", func(b *credential.RestrictBlock) { b.Prf = "other" }, CodeChainBroken, false},
		{"exp escalation", func(b *credential.RestrictBlock) { b.Exp = 2000 }, CodeExpiryEscalate, false},
		{"nbf regression", func(b *credential.RestrictBlock) { b.Nbf = 50 }, CodeChainBroken, false},
		{"dl not reduced", func(b *credential.RestrictBlock) { b.DL = 5 }, CodeAttenuation, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chain := &delegation.Chain{Elements: []delegation.ChainElement{childBlock(tt.mutate), parent}}
			err := step2Linkage(chain)
			if tt.ok {
				if err != nil {
					t.Errorf("step2Linkage(valid) = %v", err)
				}
				return
			}
			if got := asVErr(err); got == nil || got.Code != tt.wantCode {
				t.Errorf("step2Linkage = %v, want %s", err, tt.wantCode)
			}
		})
	}
}

func TestStep0Structural(t *testing.T) {
	tests := []struct {
		name    string
		element delegation.ChainElement
		wantErr bool
	}{
		{"valid block", delegation.ChainElement{Block: &credential.RestrictBlock{Exp: 100}, Mode: delegation.ModeRestrict}, false},
		{"missing expiry", delegation.ChainElement{Block: &credential.RestrictBlock{}, Mode: delegation.ModeRestrict}, true},
		{"unrecognized crit", delegation.ChainElement{Block: &credential.RestrictBlock{Exp: 100, Crit: []string{"x"}}, Mode: delegation.ModeRestrict}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chain := &delegation.Chain{Elements: []delegation.ChainElement{tt.element}}
			if err := step0Structural(chain); (err != nil) != tt.wantErr {
				t.Errorf("step0Structural = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAsVErrFallback(t *testing.T) {
	if asVErr(nil) != nil {
		t.Errorf("asVErr(nil) != nil")
	}
	if e := asVErr(errors.New("plain")); e == nil || e.Code != CodeMalformed {
		t.Errorf("asVErr(plain) = %v, want malformed wrapper", e)
	}
}

// stubRegStore is a minimal RegistrationChecker for step 11 tests.
type stubRegStore struct {
	registered map[string]bool
}

func (s *stubRegStore) Contains(_ context.Context, credentialCID, chainCID string) bool {
	return s.registered[credentialCID+"\x00"+chainCID]
}

func TestStep11RegistrationFailsClosedAtHigh(t *testing.T) {
	chain := &delegation.Chain{Elements: []delegation.ChainElement{
		{Block: &credential.RestrictBlock{Aud: "did:key:zX", Exp: 100}, CID: "bafkreileaf", Mode: delegation.ModeRestrict},
	}}
	store := &stubRegStore{registered: map[string]bool{}}
	err := step11Registration(context.Background(), chain, TierHigh, store, nil)
	if err == nil {
		t.Fatal("HIGH tier with unregistered leaf = nil, want denial")
	}
	if ve := asVErr(err); ve == nil || ve.Code != CodeUnregistered {
		t.Errorf("error = %v, want V019 UNREGISTERED", err)
	}
}

func TestStep11RegistrationDegradeAcceptsAtMedium(t *testing.T) {
	chain := &delegation.Chain{Elements: []delegation.ChainElement{
		{Block: &credential.RestrictBlock{Aud: "did:key:zX", Exp: 100}, CID: "bafkreileaf", Mode: delegation.ModeRestrict},
	}}
	store := &stubRegStore{registered: map[string]bool{}}
	if err := step11Registration(context.Background(), chain, TierMedium, store, nil); err != nil {
		t.Errorf("MEDIUM tier with unregistered leaf = %v, want nil (degrade-accept)", err)
	}
}

func TestStep11RegistrationPassesWhenRegistered(t *testing.T) {
	chain := &delegation.Chain{Elements: []delegation.ChainElement{
		{Block: &credential.RestrictBlock{Aud: "did:key:zX", Exp: 100}, CID: "bafkreileaf", Mode: delegation.ModeRestrict},
	}}
	store := &stubRegStore{registered: map[string]bool{"bafkreileaf\x00bafkreileaf": true}}
	if err := step11Registration(context.Background(), chain, TierHigh, store, nil); err != nil {
		t.Errorf("HIGH tier with registered leaf = %v, want nil", err)
	}
}

func TestStep11RegistrationNilStoreDegradeAccepts(t *testing.T) {
	chain := &delegation.Chain{Elements: []delegation.ChainElement{
		{Block: &credential.RestrictBlock{Aud: "did:key:zX", Exp: 100}, CID: "bafkreileaf", Mode: delegation.ModeRestrict},
	}}
	if err := step11Registration(context.Background(), chain, TierHigh, nil, nil); err != nil {
		t.Errorf("nil store = %v, want nil (degrade-accept)", err)
	}
}
