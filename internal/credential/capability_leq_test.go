package credential

import (
	"encoding/json"
	"testing"
)

func cap(t *testing.T, can, with string, constraints ...Constraint) Capability {
	t.Helper()
	c, err := NewCapability(can, with, constraints...)
	if err != nil {
		t.Fatalf("NewCapability(%q,%q): %v", can, with, err)
	}
	return c
}

func TestCapabilityLeq(t *testing.T) {
	tests := []struct {
		name   string
		child  Capability
		parent Capability
		want   bool
	}{
		{
			"identical",
			cap(t, CanToolInvoke, "tool://s/run"),
			cap(t, CanToolInvoke, "tool://s/run"),
			true,
		},
		{
			"different ability",
			cap(t, CanResourceRead, "tool://s/run"),
			cap(t, CanToolInvoke, "tool://s/run"),
			false,
		},
		{
			"wildcard narrowed by child",
			cap(t, CanToolInvoke, "tool://s/run"),
			cap(t, CanToolInvoke, "tool://s/*"),
			true,
		},
		{
			"child widens beyond parent",
			cap(t, CanToolInvoke, "tool://s/a/b"),
			cap(t, CanToolInvoke, "tool://s/*"),
			false,
		},
		{
			"child adds a constraint (more restrictive)",
			cap(t, CanToolInvoke, "tool://s/run", NewTimeWindow(100, 200)),
			cap(t, CanToolInvoke, "tool://s/run"),
			true,
		},
		{
			"child tightens time window",
			cap(t, CanToolInvoke, "tool://s/run", NewTimeWindow(120, 180)),
			cap(t, CanToolInvoke, "tool://s/run", NewTimeWindow(100, 200)),
			true,
		},
		{
			"child loosens time window",
			cap(t, CanToolInvoke, "tool://s/run", NewTimeWindow(50, 250)),
			cap(t, CanToolInvoke, "tool://s/run", NewTimeWindow(100, 200)),
			false,
		},
		{
			"child drops a parent constraint",
			cap(t, CanToolInvoke, "tool://s/run"),
			cap(t, CanToolInvoke, "tool://s/run", NewTimeWindow(100, 200)),
			false,
		},
		{
			"method subset",
			cap(t, CanAPICall, "https://h/x", MethodRestrictConstraint{Type: ConstraintMethodRestrict, Methods: []string{"GET"}}),
			cap(t, CanAPICall, "https://h/x", MethodRestrictConstraint{Type: ConstraintMethodRestrict, Methods: []string{"GET", "POST"}}),
			true,
		},
		{
			"method superset",
			cap(t, CanAPICall, "https://h/x", MethodRestrictConstraint{Type: ConstraintMethodRestrict, Methods: []string{"GET", "DELETE"}}),
			cap(t, CanAPICall, "https://h/x", MethodRestrictConstraint{Type: ConstraintMethodRestrict, Methods: []string{"GET", "POST"}}),
			false,
		},
		{
			"param_limit tighter",
			cap(t, CanResourceRead, "resource://db/x", ParamLimitConstraint{Type: ConstraintParamLimit, Field: "rows", Max: 10}),
			cap(t, CanResourceRead, "resource://db/x", ParamLimitConstraint{Type: ConstraintParamLimit, Field: "rows", Max: 100}),
			true,
		},
		{
			"param_limit looser",
			cap(t, CanResourceRead, "resource://db/x", ParamLimitConstraint{Type: ConstraintParamLimit, Field: "rows", Max: 1000}),
			cap(t, CanResourceRead, "resource://db/x", ParamLimitConstraint{Type: ConstraintParamLimit, Field: "rows", Max: 100}),
			false,
		},
		{
			"unknown parent constraint fails closed",
			cap(t, CanToolInvoke, "tool://s/run", RawConstraint{TypeName: "exotic", Raw: json.RawMessage(`{"type":"exotic"}`)}),
			cap(t, CanToolInvoke, "tool://s/run", RawConstraint{TypeName: "exotic", Raw: json.RawMessage(`{"type":"exotic"}`)}),
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CapabilityLeq(tt.child, tt.parent); got != tt.want {
				t.Errorf("CapabilityLeq = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestWindowContained covers the budget/max_calls window-containment predicate
// (Fix 14: previously 0% covered).
func TestWindowContained(t *testing.T) {
	w := func(s, e int64) *TimeWindow { return &TimeWindow{Start: s, End: e} }
	cases := []struct {
		name          string
		child, parent *TimeWindow
		want          bool
	}{
		{"parent unbounded contains bounded child", w(100, 200), nil, true},
		{"parent unbounded contains nil child", nil, nil, true},
		{"bounded parent rejects unbounded child", nil, w(100, 200), false},
		{"contained", w(120, 180), w(100, 200), true},
		{"equal", w(100, 200), w(100, 200), true},
		{"child starts before parent", w(90, 180), w(100, 200), false},
		{"child ends after parent", w(120, 210), w(100, 200), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := windowContained(c.child, c.parent); got != c.want {
				t.Errorf("windowContained = %v, want %v", got, c.want)
			}
		})
	}
}

// TestSchemaEqual covers the parameter_schema deep-equality predicate (Fix 14:
// previously 0% covered), including canonicalization and invalid-JSON handling.
func TestSchemaEqual(t *testing.T) {
	cases := []struct {
		name string
		a, b string
		want bool
	}{
		{"identical", `{"a":1}`, `{"a":1}`, true},
		{"reordered keys canonicalize equal", `{"a":1,"b":2}`, `{"b":2,"a":1}`, true},
		{"whitespace insignificant", `{ "a" : 1 }`, `{"a":1}`, true},
		{"different value", `{"a":1}`, `{"a":2}`, false},
		{"invalid left", `{bad}`, `{"a":1}`, false},
		{"invalid right", `{"a":1}`, `{bad}`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := schemaEqual([]byte(c.a), []byte(c.b)); got != c.want {
				t.Errorf("schemaEqual = %v, want %v", got, c.want)
			}
		})
	}
}

// TestConstraintLeqBudgetAndSchema exercises constraintLeq through CapabilityLeq
// for budget (window containment) and parameter_schema (deep equality).
func TestConstraintLeqBudgetAndSchema(t *testing.T) {
	budget := func(limit int64, win *TimeWindow) BudgetConstraint {
		return BudgetConstraint{Type: ConstraintBudget, Dim: "calls", Limit: limit, Window: win, Scope: BudgetScopeChain, Meter: BudgetMeterVerifier}
	}
	schema := func(s string) ParameterSchemaConstraint {
		return ParameterSchemaConstraint{Type: ConstraintParameterSchema, Schema: json.RawMessage(s)}
	}
	win := &TimeWindow{Start: 100, End: 200}

	tests := []struct {
		name          string
		child, parent Capability
		want          bool
	}{
		{"budget tighter limit + contained window",
			cap(t, CanAPICall, "https://h/x", budget(10, &TimeWindow{Start: 120, End: 180})),
			cap(t, CanAPICall, "https://h/x", budget(100, win)), true},
		{"budget window not contained",
			cap(t, CanAPICall, "https://h/x", budget(10, &TimeWindow{Start: 50, End: 180})),
			cap(t, CanAPICall, "https://h/x", budget(100, win)), false},
		{"budget limit too high",
			cap(t, CanAPICall, "https://h/x", budget(1000, &TimeWindow{Start: 120, End: 180})),
			cap(t, CanAPICall, "https://h/x", budget(100, win)), false},
		{"parameter_schema equal",
			cap(t, CanAPICall, "https://h/x", schema(`{"a":1}`)),
			cap(t, CanAPICall, "https://h/x", schema(`{"a":1}`)), true},
		{"parameter_schema differs",
			cap(t, CanAPICall, "https://h/x", schema(`{"a":1}`)),
			cap(t, CanAPICall, "https://h/x", schema(`{"a":2}`)), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CapabilityLeq(tt.child, tt.parent); got != tt.want {
				t.Errorf("CapabilityLeq = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCapabilitiesSubset(t *testing.T) {
	parent := []Capability{
		cap(t, CanToolInvoke, "tool://s/*"),
		cap(t, CanResourceRead, "resource://db/customers"),
	}

	t.Run("valid subset", func(t *testing.T) {
		child := []Capability{
			cap(t, CanToolInvoke, "tool://s/search"),
			cap(t, CanResourceRead, "resource://db/customers"),
		}
		if !CapabilitiesSubset(child, parent) {
			t.Errorf("expected subset")
		}
	})

	t.Run("escalation: capability not in parent", func(t *testing.T) {
		child := []Capability{
			cap(t, CanResourceWrite, "resource://db/customers"),
		}
		if CapabilitiesSubset(child, parent) {
			t.Errorf("write capability should not be covered by read-only parent")
		}
	})

	t.Run("escalation: resource outside wildcard", func(t *testing.T) {
		child := []Capability{
			cap(t, CanToolInvoke, "tool://s/a/b"),
		}
		if CapabilitiesSubset(child, parent) {
			t.Errorf("two-segment resource should not be covered by single wildcard")
		}
	})

	t.Run("empty child", func(t *testing.T) {
		if !CapabilitiesSubset(nil, parent) {
			t.Errorf("empty child is trivially a subset")
		}
	})
}
