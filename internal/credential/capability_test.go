package credential

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/Zahanturel/adtp/internal/signing"
)

func TestCanonicalizeURI(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"lowercase scheme and host", "HTTPS://Example.COM/Foo", "https://example.com/Foo"},
		{"path case preserved", "tool://Server/RunTool", "tool://server/RunTool"},
		{"default https port removed", "https://example.com:443/x", "https://example.com/x"},
		{"default http port removed", "http://example.com:80/", "http://example.com/"},
		{"non-default port kept", "https://example.com:8443/x", "https://example.com:8443/x"},
		{"leading-zero default port removed", "https://example.com:0443/x", "https://example.com/x"},
		{"leading-zero port normalized", "tool://host:0080/x", "tool://host:80/x"},
		{"no path", "https://Example.com", "https://example.com"},
		{"authority only with default port", "https://Example.com:443", "https://example.com"},
		{"trailing slash significant", "https://example.com/a/b/", "https://example.com/a/b/"},
		{"root path", "https://example.com/", "https://example.com/"},
		{"unreserved percent decoded", "https://example.com/%41%42", "https://example.com/AB"},
		{"reserved percent kept and uppercased", "https://example.com/%2a", "https://example.com/%2A"},
		{"ipv6 literal lowercased and default port removed", "https://[2001:DB8::1]:443/x", "https://[2001:db8::1]/x"},
		{"sub-delims allowed literally", "https://example.com/a,b;c", "https://example.com/a,b;c"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CanonicalizeURI(tt.in)
			if err != nil {
				t.Fatalf("CanonicalizeURI(%q): %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("CanonicalizeURI(%q) = %q, want %q", tt.in, got, tt.want)
			}
			// Idempotence: the canonical form must canonicalize to itself.
			again, err := CanonicalizeURI(got)
			if err != nil {
				t.Fatalf("re-canonicalize %q: %v", got, err)
			}
			if again != got {
				t.Errorf("not idempotent: %q -> %q", got, again)
			}
		})
	}
}

func TestCanonicalizeURIErrors(t *testing.T) {
	nonASCIIHost := "https://ex" + string([]byte{0xc3, 0xa1}) + "mple.com/x"

	tests := []struct {
		name    string
		in      string
		wantErr error
	}{
		{"no scheme separator", "//example.com/x", ErrInvalidURI},
		{"empty scheme", "://example.com/x", ErrInvalidURI},
		{"empty authority", "https:///x", ErrInvalidURI},
		{"scheme with space", "ht tp://example.com/x", ErrInvalidScheme},
		{"scheme starts with digit", "1https://example.com/x", ErrInvalidScheme},
		{"query rejected", "https://example.com/a?b=c", ErrQueryOrFragment},
		{"fragment rejected", "https://example.com/a#f", ErrQueryOrFragment},
		{"userinfo rejected", "https://user@example.com/x", ErrUserinfoNotAllowed},
		{"non-ascii host", nonASCIIHost, ErrNonASCIIHost},
		{"encoded slash", "https://example.com/a%2Fb", ErrEncodedSeparator},
		{"encoded backslash", "https://example.com/a%5Cb", ErrEncodedSeparator},
		{"encoded nul", "https://example.com/a%00b", ErrEncodedSeparator},
		{"literal dot-dot segment", "https://example.com/../etc", ErrDotSegment},
		{"literal dot segment", "https://example.com/a/./b", ErrDotSegment},
		{"encoded dot-dot traversal", "https://example.com/%2e%2e/etc", ErrDotSegment},
		{"encoded dot segment", "https://example.com/%2e/b", ErrDotSegment},
		{"invalid percent hex", "https://example.com/%zz", ErrInvalidPercentEncoding},
		{"truncated percent", "https://example.com/a%4", ErrInvalidPercentEncoding},
		{"port out of range", "https://example.com:99999/x", ErrInvalidPort},
		{"non-numeric port", "https://example.com:abc/x", ErrInvalidPort},
		{"literal space in path", "https://example.com/a b", ErrInvalidURI},
		{"literal backslash in path", "https://example.com/a\\b", ErrInvalidURI},
		{"empty host with port", "https://:80/x", ErrInvalidURI},
		{"bad ipv6 literal", "https://[xyz]/x", ErrInvalidURI},
		{"unterminated ipv6 literal", "https://[::1/x", ErrInvalidURI},
		{"junk after ipv6 literal", "https://[::1]x/y", ErrInvalidURI},
		{"illegal host character", "https://exa<mple.com/x", ErrInvalidURI},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := CanonicalizeURI(tt.in)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("CanonicalizeURI(%q) error = %v, want errors.Is %v", tt.in, err, tt.wantErr)
			}
		})
	}
}

func TestNewCapability(t *testing.T) {
	c, err := NewCapability(CanToolInvoke, "TOOL://Server/Run")
	if err != nil {
		t.Fatalf("NewCapability: %v", err)
	}
	if c.Can != CanToolInvoke {
		t.Errorf("Can = %q", c.Can)
	}
	if c.With != "tool://server/Run" {
		t.Errorf("With = %q, want canonicalized tool://server/Run", c.With)
	}
	if err := c.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

func TestNewCapabilityErrors(t *testing.T) {
	if _, err := NewCapability("not/a/type", "https://example.com/x"); !errors.Is(err, ErrUnknownCapabilityType) {
		t.Errorf("unknown type error = %v, want ErrUnknownCapabilityType", err)
	}
	if _, err := NewCapability(CanAPICall, "https://example.com/a%2Fb"); !errors.Is(err, ErrEncodedSeparator) {
		t.Errorf("bad URI error = %v, want ErrEncodedSeparator", err)
	}
}

func TestCapabilityValidateRejectsNonCanonicalWith(t *testing.T) {
	c := Capability{Can: CanToolInvoke, With: "TOOL://Server/Run"}
	if err := c.Validate(); !errors.Is(err, ErrCapabilityNotCanonical) {
		t.Errorf("Validate(non-canonical) = %v, want ErrCapabilityNotCanonical", err)
	}
}

func TestConstraintRoundTrip(t *testing.T) {
	window := TimeWindow{Start: 100, End: 200}
	cs := Constraints{
		NewTimeWindow(100, 200),
		BudgetConstraint{Type: ConstraintBudget, Dim: "calls", Limit: 1000, Window: &window, Scope: BudgetScopeChain, Meter: BudgetMeterVerifier},
		ParamLimitConstraint{Type: ConstraintParamLimit, Field: "rows", Max: 50},
		ParameterSchemaConstraint{Type: ConstraintParameterSchema, Schema: json.RawMessage(`{"kind":"object"}`)},
	}

	encoded, err := json.Marshal(cs)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded Constraints
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(decoded) != len(cs) {
		t.Fatalf("decoded %d constraints, want %d", len(decoded), len(cs))
	}
	for i := range cs {
		if decoded[i].Kind() != cs[i].Kind() {
			t.Errorf("constraint %d kind = %q, want %q", i, decoded[i].Kind(), cs[i].Kind())
		}
		if err := decoded[i].Validate(); err != nil {
			t.Errorf("constraint %d Validate: %v", i, err)
		}
	}

	// Re-marshaling the decoded list must canonicalize identically.
	reencoded, err := json.Marshal(decoded)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	c1, _ := signing.Canonicalize(encoded)
	c2, _ := signing.Canonicalize(reencoded)
	if string(c1) != string(c2) {
		t.Errorf("round trip not stable\n first: %s\nsecond: %s", c1, c2)
	}
}

func TestConstraintUnknownTypePreserved(t *testing.T) {
	input := []byte(`[{"type":"future/constraint","weight":7,"label":"x"}]`)
	var cs Constraints
	if err := json.Unmarshal(input, &cs); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(cs) != 1 {
		t.Fatalf("got %d constraints", len(cs))
	}
	if cs[0].Kind() != "future/constraint" {
		t.Errorf("Kind = %q, want future/constraint", cs[0].Kind())
	}
	if _, ok := cs[0].(RawConstraint); !ok {
		t.Errorf("unknown constraint type = %T, want RawConstraint", cs[0])
	}

	// The unknown constraint must round-trip so signatures stay verifiable.
	out, err := json.Marshal(cs)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want, _ := signing.Canonicalize(input)
	got, _ := signing.Canonicalize(out)
	if string(got) != string(want) {
		t.Errorf("unknown constraint not preserved\n got: %s\nwant: %s", got, want)
	}
}

func TestConstraintUnmarshalErrors(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{"not an array", `{"type":"time_window"}`},
		{"missing type", `[{"limit":5}]`},
		{"time_window wrong field type", `[{"type":"time_window","start":"x","end":2}]`},
		{"budget wrong field type", `[{"type":"budget","limit":"lots"}]`},
		{"param_limit wrong field type", `[{"type":"param_limit","max":"big"}]`},
		{"type wrong json type", `[{"type":5}]`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cs Constraints
			if err := json.Unmarshal([]byte(tt.in), &cs); !errors.Is(err, ErrInvalidConstraint) {
				t.Errorf("Unmarshal(%s) = %v, want ErrInvalidConstraint", tt.in, err)
			}
		})
	}
}

func TestConstraintsMarshalEmpty(t *testing.T) {
	got, err := json.Marshal(Constraints{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(got) != "[]" {
		t.Errorf("marshal(empty) = %s, want []", got)
	}
}

func TestRawConstraintMarshalEmpty(t *testing.T) {
	if _, err := (RawConstraint{TypeName: "x"}).MarshalJSON(); !errors.Is(err, ErrInvalidConstraint) {
		t.Errorf("MarshalJSON(empty raw) = %v, want ErrInvalidConstraint", err)
	}
}

func TestTimeWindowConstraintWrongType(t *testing.T) {
	c := TimeWindowConstraint{Type: "not_time_window", TimeWindow: TimeWindow{Start: 1, End: 2}}
	if err := c.Validate(); !errors.Is(err, ErrInvalidConstraint) {
		t.Errorf("Validate(wrong type) = %v, want ErrInvalidConstraint", err)
	}
}

func TestCapabilityValidateNilConstraint(t *testing.T) {
	c := Capability{Can: CanToolInvoke, With: "tool://server/run", Constraints: Constraints{nil}}
	if err := c.Validate(); !errors.Is(err, ErrInvalidConstraint) {
		t.Errorf("Validate(nil constraint) = %v, want ErrInvalidConstraint", err)
	}
}

func TestConstraintValidate(t *testing.T) {
	good := TimeWindow{Start: 1, End: 2}
	tests := []struct {
		name    string
		c       Constraint
		wantErr bool
	}{
		{"time_window ok", NewTimeWindow(1, 2), false},
		{"time_window empty interval", NewTimeWindow(5, 5), true},
		{"time_window reversed", NewTimeWindow(5, 1), true},
		{"time_window negative", NewTimeWindow(-1, 2), true},
		{"budget ok", BudgetConstraint{Type: ConstraintBudget, Dim: "calls", Limit: 1, Window: &good, Scope: BudgetScopeLeaf, Meter: BudgetMeterReceipts}, false},
		{"budget missing dim", BudgetConstraint{Type: ConstraintBudget, Limit: 1, Scope: BudgetScopeLeaf, Meter: BudgetMeterReceipts}, true},
		{"budget bad scope", BudgetConstraint{Type: ConstraintBudget, Dim: "calls", Limit: 1, Scope: "galaxy", Meter: BudgetMeterReceipts}, true},
		{"budget bad meter", BudgetConstraint{Type: ConstraintBudget, Dim: "calls", Limit: 1, Scope: BudgetScopeLeaf, Meter: "vibes"}, true},
		{"budget negative limit", BudgetConstraint{Type: ConstraintBudget, Dim: "calls", Limit: -1, Scope: BudgetScopeLeaf, Meter: BudgetMeterReceipts}, true},
		{"param_limit ok", ParamLimitConstraint{Type: ConstraintParamLimit, Field: "rows", Max: 10}, false},
		{"param_limit missing field", ParamLimitConstraint{Type: ConstraintParamLimit, Max: 10}, true},
		{"param_limit negative max", ParamLimitConstraint{Type: ConstraintParamLimit, Field: "rows", Max: -1}, true},
		{"parameter_schema ok", ParameterSchemaConstraint{Type: ConstraintParameterSchema, Schema: json.RawMessage(`{"a":1}`)}, false},
		{"parameter_schema empty", ParameterSchemaConstraint{Type: ConstraintParameterSchema}, true},
		{"parameter_schema invalid json", ParameterSchemaConstraint{Type: ConstraintParameterSchema, Schema: json.RawMessage(`{bad}`)}, true},
		{"raw ok", RawConstraint{TypeName: "x", Raw: json.RawMessage(`{"type":"x"}`)}, false},
		{"raw missing type name", RawConstraint{Raw: json.RawMessage(`{}`)}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.c.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCapabilityJSONShape(t *testing.T) {
	c, err := NewCapability(CanResourceRead, "resource://store/items", NewTimeWindow(10, 20))
	if err != nil {
		t.Fatalf("NewCapability: %v", err)
	}
	got, err := signing.CanonicalizeValue(c)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	want := `{"can":"resource/read","constraints":[{"end":20,"start":10,"type":"time_window"}],"with":"resource://store/items"}`
	if string(got) != want {
		t.Errorf("capability JSON\n got: %s\nwant: %s", got, want)
	}
}

func TestCapabilityOmitsEmptyConstraints(t *testing.T) {
	c, err := NewCapability(CanToolInvoke, "tool://server/run")
	if err != nil {
		t.Fatalf("NewCapability: %v", err)
	}
	got, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if want := `{"can":"tool/invoke","with":"tool://server/run"}`; string(got) != want {
		t.Errorf("marshal\n got: %s\nwant: %s", got, want)
	}
}
