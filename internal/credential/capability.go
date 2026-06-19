package credential

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/adtp/adtp/internal/signing"
)

// The five capability abilities. The set is closed per ucv (specification
// Section 7.1); adding a type requires a version bump.
const (
	CanToolInvoke    = "tool/invoke"
	CanResourceRead  = "resource/read"
	CanResourceWrite = "resource/write"
	CanAgentDelegate = "agent/delegate"
	CanAPICall       = "api/call"
)

var knownCapabilityTypes = map[string]struct{}{
	CanToolInvoke:    {},
	CanResourceRead:  {},
	CanResourceWrite: {},
	CanAgentDelegate: {},
	CanAPICall:       {},
}

// ValidCapabilityType reports whether can is one of the five abilities defined
// for this ucv.
func ValidCapabilityType(can string) bool {
	_, ok := knownCapabilityTypes[can]
	return ok
}

// Capability and constraint errors.
var (
	ErrUnknownCapabilityType  = errors.New("unknown capability type")
	ErrCapabilityNotCanonical = errors.New("capability 'with' URI is not canonical")
	ErrInvalidConstraint      = errors.New("invalid constraint")

	ErrInvalidURI             = errors.New("invalid capability URI")
	ErrInvalidScheme          = errors.New("invalid URI scheme")
	ErrNonASCIIHost           = errors.New("non-ASCII host must be supplied in punycode (A-label) form")
	ErrUserinfoNotAllowed     = errors.New("URI must not contain userinfo")
	ErrQueryOrFragment        = errors.New("capability URI must not carry a query or fragment")
	ErrEncodedSeparator       = errors.New("encoded path separator or NUL is not allowed")
	ErrDotSegment             = errors.New("dot-segment is not allowed in a capability URI path")
	ErrInvalidPercentEncoding = errors.New("invalid percent-encoding")
	ErrInvalidPort            = errors.New("invalid port")
)

// Capability is a single granted ability: an action (Can) over a resource
// identified by a canonical URI (With), optionally narrowed by constraints. In
// the att array a capability is a disjunction member (authorization matches any
// capability); constraints are conjunctive and evaluated at invocation time.
type Capability struct {
	Can         string      `json:"can"`
	With        string      `json:"with"`
	Constraints Constraints `json:"constraints,omitempty"`
}

// NewCapability builds a capability, canonicalizing the resource URI and
// validating the result.
func NewCapability(can, with string, constraints ...Constraint) (Capability, error) {
	canonical, err := CanonicalizeURI(with)
	if err != nil {
		return Capability{}, err
	}
	c := Capability{Can: can, With: canonical, Constraints: Constraints(constraints)}
	if err := c.Validate(); err != nil {
		return Capability{}, err
	}
	return c, nil
}

// Validate checks that the ability is known, the resource URI is already in
// canonical form, and every constraint is structurally valid.
func (c Capability) Validate() error {
	if !ValidCapabilityType(c.Can) {
		return fmt.Errorf("%w: %q", ErrUnknownCapabilityType, c.Can)
	}
	canonical, err := CanonicalizeURI(c.With)
	if err != nil {
		return fmt.Errorf("capability 'with': %w", err)
	}
	if canonical != c.With {
		return fmt.Errorf("%w: %q canonicalizes to %q", ErrCapabilityNotCanonical, c.With, canonical)
	}
	for i, con := range c.Constraints {
		if con == nil {
			return fmt.Errorf("%w: nil constraint at index %d", ErrInvalidConstraint, i)
		}
		if err := con.Validate(); err != nil {
			return fmt.Errorf("constraint %d (%s): %w", i, con.Kind(), err)
		}
	}
	return nil
}

// CanonicalizeURI applies the normative URI profile (specification Section 7.2)
// to a capability resource URI and returns its canonical form. The profile:
// lowercases scheme and host; removes default ports; rejects userinfo, query,
// and fragment; rejects encoded separators (%2F, %5C) and encoded NUL (%00);
// percent-decodes only unreserved characters and uppercases the hex of any
// remaining percent-encoding; and rejects dot-segments — including
// percent-encoded ones, because unreserved decoding runs before the dot-segment
// check. The function is idempotent: canonical input maps to itself.
//
// Non-ASCII hosts are rejected; they must be supplied in punycode (A-label)
// form. CanonicalizeURI requires the hierarchical "scheme://authority" form.
func CanonicalizeURI(raw string) (string, error) {
	sep := strings.Index(raw, "://")
	if sep <= 0 {
		return "", fmt.Errorf("%w: expected scheme://authority form", ErrInvalidURI)
	}
	scheme, err := canonicalScheme(raw[:sep])
	if err != nil {
		return "", err
	}
	rest := raw[sep+3:]
	if strings.ContainsAny(rest, "?#") {
		return "", fmt.Errorf("%w", ErrQueryOrFragment)
	}

	authority, path := rest, ""
	if slash := strings.IndexByte(rest, '/'); slash >= 0 {
		authority, path = rest[:slash], rest[slash:]
	}
	canonicalAuthority, err := canonicalAuthority(authority, scheme)
	if err != nil {
		return "", err
	}
	canonicalPath, err := canonicalPath(path)
	if err != nil {
		return "", err
	}
	return scheme + "://" + canonicalAuthority + canonicalPath, nil
}

func canonicalScheme(scheme string) (string, error) {
	if scheme == "" {
		return "", fmt.Errorf("%w: empty scheme", ErrInvalidScheme)
	}
	lower := strings.ToLower(scheme)
	for i := 0; i < len(lower); i++ {
		c := lower[i]
		switch {
		case c >= 'a' && c <= 'z':
		case i > 0 && (c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.'):
		default:
			return "", fmt.Errorf("%w: %q", ErrInvalidScheme, scheme)
		}
	}
	return lower, nil
}

func canonicalAuthority(authority, scheme string) (string, error) {
	if authority == "" {
		return "", fmt.Errorf("%w: empty authority", ErrInvalidURI)
	}
	if strings.ContainsRune(authority, '@') {
		return "", fmt.Errorf("%w", ErrUserinfoNotAllowed)
	}

	var host, port string
	if strings.HasPrefix(authority, "[") {
		end := strings.IndexByte(authority, ']')
		if end < 0 {
			return "", fmt.Errorf("%w: unterminated IPv6 literal", ErrInvalidURI)
		}
		host = authority[:end+1]
		if tail := authority[end+1:]; tail != "" {
			if tail[0] != ':' {
				return "", fmt.Errorf("%w: junk after IPv6 literal", ErrInvalidURI)
			}
			port = tail[1:]
		}
	} else if i := strings.LastIndexByte(authority, ':'); i >= 0 {
		host, port = authority[:i], authority[i+1:]
	} else {
		host = authority
	}

	host, err := canonicalHost(host)
	if err != nil {
		return "", err
	}
	port, err = canonicalPort(port, scheme)
	if err != nil {
		return "", err
	}
	if port == "" {
		return host, nil
	}
	return host + ":" + port, nil
}

func canonicalHost(host string) (string, error) {
	if host == "" {
		return "", fmt.Errorf("%w: empty host", ErrInvalidURI)
	}
	if strings.HasPrefix(host, "[") {
		// IPv6 literal: lowercase the hex; permit only hex digits, ':' and '.'.
		inner := host[1 : len(host)-1]
		if inner == "" {
			return "", fmt.Errorf("%w: empty IPv6 literal", ErrInvalidURI)
		}
		for i := 0; i < len(inner); i++ {
			c := inner[i]
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' || c == ':' || c == '.') {
				return "", fmt.Errorf("%w: bad IPv6 literal", ErrInvalidURI)
			}
		}
		return "[" + strings.ToLower(inner) + "]", nil
	}
	for i := 0; i < len(host); i++ {
		c := host[i]
		if c >= 0x80 {
			return "", fmt.Errorf("%w: %q", ErrNonASCIIHost, host)
		}
		if !isRegNameByte(c) {
			return "", fmt.Errorf("%w: illegal host character %q", ErrInvalidURI, c)
		}
	}
	return strings.ToLower(host), nil
}

func canonicalPort(port, scheme string) (string, error) {
	if port == "" {
		return "", nil
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 0 || n > 65535 {
		return "", fmt.Errorf("%w: %q", ErrInvalidPort, port)
	}
	if defaultPort(scheme) == n {
		return "", nil
	}
	return strconv.Itoa(n), nil
}

func defaultPort(scheme string) int {
	switch scheme {
	case "http", "ws":
		return 80
	case "https", "wss":
		return 443
	default:
		return -1
	}
}

func canonicalPath(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	// Reject encoded separators and encoded NUL before any decoding so they can
	// never re-enter the path as structural characters.
	lower := strings.ToLower(path)
	if strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") || strings.Contains(lower, "%00") {
		return "", fmt.Errorf("%w", ErrEncodedSeparator)
	}

	var b strings.Builder
	b.Grow(len(path))
	for i := 0; i < len(path); {
		c := path[i]
		if c == '%' {
			if i+2 >= len(path) {
				return "", fmt.Errorf("%w: truncated escape", ErrInvalidPercentEncoding)
			}
			hi, ok1 := fromHexDigit(path[i+1])
			lo, ok2 := fromHexDigit(path[i+2])
			if !ok1 || !ok2 {
				return "", fmt.Errorf("%w: %q", ErrInvalidPercentEncoding, path[i:i+3])
			}
			decoded := hi<<4 | lo
			if isUnreserved(decoded) {
				b.WriteByte(decoded)
			} else {
				b.WriteByte('%')
				b.WriteByte(upperHexDigits[hi])
				b.WriteByte(upperHexDigits[lo])
			}
			i += 3
			continue
		}
		if !isAllowedPathLiteral(c) {
			return "", fmt.Errorf("%w: illegal path character %q", ErrInvalidURI, c)
		}
		b.WriteByte(c)
		i++
	}

	decoded := b.String()
	for _, segment := range strings.Split(decoded, "/") {
		if segment == "." || segment == ".." {
			return "", fmt.Errorf("%w", ErrDotSegment)
		}
	}
	return decoded, nil
}

const upperHexDigits = "0123456789ABCDEF"

func fromHexDigit(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}

func isUnreserved(c byte) bool {
	return c >= 'A' && c <= 'Z' ||
		c >= 'a' && c <= 'z' ||
		c >= '0' && c <= '9' ||
		c == '-' || c == '.' || c == '_' || c == '~'
}

func isSubDelim(c byte) bool {
	switch c {
	case '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=':
		return true
	default:
		return false
	}
}

func isRegNameByte(c byte) bool {
	return isUnreserved(c) || isSubDelim(c)
}

// isAllowedPathLiteral reports whether c may appear literally (unencoded) in a
// path: the pchar set (unreserved, sub-delims, ':' and '@') plus the segment
// separator '/'. Everything else — spaces, control bytes, backslash, angle
// brackets — must be rejected or percent-encoded.
func isAllowedPathLiteral(c byte) bool {
	return isUnreserved(c) || isSubDelim(c) || c == ':' || c == '@' || c == '/'
}

// ConstraintType is the discriminator carried in a constraint's "type" member.
type ConstraintType string

// Constraint type discriminators.
const (
	ConstraintTimeWindow      ConstraintType = "time_window"
	ConstraintBudget          ConstraintType = "budget"
	ConstraintParamLimit      ConstraintType = "param_limit"
	ConstraintParameterSchema ConstraintType = "parameter_schema"
)

// Budget scope and meter values (specification Section 7.6).
const (
	BudgetScopeLeaf     = "leaf"
	BudgetScopeChain    = "chain"
	BudgetMeterVerifier = "verifier"
	BudgetMeterReceipts = "receipts"
)

// Constraint is one restriction on a capability or, equivalently, a caveat in a
// RESTRICT block. Constraints are conjunctive and evaluated against the
// invocation context at verification time. Every concrete constraint carries a
// "type" member; an unmodeled type round-trips through RawConstraint so that
// signatures over the enclosing object remain verifiable (SD-7).
type Constraint interface {
	// Kind returns the constraint's "type" discriminator.
	Kind() string
	// Validate reports whether the constraint is structurally well-formed.
	Validate() error
}

// TimeWindow is a half-open interval [Start, End) in integer UNIX seconds
// (specification Section 7.4). It is used both as a standalone constraint and as
// the window of a budget.
type TimeWindow struct {
	Start int64 `json:"start"`
	End   int64 `json:"end"`
}

// Validate reports whether the interval is well-formed and non-empty.
func (w TimeWindow) Validate() error {
	if w.Start < 0 || w.End < 0 {
		return fmt.Errorf("%w: time_window bounds must be non-negative", ErrInvalidConstraint)
	}
	if w.End <= w.Start {
		return fmt.Errorf("%w: time_window end (%d) must exceed start (%d)", ErrInvalidConstraint, w.End, w.Start)
	}
	return nil
}

// TimeWindowConstraint restricts a capability to a time interval.
type TimeWindowConstraint struct {
	Type ConstraintType `json:"type"`
	TimeWindow
}

// NewTimeWindow constructs a time_window constraint.
func NewTimeWindow(start, end int64) TimeWindowConstraint {
	return TimeWindowConstraint{Type: ConstraintTimeWindow, TimeWindow: TimeWindow{Start: start, End: end}}
}

func (c TimeWindowConstraint) Kind() string { return string(ConstraintTimeWindow) }

func (c TimeWindowConstraint) Validate() error {
	if c.Type != ConstraintTimeWindow {
		return fmt.Errorf("%w: time_window has type %q", ErrInvalidConstraint, c.Type)
	}
	return c.TimeWindow.Validate()
}

// BudgetConstraint meters cumulative authority along a delegation path
// (specification Section 7.6). A nil Window means the credential lifetime.
type BudgetConstraint struct {
	Type   ConstraintType `json:"type"`
	Dim    string         `json:"dim"`
	Limit  int64          `json:"limit"`
	Window *TimeWindow    `json:"window"`
	Scope  string         `json:"scope"`
	Meter  string         `json:"meter"`
}

func (c BudgetConstraint) Kind() string { return string(ConstraintBudget) }

func (c BudgetConstraint) Validate() error {
	if c.Type != ConstraintBudget {
		return fmt.Errorf("%w: budget has type %q", ErrInvalidConstraint, c.Type)
	}
	if c.Dim == "" {
		return fmt.Errorf("%w: budget dim is required", ErrInvalidConstraint)
	}
	if c.Limit < 0 {
		return fmt.Errorf("%w: budget limit must be non-negative", ErrInvalidConstraint)
	}
	switch c.Scope {
	case BudgetScopeLeaf, BudgetScopeChain:
	default:
		return fmt.Errorf("%w: budget scope %q", ErrInvalidConstraint, c.Scope)
	}
	switch c.Meter {
	case BudgetMeterVerifier, BudgetMeterReceipts:
	default:
		return fmt.Errorf("%w: budget meter %q", ErrInvalidConstraint, c.Meter)
	}
	if c.Window != nil {
		return c.Window.Validate()
	}
	return nil
}

// ParamLimitConstraint bounds a single invocation parameter — a per-invocation
// maximum, distinct from a cumulative budget (specification Section 7.6).
type ParamLimitConstraint struct {
	Type  ConstraintType `json:"type"`
	Field string         `json:"field"`
	Max   int64          `json:"max"`
}

func (c ParamLimitConstraint) Kind() string { return string(ConstraintParamLimit) }

func (c ParamLimitConstraint) Validate() error {
	if c.Type != ConstraintParamLimit {
		return fmt.Errorf("%w: param_limit has type %q", ErrInvalidConstraint, c.Type)
	}
	if c.Field == "" {
		return fmt.Errorf("%w: param_limit field is required", ErrInvalidConstraint)
	}
	if c.Max < 0 {
		return fmt.Errorf("%w: param_limit max must be non-negative", ErrInvalidConstraint)
	}
	return nil
}

// ParameterSchemaConstraint pins the shape of invocation parameters. In v0.x the
// comparison is deep equality over the schema object (specification Section
// 7.5); the schema bytes are preserved verbatim.
type ParameterSchemaConstraint struct {
	Type   ConstraintType  `json:"type"`
	Schema json.RawMessage `json:"schema"`
}

func (c ParameterSchemaConstraint) Kind() string { return string(ConstraintParameterSchema) }

func (c ParameterSchemaConstraint) Validate() error {
	if c.Type != ConstraintParameterSchema {
		return fmt.Errorf("%w: parameter_schema has type %q", ErrInvalidConstraint, c.Type)
	}
	if len(c.Schema) == 0 {
		return fmt.Errorf("%w: parameter_schema is required", ErrInvalidConstraint)
	}
	if err := signing.ValidateIJSON(c.Schema); err != nil {
		return fmt.Errorf("%w: parameter_schema: %v", ErrInvalidConstraint, err)
	}
	return nil
}

// RawConstraint preserves a constraint whose type this implementation does not
// model, so it round-trips byte-for-byte and signatures over the enclosing
// object stay verifiable. A verifier that cannot evaluate the constraint fails
// closed at verification time (specification Section 8.2).
type RawConstraint struct {
	TypeName string
	Raw      json.RawMessage
}

func (c RawConstraint) Kind() string { return c.TypeName }

func (c RawConstraint) Validate() error {
	if c.TypeName == "" {
		return fmt.Errorf("%w: constraint missing type", ErrInvalidConstraint)
	}
	return nil
}

func (c RawConstraint) MarshalJSON() ([]byte, error) {
	if len(c.Raw) == 0 {
		return nil, fmt.Errorf("%w: empty raw constraint", ErrInvalidConstraint)
	}
	return c.Raw, nil
}

// Constraints is an ordered constraint list with type-discriminated JSON
// encoding.
type Constraints []Constraint

// MarshalJSON encodes the list as a JSON array; each element carries its own
// "type" member.
func (cs Constraints) MarshalJSON() ([]byte, error) {
	if len(cs) == 0 {
		return []byte("[]"), nil
	}
	elems := make([]json.RawMessage, len(cs))
	for i, c := range cs {
		b, err := json.Marshal(c)
		if err != nil {
			return nil, err
		}
		elems[i] = b
	}
	return json.Marshal(elems)
}

// UnmarshalJSON decodes a JSON array of constraints, dispatching on each
// element's "type" member. Unknown types are preserved as RawConstraint.
func (cs *Constraints) UnmarshalJSON(data []byte) error {
	var elems []json.RawMessage
	if err := json.Unmarshal(data, &elems); err != nil {
		return fmt.Errorf("%w: constraints must be an array: %v", ErrInvalidConstraint, err)
	}
	out := make(Constraints, 0, len(elems))
	for _, el := range elems {
		c, err := unmarshalConstraint(el)
		if err != nil {
			return err
		}
		out = append(out, c)
	}
	*cs = out
	return nil
}

func unmarshalConstraint(data []byte) (Constraint, error) {
	var head struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &head); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidConstraint, err)
	}
	switch ConstraintType(head.Type) {
	case ConstraintTimeWindow:
		var c TimeWindowConstraint
		if err := json.Unmarshal(data, &c); err != nil {
			return nil, fmt.Errorf("%w: time_window: %v", ErrInvalidConstraint, err)
		}
		return c, nil
	case ConstraintBudget:
		var c BudgetConstraint
		if err := json.Unmarshal(data, &c); err != nil {
			return nil, fmt.Errorf("%w: budget: %v", ErrInvalidConstraint, err)
		}
		return c, nil
	case ConstraintParamLimit:
		var c ParamLimitConstraint
		if err := json.Unmarshal(data, &c); err != nil {
			return nil, fmt.Errorf("%w: param_limit: %v", ErrInvalidConstraint, err)
		}
		return c, nil
	case ConstraintParameterSchema:
		var c ParameterSchemaConstraint
		if err := json.Unmarshal(data, &c); err != nil {
			return nil, fmt.Errorf("%w: parameter_schema: %v", ErrInvalidConstraint, err)
		}
		return c, nil
	case ConstraintResourceRestrict:
		var c ResourceRestrictConstraint
		if err := json.Unmarshal(data, &c); err != nil {
			return nil, fmt.Errorf("%w: resource_restrict: %v", ErrInvalidConstraint, err)
		}
		return c, nil
	case ConstraintMethodRestrict:
		var c MethodRestrictConstraint
		if err := json.Unmarshal(data, &c); err != nil {
			return nil, fmt.Errorf("%w: method_restrict: %v", ErrInvalidConstraint, err)
		}
		return c, nil
	case ConstraintMaxCalls:
		var c MaxCallsConstraint
		if err := json.Unmarshal(data, &c); err != nil {
			return nil, fmt.Errorf("%w: max_calls: %v", ErrInvalidConstraint, err)
		}
		return c, nil
	case ConstraintDelegationDepth:
		var c DelegationDepthConstraint
		if err := json.Unmarshal(data, &c); err != nil {
			return nil, fmt.Errorf("%w: delegation_depth: %v", ErrInvalidConstraint, err)
		}
		return c, nil
	case "":
		return nil, fmt.Errorf("%w: constraint missing type", ErrInvalidConstraint)
	default:
		return RawConstraint{TypeName: head.Type, Raw: append(json.RawMessage(nil), data...)}, nil
	}
}
