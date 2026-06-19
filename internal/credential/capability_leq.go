package credential

import (
	"bytes"

	"github.com/adtp/adtp/internal/signing"
)

// CapabilityLeq reports whether child is less-than-or-equal-to (no broader than)
// parent: the RESTATE attenuation partial order (specification Sections 7.3,
// 7.4, 8.3). It holds iff the abilities are identical, the parent URI covers the
// child URI, and every constraint the parent imposes is matched by a child
// constraint that is at least as tight. The child may carry additional
// constraints — adding restrictions is always valid. A parent constraint of an
// unmodeled type is not comparable and fails closed.
//
// This comparison is the trusted-computing-base dependency of RESTATE
// delegation integrity (property P2, DEPENDENT). RESTRICT mode avoids it
// entirely by construction.
func CapabilityLeq(child, parent Capability) bool {
	if child.Can != parent.Can {
		return false
	}
	if !URICovers(parent.With, child.With) {
		return false
	}
	for _, pc := range parent.Constraints {
		if !childRefines(child.Constraints, pc) {
			return false
		}
	}
	return true
}

// childRefines reports whether some child constraint is at least as tight as the
// parent constraint pc.
func childRefines(childConstraints Constraints, pc Constraint) bool {
	for _, cc := range childConstraints {
		if constraintLeq(cc, pc) {
			return true
		}
	}
	return false
}

// constraintLeq reports whether child restricts at least as much as parent. The
// two must be the same kind and identify the same dimension (field, budget
// dimension, etc.); a type the comparison does not model fails closed.
func constraintLeq(child, parent Constraint) bool {
	switch p := parent.(type) {
	case TimeWindowConstraint:
		c, ok := child.(TimeWindowConstraint)
		return ok && c.Start >= p.Start && c.End <= p.End

	case BudgetConstraint:
		c, ok := child.(BudgetConstraint)
		if !ok || c.Dim != p.Dim || c.Limit > p.Limit {
			return false
		}
		return windowContained(c.Window, p.Window)

	case MaxCallsConstraint:
		c, ok := child.(MaxCallsConstraint)
		if !ok || c.Limit > p.Limit {
			return false
		}
		return windowContained(c.Window, p.Window)

	case ParamLimitConstraint:
		c, ok := child.(ParamLimitConstraint)
		return ok && c.Field == p.Field && c.Max <= p.Max

	case MethodRestrictConstraint:
		c, ok := child.(MethodRestrictConstraint)
		return ok && stringSubset(c.Methods, p.Methods)

	case ResourceRestrictConstraint:
		c, ok := child.(ResourceRestrictConstraint)
		return ok && URICovers(p.Resource, c.Resource)

	case DelegationDepthConstraint:
		c, ok := child.(DelegationDepthConstraint)
		// Delegation depth attenuates strictly (Section 7.5).
		return ok && c.Max < p.Max

	case ParameterSchemaConstraint:
		c, ok := child.(ParameterSchemaConstraint)
		// v0.x uses conservative deep equality over the canonicalized schema.
		return ok && schemaEqual(c.Schema, p.Schema)

	default:
		// Unknown parent constraint type: not comparable, fail closed.
		return false
	}
}

// windowContained reports whether the child window is contained in the parent
// window. A nil parent window means unbounded (the credential lifetime), which
// contains any child window; a nil child under a bounded parent is broader and
// therefore not contained.
func windowContained(child, parent *TimeWindow) bool {
	if parent == nil {
		return true
	}
	if child == nil {
		return false
	}
	return child.Start >= parent.Start && child.End <= parent.End
}

func stringSubset(child, parent []string) bool {
	set := make(map[string]struct{}, len(parent))
	for _, p := range parent {
		set[p] = struct{}{}
	}
	for _, c := range child {
		if _, ok := set[c]; !ok {
			return false
		}
	}
	return true
}

func schemaEqual(a, b []byte) bool {
	ca, err := signing.Canonicalize(a)
	if err != nil {
		return false
	}
	cb, err := signing.Canonicalize(b)
	if err != nil {
		return false
	}
	return bytes.Equal(ca, cb)
}

// CapabilitiesSubset reports whether every capability in childAtt is covered by
// some capability in parentAtt — the conjunctive-coverage requirement for
// RESTATE delegation (Section 7.8). Parent capabilities are indexed by
// (can, scheme, authority); because URICovers requires those to be equal, only
// capabilities sharing a key can cover one another, so the check is O(m) to
// build the index and O(n·k) to query rather than O(n·m).
func CapabilitiesSubset(childAtt, parentAtt []Capability) bool {
	index := make(map[string][]Capability, len(parentAtt))
	for _, p := range parentAtt {
		index[capabilityKey(p)] = append(index[capabilityKey(p)], p)
	}
	for _, c := range childAtt {
		covered := false
		for _, p := range index[capabilityKey(c)] {
			if CapabilityLeq(c, p) {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

// capabilityKey groups capabilities that could possibly cover one another. A
// URI that fails canonicalization yields a key that matches nothing, so an
// invalid capability is never treated as covering.
func capabilityKey(c Capability) string {
	canonical, err := CanonicalizeURI(c.With)
	if err != nil {
		return "\x00invalid\x00" + c.Can + "\x00" + c.With
	}
	scheme, authority, _, ok := splitCanonicalURI(canonical)
	if !ok {
		return "\x00invalid\x00" + c.Can + "\x00" + c.With
	}
	return c.Can + "\x00" + scheme + "\x00" + authority
}
