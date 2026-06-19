// Package revocation implements the AITP revocation protocol (specification
// Section 13): the authority model, signed entries and lists, the cache the
// verifier consults, the explicit COMPROMISED cascade, and reconciliation.
package revocation

import (
	"errors"
	"fmt"
)

// RevocationAuthority is the basis on which a principal may revoke (Section 13.1).
type RevocationAuthority string

const (
	AuthPlatform  RevocationAuthority = "platform_root"
	AuthHopIssuer RevocationAuthority = "hop_issuer"
	AuthSubject   RevocationAuthority = "subject"
	AuthSponsor   RevocationAuthority = "sponsor"
)

// RevocationScope is the breadth of a revocation.
type RevocationScope string

const (
	ScopeCredential RevocationScope = "credential"
	ScopeSubtree    RevocationScope = "subtree"
	ScopeIdentity   RevocationScope = "identity"
)

// RevocationStatus is the status a revocation entry sets.
type RevocationStatus string

const (
	StatusRevoked        RevocationStatus = "REVOKED"
	StatusSuspended      RevocationStatus = "SUSPENDED"
	StatusReinstated     RevocationStatus = "REINSTATED"
	StatusCompromised    RevocationStatus = "COMPROMISED"
	StatusDecommissioned RevocationStatus = "DECOMMISSIONED"
	StatusCascade        RevocationStatus = "CASCADE"
)

// Authority-model errors.
var (
	ErrUnknownAuthority      = errors.New("unknown revocation authority")
	ErrStatusNotPermitted    = errors.New("authority may not set this status")
	ErrScopeNotPermitted     = errors.New("authority may not use this scope")
	ErrInsufficientAuthority = errors.New("reinstating authority is below the suspending authority")
)

// authorityStatuses lists the statuses each authority may set (Section 13.1).
var authorityStatuses = map[RevocationAuthority]map[RevocationStatus]struct{}{
	AuthPlatform: {
		StatusRevoked: {}, StatusSuspended: {}, StatusReinstated: {},
		StatusCompromised: {}, StatusDecommissioned: {}, StatusCascade: {},
	},
	AuthHopIssuer: {
		StatusRevoked: {}, StatusSuspended: {}, StatusReinstated: {},
	},
	AuthSubject: {
		StatusRevoked: {}, StatusCompromised: {},
	},
	AuthSponsor: {
		StatusRevoked: {}, StatusCompromised: {}, StatusDecommissioned: {},
	},
}

// authorityScopes lists the scopes each authority may use.
var authorityScopes = map[RevocationAuthority]map[RevocationScope]struct{}{
	AuthPlatform:  {ScopeCredential: {}, ScopeSubtree: {}, ScopeIdentity: {}},
	AuthHopIssuer: {ScopeCredential: {}, ScopeSubtree: {}},
	AuthSubject:   {ScopeCredential: {}, ScopeIdentity: {}},
	AuthSponsor:   {ScopeIdentity: {}},
}

// authorityRank orders authorities for reinstatement: platform > sponsor >
// hop issuer > subject (Section 13.3).
var authorityRank = map[RevocationAuthority]int{
	AuthSubject:   1,
	AuthHopIssuer: 2,
	AuthSponsor:   3,
	AuthPlatform:  4,
}

// ValidateAuthority reports whether authority may set status with scope.
func ValidateAuthority(authority RevocationAuthority, status RevocationStatus, scope RevocationScope) error {
	statuses, ok := authorityStatuses[authority]
	if !ok {
		return fmt.Errorf("aitp/revocation: %w: %q", ErrUnknownAuthority, authority)
	}
	if _, ok := statuses[status]; !ok {
		return fmt.Errorf("aitp/revocation: %w: %s may not set %s", ErrStatusNotPermitted, authority, status)
	}
	if _, ok := authorityScopes[authority][scope]; !ok {
		return fmt.Errorf("aitp/revocation: %w: %s may not use %s scope", ErrScopeNotPermitted, authority, scope)
	}
	return nil
}

// ValidateReinstatement reports whether reinstater is permitted to reinstate a
// suspension set by suspender — only an equal or higher authority may
// (Section 13.3).
func ValidateReinstatement(reinstater, suspender RevocationAuthority) error {
	rRank, ok := authorityRank[reinstater]
	if !ok {
		return fmt.Errorf("aitp/revocation: %w: %q", ErrUnknownAuthority, reinstater)
	}
	sRank, ok := authorityRank[suspender]
	if !ok {
		return fmt.Errorf("aitp/revocation: %w: %q", ErrUnknownAuthority, suspender)
	}
	if rRank < sRank {
		return fmt.Errorf("aitp/revocation: %w: %s < %s", ErrInsufficientAuthority, reinstater, suspender)
	}
	return nil
}
