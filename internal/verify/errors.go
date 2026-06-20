// Package verify implements the ADTP 13-step verification algorithm
// (specification Section 11), proof-of-possession (Section 10), and the
// RESTATE-mode attenuation checks layered on the credential primitives.
package verify

import "fmt"

// ErrorCode is an internal verification or operational error code (the
// AGENT_ERR_V_* / AGENT_ERR_O_* taxonomy). External responses are reduced to the
// four codes returned by VerificationError.External (oracle minimization,
// Section 10.6); the detailed code is for audit only.
type ErrorCode string

// Verification errors (AGENT_ERR_V_*).
const (
	CodeSigInvalid      ErrorCode = "AGENT_ERR_V001_SIG_INVALID"
	CodeExpired         ErrorCode = "AGENT_ERR_V002_EXPIRED"
	CodeNotYetValid     ErrorCode = "AGENT_ERR_V003_NOT_YET_VALID"
	CodeRevoked         ErrorCode = "AGENT_ERR_V004_REVOKED"
	CodeSuspended       ErrorCode = "AGENT_ERR_V005_SUSPENDED"
	CodeCompromised     ErrorCode = "AGENT_ERR_V006_COMPROMISED"
	CodeCapInsufficient ErrorCode = "AGENT_ERR_V007_CAPABILITY_INSUFFICIENT"
	CodeAttenuation     ErrorCode = "AGENT_ERR_V008_ATTENUATION_VIOLATION"
	CodeChainBroken     ErrorCode = "AGENT_ERR_V009_CHAIN_BROKEN"
	CodeChainTooDeep    ErrorCode = "AGENT_ERR_V010_CHAIN_TOO_DEEP"
	CodeCircular        ErrorCode = "AGENT_ERR_V011_CIRCULAR_DELEGATION"
	CodeUntrustedRoot   ErrorCode = "AGENT_ERR_V012_UNTRUSTED_ROOT"
	CodeCrossOrg        ErrorCode = "AGENT_ERR_V013_CROSS_ORG_VIOLATION"
	CodePoPFailed       ErrorCode = "AGENT_ERR_V014_POP_FAILED"
	CodeExpiryEscalate  ErrorCode = "AGENT_ERR_V015_EXPIRY_ESCALATION"
	CodeBranching       ErrorCode = "AGENT_ERR_V016_BRANCHING_UNSUPPORTED"
	CodeMalformed       ErrorCode = "AGENT_ERR_V017_MALFORMED"
	CodeCIDMismatch     ErrorCode = "AGENT_ERR_V018_CID_MISMATCH"
	CodeUnregistered    ErrorCode = "AGENT_ERR_V019_UNREGISTERED"
)

// Operational errors (AGENT_ERR_O_*).
const (
	CodeRevocUnavailable ErrorCode = "AGENT_ERR_O001_REVOC_UNAVAILABLE"
	CodeDIDResolution    ErrorCode = "AGENT_ERR_O002_DID_RESOLUTION_FAILED"
	CodeClockSkew        ErrorCode = "AGENT_ERR_O003_CLOCK_SKEW"
	CodeProofCacheMiss   ErrorCode = "AGENT_ERR_O004_PROOF_CACHE_MISS"
	CodeKeyStorage       ErrorCode = "AGENT_ERR_O005_KEY_STORAGE_UNAVAILABLE"
	CodeTrustUnavailable ErrorCode = "AGENT_ERR_O006_TRUST_POLICY_UNAVAILABLE"
	CodeAuditUnavailable ErrorCode = "AGENT_ERR_O007_AUDIT_LOG_UNAVAILABLE"
)

// External response codes (Section 10.6).
const (
	ExtMalformed = "ADTP_MALFORMED"
	ExtDenied    = "ADTP_DENIED"
	ExtRevoked   = "ADTP_REVOKED"
	ExtRetry     = "ADTP_RETRY"
)

// VerificationError is a structured verification failure carrying the step at
// which it occurred and the internal AGENT_ERR code.
type VerificationError struct {
	Step   int
	Code   ErrorCode
	Detail string
	cause  error
}

func (e *VerificationError) Error() string {
	if e.Detail == "" {
		return fmt.Sprintf("adtp/verify: step %d: %s", e.Step, e.Code)
	}
	return fmt.Sprintf("adtp/verify: step %d: %s: %s", e.Step, e.Code, e.Detail)
}

func (e *VerificationError) Unwrap() error { return e.cause }

// External maps the internal code to one of the four external response codes
// (Section 10.6), which is all a relying party ever returns to the caller.
func (e *VerificationError) External() string {
	switch e.Code {
	case CodeMalformed, CodeChainBroken, CodeChainTooDeep, CodeCircular, CodeBranching, CodeCIDMismatch:
		return ExtMalformed
	case CodeRevoked, CodeSuspended, CodeCompromised:
		return ExtRevoked
	case CodeRevocUnavailable, CodeDIDResolution, CodeProofCacheMiss, CodeTrustUnavailable, CodeAuditUnavailable:
		return ExtRetry
	default:
		return ExtDenied
	}
}

// verr builds a VerificationError.
func verr(step int, code ErrorCode, cause error, format string, args ...any) *VerificationError {
	return &VerificationError{
		Step:   step,
		Code:   code,
		Detail: fmt.Sprintf(format, args...),
		cause:  cause,
	}
}

// RiskTier classifies the sensitivity of a requested action and drives
// channel-binding requirements and revocation-staleness bounds (Sections 7.7,
// 10.3, 13.4).
type RiskTier int

const (
	TierAnalytics RiskTier = iota
	TierLow
	TierMedium
	TierHigh
)

func (t RiskTier) String() string {
	switch t {
	case TierHigh:
		return "HIGH"
	case TierMedium:
		return "MEDIUM"
	case TierLow:
		return "LOW"
	default:
		return "ANALYTICS"
	}
}
