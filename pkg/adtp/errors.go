package adtp

import "github.com/adtp/adtp/internal/verify"

// External error codes (specification Section 10.6, oracle minimization). A
// relying party never reveals the internal per-step reason.
const (
	CodeMalformed = "ADTP_MALFORMED"
	CodeDenied    = "ADTP_DENIED"
	CodeRevoked   = "ADTP_REVOKED"
	CodeRetry     = "ADTP_RETRY"
)

// ExternalCode maps an internal verification error to its external,
// oracle-minimized code.
func ExternalCode(verr *verify.VerificationError) string {
	if verr == nil {
		return ""
	}
	switch verr.External() {
	case verify.ExtMalformed:
		return CodeMalformed
	case verify.ExtRevoked:
		return CodeRevoked
	case verify.ExtRetry:
		return CodeRetry
	default:
		return CodeDenied
	}
}
