package adtp

import (
	"testing"

	"github.com/adtp/adtp/internal/verify"
)

func TestExternalCode(t *testing.T) {
	cases := []struct {
		code verify.ErrorCode
		want string
	}{
		{verify.CodeMalformed, CodeMalformed},
		{verify.CodeCircular, CodeMalformed},
		{verify.CodeChainBroken, CodeMalformed},
		{verify.CodeRevoked, CodeRevoked},
		{verify.CodeSuspended, CodeRevoked},
		{verify.CodeCompromised, CodeRevoked},
		{verify.CodeRevocUnavailable, CodeRetry},
		{verify.CodeProofCacheMiss, CodeRetry},
		{verify.CodeSigInvalid, CodeDenied},
		{verify.CodeExpired, CodeDenied},
		{verify.CodePoPFailed, CodeDenied},
		{verify.CodeCapInsufficient, CodeDenied},
	}
	for _, c := range cases {
		got := ExternalCode(&verify.VerificationError{Code: c.code})
		if got != c.want {
			t.Errorf("ExternalCode(%s) = %q, want %q", c.code, got, c.want)
		}
	}
}

func TestExternalCodeNil(t *testing.T) {
	if got := ExternalCode(nil); got != "" {
		t.Errorf("ExternalCode(nil) = %q, want empty", got)
	}
}
