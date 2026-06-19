package revocation

import (
	"errors"
	"testing"
)

func TestValidateAuthority(t *testing.T) {
	tests := []struct {
		name      string
		authority RevocationAuthority
		status    RevocationStatus
		scope     RevocationScope
		wantErr   error
	}{
		{"platform any status credential", AuthPlatform, StatusRevoked, ScopeCredential, nil},
		{"platform compromised identity", AuthPlatform, StatusCompromised, ScopeIdentity, nil},
		{"platform cascade subtree", AuthPlatform, StatusCascade, ScopeSubtree, nil},
		{"platform decommissioned identity", AuthPlatform, StatusDecommissioned, ScopeIdentity, nil},

		{"hop issuer revoked subtree", AuthHopIssuer, StatusRevoked, ScopeSubtree, nil},
		{"hop issuer suspended credential", AuthHopIssuer, StatusSuspended, ScopeCredential, nil},
		{"hop issuer reinstated subtree", AuthHopIssuer, StatusReinstated, ScopeSubtree, nil},
		{"hop issuer cannot compromise", AuthHopIssuer, StatusCompromised, ScopeCredential, ErrStatusNotPermitted},
		{"hop issuer cannot use identity scope", AuthHopIssuer, StatusRevoked, ScopeIdentity, ErrScopeNotPermitted},
		{"hop issuer cannot decommission", AuthHopIssuer, StatusDecommissioned, ScopeSubtree, ErrStatusNotPermitted},

		{"subject revoked credential", AuthSubject, StatusRevoked, ScopeCredential, nil},
		{"subject compromised identity", AuthSubject, StatusCompromised, ScopeIdentity, nil},
		{"subject cannot suspend", AuthSubject, StatusSuspended, ScopeCredential, ErrStatusNotPermitted},
		{"subject cannot use subtree", AuthSubject, StatusRevoked, ScopeSubtree, ErrScopeNotPermitted},

		{"sponsor decommissioned identity", AuthSponsor, StatusDecommissioned, ScopeIdentity, nil},
		{"sponsor compromised identity", AuthSponsor, StatusCompromised, ScopeIdentity, nil},
		{"sponsor cannot use credential scope", AuthSponsor, StatusRevoked, ScopeCredential, ErrScopeNotPermitted},
		{"sponsor cannot suspend", AuthSponsor, StatusSuspended, ScopeIdentity, ErrStatusNotPermitted},

		{"unknown authority", RevocationAuthority("alien"), StatusRevoked, ScopeCredential, ErrUnknownAuthority},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAuthority(tt.authority, tt.status, tt.scope)
			if tt.wantErr == nil {
				if err != nil {
					t.Errorf("ValidateAuthority = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("ValidateAuthority = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateReinstatement(t *testing.T) {
	tests := []struct {
		name       string
		reinstater RevocationAuthority
		suspender  RevocationAuthority
		wantErr    error
	}{
		{"platform reinstates hop issuer", AuthPlatform, AuthHopIssuer, nil},
		{"platform reinstates subject", AuthPlatform, AuthSubject, nil},
		{"sponsor reinstates hop issuer", AuthSponsor, AuthHopIssuer, nil},
		{"equal authority", AuthHopIssuer, AuthHopIssuer, nil},
		{"subject cannot reinstate platform", AuthSubject, AuthPlatform, ErrInsufficientAuthority},
		{"hop issuer cannot reinstate sponsor", AuthHopIssuer, AuthSponsor, ErrInsufficientAuthority},
		{"unknown reinstater", RevocationAuthority("alien"), AuthSubject, ErrUnknownAuthority},
		{"unknown suspender", AuthPlatform, RevocationAuthority("alien"), ErrUnknownAuthority},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateReinstatement(tt.reinstater, tt.suspender)
			if tt.wantErr == nil {
				if err != nil {
					t.Errorf("ValidateReinstatement = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("ValidateReinstatement = %v, want %v", err, tt.wantErr)
			}
		})
	}
}
