package postgres

import (
	"strings"
	"testing"

	"github.com/Zahanturel/adtp/internal/credential"
	"github.com/Zahanturel/adtp/internal/identity"
	"github.com/Zahanturel/adtp/store"
)

// Compile-time check that the real backend satisfies the unified interface.
var _ store.Store = (*PostgresStore)(nil)

func TestSchemaEmbedded(t *testing.T) {
	for _, want := range []string{
		"agents", "credentials", "registration_index", "revocation_entries", "audit_log",
		"idx_reg_chain_cid", "authority_proof",
		"UNIQUE (subject_cid, subject_did, seq)", // Fix 13 concurrency guard
	} {
		if !strings.Contains(Schema, want) {
			t.Errorf("embedded schema is missing %q", want)
		}
	}
}

func TestCredentialMeta(t *testing.T) {
	did, key, err := identity.GenerateDID()
	if err != nil {
		t.Fatalf("GenerateDID: %v", err)
	}
	token, err := credential.CreateUCAN(credential.UCANPayload{
		Iss: did, Aud: "did:key:zAud",
		Att: []credential.Capability{}, Prf: []string{}, Exp: 5000, Nbf: 1000, Iat: 1000,
	}, key)
	if err != nil {
		t.Fatalf("CreateUCAN: %v", err)
	}

	t.Run("ucan token", func(t *testing.T) {
		iss, aud, exp, err := credentialMeta([]byte(token))
		if err != nil || iss != did || aud != "did:key:zAud" || exp != 5000 {
			t.Errorf("credentialMeta(ucan) = (%q, %q, %d, %v)", iss, aud, exp, err)
		}
	})

	t.Run("restrict block", func(t *testing.T) {
		_, raw, err := credential.CreateRestrictBlock(
			credential.DelegationParent{CID: credential.ComputeCID([]byte(token)), Aud: did, Exp: 4000, Nbf: 1000, DL: 5},
			"did:key:zChild", 4, credential.Constraints{credential.NewTimeWindow(1000, 4000)}, key)
		if err != nil {
			t.Fatalf("CreateRestrictBlock: %v", err)
		}
		iss, aud, exp, err := credentialMeta(raw)
		if err != nil || iss != did || aud != "did:key:zChild" || exp != 4000 {
			t.Errorf("credentialMeta(block) = (%q, %q, %d, %v)", iss, aud, exp, err)
		}
	})

	t.Run("invalid", func(t *testing.T) {
		if _, _, _, err := credentialMeta([]byte("not a credential")); err == nil {
			t.Errorf("credentialMeta(garbage) = nil error, want failure")
		}
	})
}

func TestNewPostgresStoreInvalidDSN(t *testing.T) {
	// A malformed DSN fails at parse time, before any connection attempt.
	if _, err := NewPostgresStore("http://not-a-postgres-dsn"); err == nil {
		t.Errorf("NewPostgresStore(invalid) = nil error, want failure")
	}
}
