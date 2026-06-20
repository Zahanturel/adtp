package verify

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	"github.com/Zahanturel/adtp/internal/audit"
	"github.com/Zahanturel/adtp/internal/credential"
	"github.com/Zahanturel/adtp/internal/delegation"
	"github.com/Zahanturel/adtp/internal/revocation"
	"github.com/Zahanturel/adtp/internal/signing"
)

// forgeBlock signs and stores a RestrictBlock without issuance-time validation,
// simulating an attacker who holds the signing key and crafts arbitrary payloads.
func forgeBlock(t *testing.T, block *credential.RestrictBlock, key ed25519.PrivateKey, store *delegation.MemoryProofStore) string {
	t.Helper()
	sig, err := signing.Sign(block, key)
	if err != nil {
		t.Fatalf("forge sign: %v", err)
	}
	block.Sig = signing.EncodeSignature(sig)
	raw, err := signing.CanonicalizeValue(block)
	if err != nil {
		t.Fatalf("forge canonicalize: %v", err)
	}
	return store.Put(raw)
}

// advRoot creates a root UCAN with delegation and tool capabilities and returns
// everything needed to construct adversarial child blocks against it.
type advRoot struct {
	store       *delegation.MemoryProofStore
	config      *VerifierConfig
	rootCID     string
	agentKey    ed25519.PrivateKey
	agentDID    string
	leafKey     ed25519.PrivateKey
	leafDID     string
	verifierDID string
	now         int64
}

func newAdvRoot(t *testing.T) *advRoot {
	t.Helper()
	now := time.Now().Unix()
	store := delegation.NewMemoryProofStore()

	platformKey, platformDID := genKey(t)
	agentKey, agentDID := genKey(t)
	leafKey, leafDID := genKey(t)
	_, verifierDID := genKey(t)

	delegateCap := vcap(t, credential.CanAgentDelegate, "agent://platform/agents",
		credential.DelegationDepthConstraint{Type: credential.ConstraintDelegationDepth, Max: 5})
	toolCap := vcap(t, credential.CanToolInvoke, "tool://server/*")

	rootToken, err := credential.CreateUCAN(credential.UCANPayload{
		Iss: platformDID, Aud: agentDID,
		Att: []credential.Capability{delegateCap, toolCap},
		Prf: []string{}, Exp: now + 3600, Nbf: now - 60, Iat: now,
	}, platformKey)
	if err != nil {
		t.Fatalf("CreateUCAN: %v", err)
	}
	rootCID := store.Put([]byte(rootToken))

	config := &VerifierConfig{
		VerifierDID:     verifierDID,
		TrustedRootDIDs: map[string]bool{platformDID: true},
		MaxChainDepth:   10,
		ProofStore:      store,
		NonceCache:      NewMemoryNonceCache(),
		RevocationCache: revocation.NewMemoryRevocationCache(),
		AuditLog:        audit.NewMemoryAuditLog(),
		NowFn:           func() int64 { return now },
	}

	return &advRoot{
		store: store, config: config, rootCID: rootCID,
		agentKey: agentKey, agentDID: agentDID,
		leafKey: leafKey, leafDID: leafDID,
		verifierDID: verifierDID, now: now,
	}
}

func (a *advRoot) invoke(t *testing.T, leafCID string) *UCANInvocation {
	t.Helper()
	inv, err := CreateInvocation(leafCID, credential.CanToolInvoke, "tool://server/search", nil, a.leafKey, a.verifierDID, "")
	if err != nil {
		t.Fatalf("CreateInvocation: %v", err)
	}
	return inv
}

func TestAdversarialRestrictBypass(t *testing.T) {
	t.Run("dl_escalation", func(t *testing.T) {
		a := newAdvRoot(t)
		leafCID := forgeBlock(t, &credential.RestrictBlock{
			Typ: credential.RestrictBlockTyp,
			Iss: a.agentDID, Aud: a.leafDID, Prf: a.rootCID,
			Exp: a.now + 3600, Nbf: a.now - 60,
			DL:  6, // parent dl is 5 — escalation
			Cav: credential.Constraints{credential.NewTimeWindow(a.now-60, a.now+3600)},
		}, a.agentKey, a.store)

		res := Verify(context.Background(), nil, a.invoke(t, leafCID), a.config)
		if res.OK {
			t.Fatal("FATAL: dl escalation was not rejected")
		}
		if res.Error.Code != CodeAttenuation {
			t.Errorf("code = %s, want %s (attenuation)", res.Error.Code, CodeAttenuation)
		}
		if res.Error.Step != 2 {
			t.Errorf("step = %d, want 2 (linkage)", res.Error.Step)
		}
	})

	t.Run("exp_escalation", func(t *testing.T) {
		a := newAdvRoot(t)
		leafCID := forgeBlock(t, &credential.RestrictBlock{
			Typ: credential.RestrictBlockTyp,
			Iss: a.agentDID, Aud: a.leafDID, Prf: a.rootCID,
			Exp: a.now + 7200, // parent exp is now+3600 — escalation
			Nbf: a.now - 60, DL: 4,
			Cav: credential.Constraints{credential.NewTimeWindow(a.now-60, a.now+7200)},
		}, a.agentKey, a.store)

		res := Verify(context.Background(), nil, a.invoke(t, leafCID), a.config)
		if res.OK {
			t.Fatal("FATAL: exp escalation was not rejected")
		}
		if res.Error.Code != CodeExpiryEscalate {
			t.Errorf("code = %s, want %s", res.Error.Code, CodeExpiryEscalate)
		}
		if res.Error.Step != 2 {
			t.Errorf("step = %d, want 2", res.Error.Step)
		}
	})

	t.Run("nbf_regression", func(t *testing.T) {
		a := newAdvRoot(t)
		leafCID := forgeBlock(t, &credential.RestrictBlock{
			Typ: credential.RestrictBlockTyp,
			Iss: a.agentDID, Aud: a.leafDID, Prf: a.rootCID,
			Exp: a.now + 3600,
			Nbf: a.now - 3600, // parent nbf is now-60 — regression
			DL:  4,
			Cav: credential.Constraints{credential.NewTimeWindow(a.now-3600, a.now+3600)},
		}, a.agentKey, a.store)

		res := Verify(context.Background(), nil, a.invoke(t, leafCID), a.config)
		if res.OK {
			t.Fatal("FATAL: nbf regression was not rejected")
		}
		if res.Error.Code != CodeChainBroken {
			t.Errorf("code = %s, want %s", res.Error.Code, CodeChainBroken)
		}
		if res.Error.Step != 2 {
			t.Errorf("step = %d, want 2", res.Error.Step)
		}
	})

	t.Run("iss_aud_linkage_break", func(t *testing.T) {
		a := newAdvRoot(t)
		// Attacker uses their own identity, not the parent's audience.
		attackerKey, attackerDID := genKey(t)
		leafCID := forgeBlock(t, &credential.RestrictBlock{
			Typ: credential.RestrictBlockTyp,
			Iss: attackerDID, // != parent aud (agentDID)
			Aud: a.leafDID, Prf: a.rootCID,
			Exp: a.now + 3600, Nbf: a.now - 60, DL: 4,
			Cav: credential.Constraints{credential.NewTimeWindow(a.now-60, a.now+3600)},
		}, attackerKey, a.store)

		res := Verify(context.Background(), nil, a.invoke(t, leafCID), a.config)
		if res.OK {
			t.Fatal("FATAL: iss/aud linkage break was not rejected")
		}
		if res.Error.Code != CodeChainBroken {
			t.Errorf("code = %s, want %s", res.Error.Code, CodeChainBroken)
		}
		if res.Error.Step != 2 {
			t.Errorf("step = %d, want 2", res.Error.Step)
		}
	})

	t.Run("caveat_removal", func(t *testing.T) {
		a := newAdvRoot(t)
		root, err := credential.ParseUCAN(string(mustGet(t, a.store, a.rootCID)))
		if err != nil {
			t.Fatalf("ParseUCAN: %v", err)
		}
		parent, err := delegation.ParentFromUCAN(root, a.rootCID)
		if err != nil {
			t.Fatalf("ParentFromUCAN: %v", err)
		}

		// Hop 1: tight time_window [now-100, now+100].
		sub1Key, sub1DID := genKey(t)
		tightWindow := credential.Constraints{credential.NewTimeWindow(a.now-100, a.now+100)}
		block1, block1CID, err := delegation.DelegateRestrict(parent, sub1DID, tightWindow, 4, a.agentKey, a.store)
		if err != nil {
			t.Fatalf("DelegateRestrict hop1: %v", err)
		}

		// Hop 2: resource_restrict only — attacker drops the time_window.
		noTimeWindow := credential.Constraints{
			credential.ResourceRestrictConstraint{Type: credential.ConstraintResourceRestrict, Resource: "tool://server/*"},
		}
		_, leafCID, err := delegation.DelegateRestrict(
			delegation.ParentFromBlock(block1, block1CID), a.leafDID, noTimeWindow, 3, sub1Key, a.store)
		if err != nil {
			t.Fatalf("DelegateRestrict hop2: %v", err)
		}

		// Invoke at now+500: within credential validity but outside hop 1's
		// time_window [now-100, now+100]. Cumulative caveats must still apply.
		a.config.NowFn = func() int64 { return a.now + 500 }
		a.config.NonceCache = NewMemoryNonceCache()
		inv, err := CreateInvocation(leafCID, credential.CanToolInvoke, "tool://server/search", nil, a.leafKey, a.verifierDID, "")
		if err != nil {
			t.Fatalf("CreateInvocation: %v", err)
		}
		res := Verify(context.Background(), nil, inv, a.config)
		if res.OK {
			t.Fatal("FATAL: caveat removal (time_window dropped by child) was not rejected")
		}
		if res.Error.Code != CodeCapInsufficient {
			t.Errorf("code = %s, want %s", res.Error.Code, CodeCapInsufficient)
		}
	})

	t.Run("revoked_credential_replay", func(t *testing.T) {
		a := newAdvRoot(t)
		// Build a valid chain.
		root, err := credential.ParseUCAN(string(mustGet(t, a.store, a.rootCID)))
		if err != nil {
			t.Fatalf("ParseUCAN: %v", err)
		}
		parent, err := delegation.ParentFromUCAN(root, a.rootCID)
		if err != nil {
			t.Fatalf("ParentFromUCAN: %v", err)
		}
		caveats := credential.Constraints{credential.NewTimeWindow(a.now-100, a.now+3600)}
		_, leafCID, err := delegation.DelegateRestrict(parent, a.leafDID, caveats, 4, a.agentKey, a.store)
		if err != nil {
			t.Fatalf("DelegateRestrict: %v", err)
		}

		// First invocation succeeds.
		inv1 := a.invoke(t, leafCID)
		if res := Verify(context.Background(), nil, inv1, a.config); !res.OK {
			t.Fatalf("pre-revocation verify failed: %v", res.Error)
		}

		// Revoke the credential.
		revokerKey, revokerDID := genKey(t)
		entry, err := revocation.CreateRevocationEntry(
			revocation.RevocationSubject{CID: leafCID}, revocation.ScopeCredential, revocation.StatusRevoked,
			revocation.RevocationAuth{DID: revokerDID, Basis: revocation.AuthPlatform}, 1, "", revokerKey)
		if err != nil {
			t.Fatalf("CreateRevocationEntry: %v", err)
		}
		cache := a.config.RevocationCache.(*revocation.MemoryRevocationCache)
		if err := cache.Revoke(context.Background(), *entry); err != nil {
			t.Fatalf("Revoke: %v", err)
		}

		// Replay with a fresh invocation — must be rejected.
		inv2 := a.invoke(t, leafCID)
		res := Verify(context.Background(), nil, inv2, a.config)
		if res.OK {
			t.Fatal("FATAL: revoked credential was accepted on replay")
		}
		if res.Error.Code != CodeRevoked {
			t.Errorf("code = %s, want %s", res.Error.Code, CodeRevoked)
		}
		if res.Error.Step != 6 {
			t.Errorf("step = %d, want 6 (revocation)", res.Error.Step)
		}
	})

	t.Run("unknown_constraint_fail_closed", func(t *testing.T) {
		a := newAdvRoot(t)
		leafCID := forgeBlock(t, &credential.RestrictBlock{
			Typ: credential.RestrictBlockTyp,
			Iss: a.agentDID, Aud: a.leafDID, Prf: a.rootCID,
			Exp: a.now + 3600, Nbf: a.now - 60, DL: 4,
			Cav: credential.Constraints{
				credential.RawConstraint{
					TypeName: "exotic_future_caveat",
					Raw:      json.RawMessage(`{"type":"exotic_future_caveat","value":42}`),
				},
			},
		}, a.agentKey, a.store)

		res := Verify(context.Background(), nil, a.invoke(t, leafCID), a.config)
		if res.OK {
			t.Fatal("FATAL: unknown constraint type was silently accepted")
		}
		if res.Error.Code != CodeCapInsufficient {
			t.Errorf("code = %s, want %s", res.Error.Code, CodeCapInsufficient)
		}
	})
}

func mustGet(t *testing.T, store *delegation.MemoryProofStore, cid string) []byte {
	t.Helper()
	raw, err := store.Get(context.Background(), cid)
	if err != nil {
		t.Fatalf("store.Get(%s): %v", cid, err)
	}
	return raw
}
