package credential

import (
	"crypto/ed25519"
	"testing"

	"github.com/Zahanturel/adtp/internal/identity"
)

// delegableRoot mints a root credential whose audience is a fresh agent, and
// returns the parsed root, the agent's signing key, and the agent DID.
func delegableRoot(t *testing.T) (*UCAN, ed25519.PrivateKey, string) {
	t.Helper()
	platformDID, platformKey, err := identity.GenerateDID()
	if err != nil {
		t.Fatalf("platform: %v", err)
	}
	agentDID, agentKey, err := identity.GenerateDID()
	if err != nil {
		t.Fatalf("agent: %v", err)
	}
	readCap, err := NewCapability(CanResourceRead, "resource://db/customers")
	if err != nil {
		t.Fatalf("cap: %v", err)
	}
	toolCap, err := NewCapability(CanToolInvoke, "tool://server/search")
	if err != nil {
		t.Fatalf("cap: %v", err)
	}
	token, err := CreateUCAN(UCANPayload{
		Iss: platformDID,
		Aud: agentDID,
		Att: []Capability{readCap, toolCap},
		Prf: []string{},
		Exp: 5000,
		Nbf: 1000,
		Iat: 1000,
	}, platformKey)
	if err != nil {
		t.Fatalf("CreateUCAN: %v", err)
	}
	root, err := ParseUCAN(token)
	if err != nil {
		t.Fatalf("ParseUCAN: %v", err)
	}
	return root, agentKey, agentDID
}

func TestCreateRestateHop(t *testing.T) {
	root, agentKey, agentDID := delegableRoot(t)
	childDID := "did:key:zChild"

	// Restate a strict subset: just the read capability.
	subset := []Capability{root.Payload.Att[0]}
	hopToken, err := CreateRestateHop(root, childDID, subset, agentKey)
	if err != nil {
		t.Fatalf("CreateRestateHop: %v", err)
	}

	hop, err := ParseUCAN(hopToken)
	if err != nil {
		t.Fatalf("ParseUCAN: %v", err)
	}
	if hop.Payload.Iss != agentDID {
		t.Errorf("iss = %q, want %q", hop.Payload.Iss, agentDID)
	}
	if hop.Payload.Aud != childDID {
		t.Errorf("aud = %q", hop.Payload.Aud)
	}
	if len(hop.Payload.Prf) != 1 || hop.Payload.Prf[0] != root.CID() {
		t.Errorf("prf = %v, want [%s]", hop.Payload.Prf, root.CID())
	}
	if len(hop.Payload.Att) != 1 {
		t.Errorf("att length = %d, want 1", len(hop.Payload.Att))
	}

	// The hop carries an att_seal in its header, signed by the delegator.
	if hop.Header.Seal == nil {
		t.Fatal("hop header has no att_seal")
	}
	if err := VerifyAttSeal(hop.Header.Seal, hop.Payload.Att, agentKey.Public().(ed25519.PublicKey)); err != nil {
		t.Errorf("VerifyAttSeal: %v", err)
	}
	// The hop's own JWS signature verifies under the delegator's key.
	if err := hop.Verify(agentKey.Public().(ed25519.PublicKey)); err != nil {
		t.Errorf("hop Verify: %v", err)
	}
}

func TestCreateRestateHopValidation(t *testing.T) {
	root, agentKey, _ := delegableRoot(t)

	if _, err := CreateRestateHop(nil, "did:key:zC", root.Payload.Att, agentKey); err == nil {
		t.Errorf("nil parent accepted")
	}
	if _, err := CreateRestateHop(root, "", root.Payload.Att, agentKey); err == nil {
		t.Errorf("empty aud accepted")
	}
	if _, err := CreateRestateHop(root, "did:key:zC", nil, agentKey); err == nil {
		t.Errorf("empty att accepted")
	}
	if _, err := CreateRestateHop(root, "did:key:zC", root.Payload.Att, ed25519.PrivateKey{1}); err == nil {
		t.Errorf("bad key accepted")
	}
}
