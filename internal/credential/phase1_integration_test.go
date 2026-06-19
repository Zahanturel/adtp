package credential_test

import (
	"testing"

	"github.com/adtp/adtp/internal/credential"
	"github.com/adtp/adtp/internal/identity"
)

// TestPhase1EndToEnd exercises the full cryptographic-core flow from the build
// plan's Phase 1 exit criteria: generate Ed25519 identities, mint a root UCAN
// with capabilities, serialize to a JWT, parse it back, verify the signature
// against the issuer's resolved key, and compute a stable content identifier.
//
// The platform issuer is modeled here with a did:key for self-containment; in
// production a platform is a did:web with pinned root keys (Section 15.1).
func TestPhase1EndToEnd(t *testing.T) {
	platformDID, platformPriv, err := identity.GenerateDID()
	if err != nil {
		t.Fatalf("generate platform identity: %v", err)
	}
	agentDID, _, err := identity.GenerateDID()
	if err != nil {
		t.Fatalf("generate agent identity: %v", err)
	}

	// The platform keeps its signing key in a keystore.
	ks := identity.NewMemoryKeyStore()
	if err := ks.Store(platformDID, platformPriv); err != nil {
		t.Fatalf("store platform key: %v", err)
	}
	signingKey, err := ks.Load(platformDID)
	if err != nil {
		t.Fatalf("load platform key: %v", err)
	}

	// Grant the agent two capabilities, one time-boxed.
	toolCap, err := credential.NewCapability(
		credential.CanToolInvoke,
		"tool://search.example/query",
		credential.NewTimeWindow(1_000, 1_000_000),
	)
	if err != nil {
		t.Fatalf("build tool capability: %v", err)
	}
	readCap, err := credential.NewCapability(
		credential.CanResourceRead,
		"resource://db.example/customers",
	)
	if err != nil {
		t.Fatalf("build resource capability: %v", err)
	}

	payload := credential.UCANPayload{
		Iss: platformDID,
		Aud: agentDID,
		Att: []credential.Capability{toolCap, readCap},
		Prf: []string{}, // root credential
		Exp: 1_000_000,
		Nbf: 1_000,
		Iat: 1_000,
	}

	token, err := credential.CreateUCAN(payload, signingKey)
	if err != nil {
		t.Fatalf("mint root credential: %v", err)
	}

	parsed, err := credential.ParseUCAN(token)
	if err != nil {
		t.Fatalf("parse credential: %v", err)
	}

	// Verify the signature against the issuer's key, resolved from its DID.
	issuerKey, err := identity.ResolveDID(parsed.Payload.Iss)
	if err != nil {
		t.Fatalf("resolve issuer DID: %v", err)
	}
	if err := parsed.Verify(issuerKey); err != nil {
		t.Fatalf("verify credential signature: %v", err)
	}

	// The content identifier is stable and content-addresses the token bytes.
	cid := parsed.CID()
	if !credential.VerifyCID([]byte(token), cid) {
		t.Errorf("CID %q does not address the token bytes", cid)
	}

	// The agent is the audience and holds both granted capabilities.
	if parsed.Payload.Aud != agentDID {
		t.Errorf("aud = %q, want %q", parsed.Payload.Aud, agentDID)
	}
	if len(parsed.Payload.Att) != 2 {
		t.Fatalf("att length = %d, want 2", len(parsed.Payload.Att))
	}

	// A credential signed by a different key must not verify against the issuer.
	_, impostorPriv, err := identity.GenerateDID()
	if err != nil {
		t.Fatalf("generate impostor: %v", err)
	}
	forged, err := credential.CreateUCAN(payload, impostorPriv)
	if err != nil {
		t.Fatalf("mint forged credential: %v", err)
	}
	forgedParsed, err := credential.ParseUCAN(forged)
	if err != nil {
		t.Fatalf("parse forged credential: %v", err)
	}
	if err := forgedParsed.Verify(issuerKey); err == nil {
		t.Errorf("forged credential verified against issuer key, want failure")
	}
}
