package credential

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

const validHeaderJSON = `{"typ":"aitp/ucan/1","alg":"EdDSA","ucv":"0.1.0"}`

func b64seg(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

// makeToken assembles a compact token from raw JSON segments and a signature,
// for exercising the parser against inputs CreateUCAN would never emit.
func makeToken(headerJSON, payloadJSON string, sig []byte) string {
	return b64seg(headerJSON) + "." + b64seg(payloadJSON) + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub, priv
}

func rootPayload(t *testing.T) UCANPayload {
	t.Helper()
	cap1, err := NewCapability(CanToolInvoke, "tool://server/run", NewTimeWindow(1000, 2000))
	if err != nil {
		t.Fatalf("NewCapability: %v", err)
	}
	cap2, err := NewCapability(CanResourceRead, "resource://store/items")
	if err != nil {
		t.Fatalf("NewCapability: %v", err)
	}
	return UCANPayload{
		Iss: "did:web:platform.example",
		Aud: "did:key:zAgent",
		Att: []Capability{cap1, cap2},
		Prf: []string{},
		Exp: 5000,
		Nbf: 1000,
		Iat: 1000,
	}
}

func TestCreateParseVerifyRoundTrip(t *testing.T) {
	pub, priv := testKey(t)
	payload := rootPayload(t)

	token, err := CreateUCAN(payload, priv)
	if err != nil {
		t.Fatalf("CreateUCAN: %v", err)
	}
	if strings.Count(token, ".") != 2 {
		t.Fatalf("token is not a 3-segment JWS: %q", token)
	}

	u, err := ParseUCAN(token)
	if err != nil {
		t.Fatalf("ParseUCAN: %v", err)
	}
	if err := u.Verify(pub); err != nil {
		t.Errorf("Verify: %v", err)
	}
	if u.Payload.Iss != payload.Iss || u.Payload.Aud != payload.Aud {
		t.Errorf("iss/aud mismatch: %+v", u.Payload)
	}
	if len(u.Payload.Att) != 2 {
		t.Errorf("att length = %d, want 2", len(u.Payload.Att))
	}
	if u.Payload.Exp != payload.Exp {
		t.Errorf("exp = %d, want %d", u.Payload.Exp, payload.Exp)
	}
	if u.Header.Typ != UCANTyp || u.Header.Alg != UCANAlg || u.Header.Ucv != UCANVersion {
		t.Errorf("header = %+v", u.Header)
	}
}

func TestCreateUCANDeterministic(t *testing.T) {
	_, priv := testKey(t)
	payload := rootPayload(t)

	a, err := CreateUCAN(payload, priv)
	if err != nil {
		t.Fatalf("CreateUCAN: %v", err)
	}
	b, err := CreateUCAN(payload, priv)
	if err != nil {
		t.Fatalf("CreateUCAN: %v", err)
	}
	if a != b {
		t.Errorf("CreateUCAN is not deterministic")
	}
}

func TestUCANCIDStable(t *testing.T) {
	_, priv := testKey(t)
	token, err := CreateUCAN(rootPayload(t), priv)
	if err != nil {
		t.Fatalf("CreateUCAN: %v", err)
	}
	u1, err := ParseUCAN(token)
	if err != nil {
		t.Fatalf("ParseUCAN: %v", err)
	}
	u2, _ := ParseUCAN(token)
	if u1.CID() != u2.CID() {
		t.Errorf("CID not stable: %q vs %q", u1.CID(), u2.CID())
	}
	if !strings.HasPrefix(u1.CID(), "bafkrei") {
		t.Errorf("CID = %q, want bafkrei prefix", u1.CID())
	}
	if !VerifyCID([]byte(token), u1.CID()) {
		t.Errorf("VerifyCID failed for token's own CID")
	}
}

func TestUCANVerifyRejectsTamper(t *testing.T) {
	pub, priv := testKey(t)
	token, err := CreateUCAN(rootPayload(t), priv)
	if err != nil {
		t.Fatalf("CreateUCAN: %v", err)
	}
	parts := strings.Split(token, ".")

	t.Run("flipped signature bit", func(t *testing.T) {
		sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
		sig[0] ^= 0x01
		tampered := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(sig)
		u, err := ParseUCAN(tampered)
		if err != nil {
			t.Fatalf("ParseUCAN: %v", err)
		}
		if err := u.Verify(pub); !errors.Is(err, ErrSignatureVerification) {
			t.Errorf("Verify(flipped sig) = %v, want ErrSignatureVerification", err)
		}
	})

	t.Run("swapped payload", func(t *testing.T) {
		other := rootPayload(t)
		other.Aud = "did:key:zAttacker"
		otherToken, err := CreateUCAN(other, priv)
		if err != nil {
			t.Fatalf("CreateUCAN: %v", err)
		}
		otherParts := strings.Split(otherToken, ".")
		// Splice a different payload under the original signature.
		tampered := parts[0] + "." + otherParts[1] + "." + parts[2]
		u, err := ParseUCAN(tampered)
		if err != nil {
			t.Fatalf("ParseUCAN: %v", err)
		}
		if err := u.Verify(pub); !errors.Is(err, ErrSignatureVerification) {
			t.Errorf("Verify(swapped payload) = %v, want ErrSignatureVerification", err)
		}
	})

	t.Run("wrong key", func(t *testing.T) {
		otherPub, _ := testKey(t)
		u, err := ParseUCAN(token)
		if err != nil {
			t.Fatalf("ParseUCAN: %v", err)
		}
		if err := u.Verify(otherPub); !errors.Is(err, ErrSignatureVerification) {
			t.Errorf("Verify(wrong key) = %v, want ErrSignatureVerification", err)
		}
	})
}

func TestParseUCANMalformed(t *testing.T) {
	sig := make([]byte, ed25519.SignatureSize)
	validPayload := `{"iss":"a","aud":"b","att":[],"prf":[],"exp":5000,"nbf":1000,"iat":1000}`

	tests := []struct {
		name    string
		token   string
		wantErr error
	}{
		{"empty", "", ErrMalformedToken},
		{"two segments", "a.b", ErrMalformedToken},
		{"four segments", "a.b.c.d", ErrMalformedToken},
		{"header not base64url", "!!!." + b64seg(validPayload) + "." + base64.RawURLEncoding.EncodeToString(sig), ErrMalformedToken},
		{"signature wrong length", makeToken(validHeaderJSON, validPayload, []byte{1, 2, 3}), ErrMalformedToken},
		{"wrong typ", makeToken(`{"typ":"jwt","alg":"EdDSA","ucv":"0.1.0"}`, validPayload, sig), ErrUnsupportedHeader},
		{"wrong alg", makeToken(`{"typ":"aitp/ucan/1","alg":"RS256","ucv":"0.1.0"}`, validPayload, sig), ErrUnsupportedHeader},
		{"unsupported ucv", makeToken(`{"typ":"aitp/ucan/1","alg":"EdDSA","ucv":"9.9.9"}`, validPayload, sig), ErrUnsupportedHeader},
		{"missing exp", makeToken(validHeaderJSON, `{"iss":"a","aud":"b","att":[],"prf":[],"nbf":1,"iat":1}`, sig), ErrMissingExpiry},
		{"duplicate key in payload", makeToken(validHeaderJSON, `{"iss":"a","iss":"b","aud":"c","att":[],"prf":[],"exp":5}`, sig), ErrMalformedToken},
		{"float in payload", makeToken(validHeaderJSON, `{"iss":"a","aud":"b","att":[],"prf":[],"exp":5.5}`, sig), ErrMalformedToken},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseUCAN(tt.token)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("ParseUCAN error = %v, want errors.Is %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseUCANTooManyCapabilities(t *testing.T) {
	var caps []string
	for i := 0; i <= MaxCapabilities; i++ { // 101 capabilities
		caps = append(caps, `{"can":"tool/invoke","with":"tool://h/x"}`)
	}
	payload := `{"iss":"a","aud":"b","att":[` + strings.Join(caps, ",") + `],"prf":[],"exp":5}`
	token := makeToken(validHeaderJSON, payload, make([]byte, ed25519.SignatureSize))

	if _, err := ParseUCAN(token); !errors.Is(err, ErrTooManyCapabilities) {
		t.Errorf("ParseUCAN(101 caps) = %v, want ErrTooManyCapabilities", err)
	}
}

func TestCreateUCANValidation(t *testing.T) {
	_, priv := testKey(t)
	base := rootPayload(t)

	tests := []struct {
		name    string
		mutate  func(p *UCANPayload)
		wantErr error
	}{
		{"missing iss", func(p *UCANPayload) { p.Iss = "" }, ErrMissingField},
		{"missing aud", func(p *UCANPayload) { p.Aud = "" }, ErrMissingField},
		{"non-positive exp", func(p *UCANPayload) { p.Exp = 0 }, ErrMissingExpiry},
		{"exp before nbf", func(p *UCANPayload) { p.Exp = 500; p.Nbf = 1000 }, ErrInvalidExpiry},
		{"invalid capability", func(p *UCANPayload) {
			p.Att = []Capability{{Can: "bogus", With: "tool://h/x"}}
		}, ErrUnknownCapabilityType},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := base
			// Copy the att slice header so mutations do not leak between cases.
			p.Att = append([]Capability(nil), base.Att...)
			tt.mutate(&p)
			if _, err := CreateUCAN(p, priv); !errors.Is(err, tt.wantErr) {
				t.Errorf("CreateUCAN error = %v, want errors.Is %v", err, tt.wantErr)
			}
		})
	}
}

func TestCreateUCANBadKey(t *testing.T) {
	if _, err := CreateUCAN(rootPayload(t), ed25519.PrivateKey{1, 2, 3}); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("CreateUCAN(bad key) = %v, want ErrInvalidKey", err)
	}
}

func TestUCANString(t *testing.T) {
	_, priv := testKey(t)
	token, err := CreateUCAN(rootPayload(t), priv)
	if err != nil {
		t.Fatalf("CreateUCAN: %v", err)
	}
	u, err := ParseUCAN(token)
	if err != nil {
		t.Fatalf("ParseUCAN: %v", err)
	}
	if u.String() != token {
		t.Errorf("String() = %q, want %q", u.String(), token)
	}
}

// TestCreateUCANNilCollections checks that nil att and prf are emitted as empty
// arrays (never null), which a root credential requires.
func TestCreateUCANNilCollections(t *testing.T) {
	pub, priv := testKey(t)
	payload := UCANPayload{
		Iss: "did:web:platform.example",
		Aud: "did:key:zAgent",
		Att: nil,
		Prf: nil,
		Exp: 5000,
		Nbf: 1000,
		Iat: 1000,
	}
	token, err := CreateUCAN(payload, priv)
	if err != nil {
		t.Fatalf("CreateUCAN: %v", err)
	}
	u, err := ParseUCAN(token)
	if err != nil {
		t.Fatalf("ParseUCAN: %v", err)
	}
	if err := u.Verify(pub); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(u.Payload.Att) != 0 {
		t.Errorf("att length = %d, want 0", len(u.Payload.Att))
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if !strings.Contains(string(payloadBytes), `"att":[]`) || !strings.Contains(string(payloadBytes), `"prf":[]`) {
		t.Errorf("payload did not encode empty arrays: %s", payloadBytes)
	}
}

func TestUCANVerifyBadKey(t *testing.T) {
	_, priv := testKey(t)
	token, err := CreateUCAN(rootPayload(t), priv)
	if err != nil {
		t.Fatalf("CreateUCAN: %v", err)
	}
	u, err := ParseUCAN(token)
	if err != nil {
		t.Fatalf("ParseUCAN: %v", err)
	}
	if err := u.Verify(ed25519.PublicKey{1, 2, 3}); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("Verify(bad key) = %v, want ErrInvalidKey", err)
	}
}
