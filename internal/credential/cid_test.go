package credential

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"strings"
	"testing"
)

// sha256 of the empty input, a widely published constant, used to anchor the CID
// construction to a value independent of this implementation.
const emptySHA256Hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// independentCID rebuilds the CIDv1 of data through a separately constructed
// base32 encoder, so the test does not merely re-run the package's own helper.
func independentCID(t *testing.T, data []byte) string {
	t.Helper()
	enc := base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)
	digest := sha256.Sum256(data)
	buf := []byte{0x01, 0x55, 0x12, 0x20}
	buf = append(buf, digest[:]...)
	return "b" + enc.EncodeToString(buf)
}

func TestComputeCIDMatchesIndependentConstruction(t *testing.T) {
	inputs := [][]byte{
		{},
		[]byte("hello"),
		[]byte("hello world"),
		[]byte(`{"typ":"aitp/ucan/1"}`),
		make([]byte, 1024),
	}
	for _, in := range inputs {
		got := ComputeCID(in)
		want := independentCID(t, in)
		if got != want {
			t.Errorf("ComputeCID(%q)\n got: %q\nwant: %q", in, got, want)
		}
		if !strings.HasPrefix(got, "bafkrei") {
			t.Errorf("ComputeCID(%q) = %q, want prefix bafkrei", in, got)
		}
		if len(got) != 59 {
			t.Errorf("ComputeCID(%q) length = %d, want 59", in, len(got))
		}
	}
}

// TestComputeCIDEmptyVector anchors the empty-input CID to the published SHA-256
// of the empty string and pins the resulting CID string.
func TestComputeCIDEmptyVector(t *testing.T) {
	if got := hex.EncodeToString(sha256Sum(nil)); got != emptySHA256Hex {
		t.Fatalf("sha256(empty) = %s, want %s", got, emptySHA256Hex)
	}

	// Build the expected CID from the external SHA-256 constant (not from a
	// fresh hash of the input), then compare.
	hashBytes, err := hex.DecodeString(emptySHA256Hex)
	if err != nil {
		t.Fatalf("decode hash: %v", err)
	}
	enc := base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)
	cidBytes := append([]byte{0x01, 0x55, 0x12, 0x20}, hashBytes...)
	want := "b" + enc.EncodeToString(cidBytes)

	if got := ComputeCID([]byte{}); got != want {
		t.Errorf("ComputeCID(empty)\n got: %q\nwant: %q", got, want)
	}

	const pinned = "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku"
	if got := ComputeCID([]byte{}); got != pinned {
		t.Errorf("ComputeCID(empty) = %q, want pinned %q", got, pinned)
	}
}

func TestComputeCIDDeterministic(t *testing.T) {
	data := []byte("repeatable")
	if ComputeCID(data) != ComputeCID(data) {
		t.Errorf("ComputeCID is not deterministic")
	}
}

func TestVerifyCID(t *testing.T) {
	data := []byte("content-addressed bytes")
	cid := ComputeCID(data)

	if !VerifyCID(data, cid) {
		t.Errorf("VerifyCID(matching) = false, want true")
	}
	if VerifyCID([]byte("different bytes"), cid) {
		t.Errorf("VerifyCID(mismatched data) = true, want false")
	}
	if VerifyCID(data, "bafkreinotarealcid") {
		t.Errorf("VerifyCID(wrong cid) = true, want false")
	}
}

// sha256Sum is a tiny indirection so the anchor test reads clearly.
func sha256Sum(b []byte) []byte {
	d := sha256.Sum256(b)
	return d[:]
}
