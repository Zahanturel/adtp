package identity

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"
)

// base58Vectors are the widely-used Bitcoin/base-x base58btc test vectors. They
// validate the encoding independently of any ADTP-specific code.
var base58Vectors = []struct {
	hexInput string
	encoded  string
}{
	{"", ""},
	{"00", "1"},
	{"0000", "11"},
	{"61", "2g"},
	{"626262", "a3gV"},
	{"636363", "aPEr"},
	{"73696d706c792061206c6f6e6720737472696e67", "2cFupjhnEsSn59qHXstmK2ffpLv2"},
	{"516b6fcd0f", "ABnLTmg"},
	{"bf4f89001e670274dd", "3SEo3LWLoPntC"},
	{"572e4794", "3EFU7m"},
	{"ecac89cad93923c02321", "EJDM8drfXA6uyA"},
	{"10c8511e", "Rt5zm"},
	{"00000000000000000000", "1111111111"},
}

func TestBase58Encode(t *testing.T) {
	for _, v := range base58Vectors {
		in, err := hex.DecodeString(v.hexInput)
		if err != nil {
			t.Fatalf("bad hex %q: %v", v.hexInput, err)
		}
		if got := base58Encode(in); got != v.encoded {
			t.Errorf("base58Encode(%s) = %q, want %q", v.hexInput, got, v.encoded)
		}
	}
}

func TestBase58Decode(t *testing.T) {
	for _, v := range base58Vectors {
		want, err := hex.DecodeString(v.hexInput)
		if err != nil {
			t.Fatalf("bad hex %q: %v", v.hexInput, err)
		}
		got, err := base58Decode(v.encoded)
		if err != nil {
			t.Fatalf("base58Decode(%q): %v", v.encoded, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("base58Decode(%q) = %x, want %s", v.encoded, got, v.hexInput)
		}
	}
}

func TestBase58DecodeRejectsInvalidCharacters(t *testing.T) {
	for _, bad := range []string{"0", "O", "I", "l", "z0", "abc!", " "} {
		if _, err := base58Decode(bad); !errors.Is(err, ErrInvalidBase58) {
			t.Errorf("base58Decode(%q) = %v, want ErrInvalidBase58", bad, err)
		}
	}
}

func TestBase58RoundTripRandom(t *testing.T) {
	for size := 0; size < 40; size++ {
		buf := make([]byte, size)
		if _, err := rand.Read(buf); err != nil {
			t.Fatalf("rand: %v", err)
		}
		got, err := base58Decode(base58Encode(buf))
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !bytes.Equal(got, buf) {
			t.Errorf("round trip mismatch at size %d", size)
		}
	}
}

func TestBase58RoundTripLeadingZeros(t *testing.T) {
	in := []byte{0, 0, 0, 7, 8, 9}
	encoded := base58Encode(in)
	if encoded[:3] != "111" {
		t.Errorf("leading zero bytes not encoded as '1': %q", encoded)
	}
	got, err := base58Decode(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(got, in) {
		t.Errorf("leading-zero round trip = %x, want %x", got, in)
	}
}
