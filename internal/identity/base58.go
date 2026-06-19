package identity

import (
	"errors"
	"fmt"
	"math/big"
)

// base58Alphabet is the Bitcoin base58 alphabet used by the base58btc multibase
// encoding (multibase code 'z'). It deliberately omits the visually ambiguous
// characters 0, O, I, and l.
const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// ErrInvalidBase58 reports a character outside the base58btc alphabet.
var ErrInvalidBase58 = errors.New("invalid base58btc encoding")

var bigRadix = big.NewInt(58)

// base58Index maps each byte to its position in the alphabet, or -1 if the byte
// is not a base58btc character.
var base58Index [256]int8

func init() {
	for i := range base58Index {
		base58Index[i] = -1
	}
	for i := 0; i < len(base58Alphabet); i++ {
		base58Index[base58Alphabet[i]] = int8(i)
	}
}

// base58Encode encodes b using base58btc. Each leading zero byte is preserved as
// a leading '1', matching the standard Bitcoin/multibase behaviour.
func base58Encode(b []byte) string {
	zeros := 0
	for zeros < len(b) && b[zeros] == 0 {
		zeros++
	}

	// 138/100 slightly over-estimates log(256)/log(58) ≈ 1.3658 chars per byte.
	out := make([]byte, 0, len(b)*138/100+1)
	x := new(big.Int).SetBytes(b)
	mod := new(big.Int)
	for x.Sign() > 0 {
		x.DivMod(x, bigRadix, mod)
		out = append(out, base58Alphabet[mod.Int64()])
	}
	for i := 0; i < zeros; i++ {
		out = append(out, base58Alphabet[0])
	}

	// The digits were produced least-significant first; reverse in place.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

// base58Decode decodes a base58btc string. Leading '1' characters are restored
// as leading zero bytes.
func base58Decode(s string) ([]byte, error) {
	x := new(big.Int)
	for i := 0; i < len(s); i++ {
		v := base58Index[s[i]]
		if v < 0 {
			return nil, fmt.Errorf("%w: invalid character %q at offset %d", ErrInvalidBase58, s[i], i)
		}
		x.Mul(x, bigRadix)
		x.Add(x, big.NewInt(int64(v)))
	}

	zeros := 0
	for zeros < len(s) && s[zeros] == base58Alphabet[0] {
		zeros++
	}

	decoded := x.Bytes()
	out := make([]byte, zeros+len(decoded))
	copy(out[zeros:], decoded)
	return out, nil
}
