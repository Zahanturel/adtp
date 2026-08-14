// SPDX-License-Identifier: Apache-2.0

// Package signing implements ADTP's canonical signing discipline (specification
// Section 3, rules SD-1 through SD-7) together with the RFC 8785 JSON
// Canonicalization Scheme (JCS) that the discipline is built upon.
//
// Canonicalization is the foundation of the protocol: every signed object is
// serialized through JCS before a signature is computed or verified, so that
// the signed bytes are a deterministic function of the object's semantic
// content and never of incidental serialization choices (key order,
// whitespace, number formatting).
//
// # I-JSON profile (SD-3)
//
// ADTP signs only I-JSON (RFC 7493) documents and constrains them further:
//
//   - Object keys MUST be unique. Duplicate keys are the canonical
//     parser-differential attack vector (adversary class A_parser) and are
//     rejected at canonicalization time.
//   - All numbers are integers. Floating-point syntax (a fractional part or an
//     exponent) is rejected. Monetary values are carried in minor units.
//     Integers are preserved exactly with arbitrary precision; unlike the
//     IEEE-754 number handling of generic RFC 8785, this profile never rounds a
//     protocol value, which is both safer and sufficient because no signed
//     field is ever a float.
//
// Within those constraints the output is byte-for-byte the RFC 8785 canonical
// form: members sorted by UTF-16 code unit, minimal string escaping, no
// insignificant whitespace.
package signing

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"unicode/utf16"
	"unicode/utf8"
)

// Canonicalization errors. They are joined into returned errors with %w so that
// callers can match them with errors.Is.
var (
	// ErrDuplicateKey reports a repeated key within a single JSON object.
	ErrDuplicateKey = errors.New("duplicate object key")
	// ErrNonInteger reports a number that uses floating-point syntax (a
	// fractional part or an exponent), which the SD-3 profile forbids.
	ErrNonInteger = errors.New("number is not an integer")
	// ErrTrailingData reports bytes after the top-level JSON value.
	ErrTrailingData = errors.New("trailing data after JSON value")
	// ErrInvalidJSON reports input that is not well-formed JSON.
	ErrInvalidJSON = errors.New("invalid JSON")
	// ErrInvalidUTF8 reports a document that is not valid UTF-8, which I-JSON
	// and RFC 8785 both require.
	ErrInvalidUTF8 = errors.New("input is not valid UTF-8")
	// ErrLoneSurrogate reports a \u escape naming an unpaired surrogate code
	// point, which is not a Unicode scalar value and has no UTF-8 encoding.
	ErrLoneSurrogate = errors.New("unpaired surrogate escape")
)

// Canonicalize returns the RFC 8785 canonical serialization of data under the
// ADTP I-JSON profile. data may be any JSON value (object, array, string,
// integer, boolean, or null). The input is fully parsed — duplicate keys and
// non-integer numbers are rejected — before any output is produced.
func Canonicalize(data []byte) ([]byte, error) {
	// Must run before decoding: encoding/json silently substitutes U+FFFD for
	// invalid UTF-8 and for unpaired surrogate escapes, so by the time a string
	// token is produced the evidence is gone.
	if err := validateTextEncoding(data); err != nil {
		return nil, err
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()

	var out bytes.Buffer
	if err := canonicalizeValue(dec, &out); err != nil {
		return nil, err
	}

	// Reject anything other than optional whitespace after the value.
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf("adtp/signing: jcs: %w", ErrTrailingData)
		}
		return nil, fmt.Errorf("adtp/signing: jcs: %w: %v", ErrTrailingData, err)
	}
	return out.Bytes(), nil
}

// CanonicalizeValue marshals v to JSON and returns its canonical form. It is a
// convenience wrapper over Canonicalize for in-memory Go values; a value that
// marshals to a float (and therefore violates SD-3) is rejected.
func CanonicalizeValue(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("adtp/signing: jcs: marshal value: %w", err)
	}
	return Canonicalize(raw)
}

// ValidateIJSON reports whether data conforms to the ADTP I-JSON profile
// (SD-3): well-formed JSON, no duplicate object keys, integers only. It performs
// the same parse as Canonicalize but discards the canonical output, which is
// convenient for parsers that re-decode into typed structures separately.
func ValidateIJSON(data []byte) error {
	_, err := Canonicalize(data)
	return err
}

// validateTextEncoding enforces the text-level requirements RFC 8785 and I-JSON
// place on the input, which encoding/json does not: the document must be valid
// UTF-8, and every \u escape inside a string must be a scalar value or a
// correctly ordered surrogate pair.
//
// This cannot be folded into the decode pass. encoding/json replaces invalid
// UTF-8 bytes and unpaired surrogate escapes with U+FFFD rather than failing, so
// "\ud800", "\udfff", and a literal U+FFFD all arrive at canonicalizeToken as
// the same string. Three distinct documents would then canonicalize to identical
// bytes and therefore to one signature and one CID — a canonicalization
// collision, which is precisely the parser-differential class SD-3 exists to
// close.
func validateTextEncoding(data []byte) error {
	if !utf8.Valid(data) {
		return fmt.Errorf("adtp/signing: jcs: %w", ErrInvalidUTF8)
	}
	inString := false
	for i := 0; i < len(data); i++ {
		if !inString {
			if data[i] == '"' {
				inString = true
			}
			continue
		}
		switch data[i] {
		case '"':
			inString = false
		case '\\':
			if i+1 >= len(data) {
				return fmt.Errorf("adtp/signing: jcs: %w: truncated escape", ErrInvalidJSON)
			}
			if data[i+1] != 'u' {
				i++ // a simple two-character escape
				continue
			}
			hi, ok := hex4(data, i+2)
			if !ok {
				return fmt.Errorf("adtp/signing: jcs: %w: malformed \\u escape", ErrInvalidJSON)
			}
			i += 5
			if !utf16.IsSurrogate(rune(hi)) {
				continue
			}
			// A surrogate is only legal as the high half of a pair immediately
			// followed by the low half.
			lo, ok := hex4(data, i+3)
			if hi > 0xDBFF || !ok || data[i+1] != '\\' || data[i+2] != 'u' ||
				utf16.DecodeRune(rune(hi), rune(lo)) == utf8.RuneError {
				return fmt.Errorf("adtp/signing: jcs: %w: \\u%04X", ErrLoneSurrogate, hi)
			}
			i += 6
		}
	}
	return nil
}

// hex4 decodes the four hexadecimal digits at data[i:i+4].
func hex4(data []byte, i int) (uint32, bool) {
	if i+4 > len(data) {
		return 0, false
	}
	var v uint32
	for _, b := range data[i : i+4] {
		switch {
		case b >= '0' && b <= '9':
			v = v<<4 | uint32(b-'0')
		case b >= 'a' && b <= 'f':
			v = v<<4 | uint32(b-'a'+10)
		case b >= 'A' && b <= 'F':
			v = v<<4 | uint32(b-'A'+10)
		default:
			return 0, false
		}
	}
	return v, true
}

// canonicalizeValue reads exactly one JSON value from dec and writes its
// canonical form to out.
func canonicalizeValue(dec *json.Decoder, out *bytes.Buffer) error {
	tok, err := dec.Token()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("adtp/signing: jcs: %w: unexpected end of input", ErrInvalidJSON)
		}
		return fmt.Errorf("adtp/signing: jcs: %w: %v", ErrInvalidJSON, err)
	}
	return canonicalizeToken(dec, tok, out)
}

func canonicalizeToken(dec *json.Decoder, tok json.Token, out *bytes.Buffer) error {
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			return canonicalizeObject(dec, out)
		case '[':
			return canonicalizeArray(dec, out)
		default:
			// A closing delimiter cannot appear where a value is expected.
			return fmt.Errorf("adtp/signing: jcs: %w: unexpected %q", ErrInvalidJSON, t)
		}
	case string:
		writeString(out, t)
		return nil
	case json.Number:
		return writeNumber(out, t)
	case bool:
		if t {
			out.WriteString("true")
		} else {
			out.WriteString("false")
		}
		return nil
	case nil:
		out.WriteString("null")
		return nil
	default:
		return fmt.Errorf("adtp/signing: jcs: %w: unexpected token type %T", ErrInvalidJSON, tok)
	}
}

// member is one object entry, decorated with its UTF-16 encoding so the sort
// comparator is a pure slice comparison.
type member struct {
	key   string
	key16 []uint16
	value []byte
}

func canonicalizeObject(dec *json.Decoder, out *bytes.Buffer) error {
	var members []member
	seen := make(map[string]struct{})

	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("adtp/signing: jcs: %w: %v", ErrInvalidJSON, err)
		}
		key, ok := keyTok.(string)
		if !ok {
			// encoding/json guarantees object keys are strings; this is defensive.
			return fmt.Errorf("adtp/signing: jcs: %w: non-string object key", ErrInvalidJSON)
		}
		if _, dup := seen[key]; dup {
			return fmt.Errorf("adtp/signing: jcs: %w: %q", ErrDuplicateKey, key)
		}
		seen[key] = struct{}{}

		var valBuf bytes.Buffer
		if err := canonicalizeValue(dec, &valBuf); err != nil {
			return err
		}
		members = append(members, member{
			key:   key,
			key16: utf16.Encode([]rune(key)),
			value: valBuf.Bytes(),
		})
	}
	// Consume the closing '}'.
	if _, err := dec.Token(); err != nil {
		return fmt.Errorf("adtp/signing: jcs: %w: %v", ErrInvalidJSON, err)
	}

	sort.Slice(members, func(i, j int) bool {
		return compareUTF16(members[i].key16, members[j].key16) < 0
	})

	out.WriteByte('{')
	for i := range members {
		if i > 0 {
			out.WriteByte(',')
		}
		writeString(out, members[i].key)
		out.WriteByte(':')
		out.Write(members[i].value)
	}
	out.WriteByte('}')
	return nil
}

func canonicalizeArray(dec *json.Decoder, out *bytes.Buffer) error {
	out.WriteByte('[')
	first := true
	for dec.More() {
		if !first {
			out.WriteByte(',')
		}
		first = false
		if err := canonicalizeValue(dec, out); err != nil {
			return err
		}
	}
	// Consume the closing ']'.
	if _, err := dec.Token(); err != nil {
		return fmt.Errorf("adtp/signing: jcs: %w: %v", ErrInvalidJSON, err)
	}
	out.WriteByte(']')
	return nil
}

const hexDigits = "0123456789abcdef"

// writeString writes s as a JSON string literal using the minimal escaping
// mandated by RFC 8785 (the ECMAScript JSON.stringify quoting rules). Only the
// mandatory escapes are emitted; all other code points, including non-ASCII, are
// written as literal UTF-8.
func writeString(out *bytes.Buffer, s string) {
	out.WriteByte('"')
	for i := 0; i < len(s); i++ {
		b := s[i]
		switch b {
		case '"':
			out.WriteString(`\"`)
		case '\\':
			out.WriteString(`\\`)
		case '\b':
			out.WriteString(`\b`)
		case '\t':
			out.WriteString(`\t`)
		case '\n':
			out.WriteString(`\n`)
		case '\f':
			out.WriteString(`\f`)
		case '\r':
			out.WriteString(`\r`)
		default:
			if b < 0x20 {
				out.WriteString(`\u00`)
				out.WriteByte(hexDigits[b>>4])
				out.WriteByte(hexDigits[b&0x0f])
			} else {
				// Bytes >= 0x20, including every byte of a multi-byte UTF-8
				// sequence (all >= 0x80), are emitted verbatim.
				out.WriteByte(b)
			}
		}
	}
	out.WriteByte('"')
}

// writeNumber writes n in canonical integer form. Floating-point syntax is
// rejected per SD-3. The JSON grammar already forbids leading zeros, so the only
// normalization required is folding the negative-zero literal to "0".
func writeNumber(out *bytes.Buffer, n json.Number) error {
	s := string(n)
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '.', 'e', 'E':
			return fmt.Errorf("adtp/signing: jcs: %w: %q", ErrNonInteger, s)
		}
	}
	if s == "-0" {
		s = "0"
	}
	out.WriteString(s)
	return nil
}

// compareUTF16 lexicographically compares two UTF-16 code unit sequences,
// returning a negative, zero, or positive result analogous to bytes.Compare.
// RFC 8785 specifies object member ordering over UTF-16 code units, which
// differs from Unicode code point order for characters outside the Basic
// Multilingual Plane.
func compareUTF16(a, b []uint16) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	default:
		return 0
	}
}
