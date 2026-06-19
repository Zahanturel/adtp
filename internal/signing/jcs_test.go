package signing

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// raw builds a string from explicit byte values. Expected canonical output is
// expressed this way so that this source file contains no raw control or
// non-ASCII bytes (which tooling may rewrite) and the expected bytes are an
// unambiguous oracle independent of the implementation.
func raw(b ...byte) string { return string(b) }

func TestCanonicalize(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty object", `{}`, `{}`},
		{"empty array", `[]`, `[]`},
		{"empty nested", `{"a":{},"b":[]}`, `{"a":{},"b":[]}`},
		{"scalar string", `"hello"`, `"hello"`},
		{"scalar integer", `42`, `42`},
		{"scalar true", `true`, `true`},
		{"scalar false", `false`, `false`},
		{"scalar null", `null`, `null`},

		{"key sort simple", `{"b":1,"a":2}`, `{"a":2,"b":1}`},
		{"key sort length tiebreak", `{"ab":1,"a":2}`, `{"a":2,"ab":1}`},
		{"whitespace stripped", "{ \"a\" :\n1 ,\t\"b\": 2 }", `{"a":1,"b":2}`},
		{
			"nested sorted recursively",
			`{"z":{"b":1,"a":2},"a":[3,2,1]}`,
			`{"a":[3,2,1],"z":{"a":2,"b":1}}`,
		},
		{"array order preserved", `[3,1,2]`, `[3,1,2]`},
		{"mixed literals", `[null, true, false]`, `[null,true,false]`},

		{"integer zero", `0`, `0`},
		{"integer negative zero folds", `-0`, `0`},
		{"integer negative", `-123`, `-123`},
		{
			"integer beyond float64 precision preserved exactly",
			`123456789012345678901234567890`,
			`123456789012345678901234567890`,
		},

		{"forward slash not escaped", `"a/b"`, `"a/b"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Canonicalize([]byte(tt.in))
			if err != nil {
				t.Fatalf("Canonicalize(%q) returned error: %v", tt.in, err)
			}
			if string(got) != tt.want {
				t.Errorf("Canonicalize(%q)\n got: %q\nwant: %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestCanonicalizeStringEscaping verifies RFC 8785 minimal string escaping.
// Inputs are produced by marshaling a byte-built Go string into valid JSON;
// expected outputs are exact byte sequences.
func TestCanonicalizeStringEscaping(t *testing.T) {
	const (
		quote = 0x22 // "
		bsl   = 0x5c // backslash
	)
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{"quote", raw(quote), raw(quote, bsl, quote, quote)},        // "\""
		{"backslash", raw(bsl), raw(quote, bsl, bsl, quote)},        // "\\"
		{"backspace", raw(0x08), raw(quote, bsl, 'b', quote)},       // "\b"
		{"tab", raw(0x09), raw(quote, bsl, 't', quote)},             // "\t"
		{"newline", raw(0x0a), raw(quote, bsl, 'n', quote)},         // "\n"
		{"formfeed", raw(0x0c), raw(quote, bsl, 'f', quote)},        // "\f"
		{"carriage return", raw(0x0d), raw(quote, bsl, 'r', quote)}, // "\r"
		{"null long form", raw(0x00), raw(quote, bsl, 'u', '0', '0', '0', '0', quote)},
		{"unit separator long form", raw(0x1f), raw(quote, bsl, 'u', '0', '0', '1', 'f', quote)},
		{"del is literal", raw(0x7f), raw(quote, 0x7f, quote)},
		{"c1 control 0x80 is literal utf-8", raw(0xc2, 0x80), raw(quote, 0xc2, 0x80, quote)},
		{"euro sign is literal utf-8", raw(0xe2, 0x82, 0xac), raw(quote, 0xe2, 0x82, 0xac, quote)},
		{"plain ascii unchanged", "a/b", `"a/b"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input, err := json.Marshal(tt.content)
			if err != nil {
				t.Fatalf("marshal input: %v", err)
			}
			got, err := Canonicalize(input)
			if err != nil {
				t.Fatalf("Canonicalize(% x): %v", input, err)
			}
			if string(got) != tt.want {
				t.Errorf("escaping mismatch\n got: % x\nwant: % x", got, tt.want)
			}
		})
	}
}

// TestCanonicalizeUTF16Ordering exercises RFC 8785 member ordering over UTF-16
// code units. The grinning-face emoji (U+1F600) must sort before U+FB33 because
// its leading surrogate (0xD83D) is numerically below 0xFB33, even though its
// code point is higher. Code-point ordering would place the emoji last; this
// vector fails under that incorrect ordering. Keys are built from rune values so
// the source holds no raw multi-byte characters, and ordering is asserted by the
// position of each key's canonical encoding in the output.
func TestCanonicalizeUTF16Ordering(t *testing.T) {
	members := map[string]string{
		string(rune(0x20ac)):  "Euro Sign",
		string(rune(0x000d)):  "Carriage Return",
		string(rune(0x000a)):  "Newline",
		"1":                   "One",
		string(rune(0x0080)):  "Control",
		string(rune(0x00f6)):  "Latin Small Letter O With Diaeresis",
		string(rune(0xfb33)):  "Hebrew Letter Dalet With Dagesh",
		string(rune(0x1f600)): "Emoji Grinning Face",
		"</script>":           "Browser Challenge",
	}
	input, err := json.Marshal(members)
	if err != nil {
		t.Fatalf("marshal input: %v", err)
	}
	got, err := Canonicalize(input)
	if err != nil {
		t.Fatalf("Canonicalize returned error: %v", err)
	}
	out := string(got)

	// Each key's canonical encoding, in the required ascending order.
	order := []struct {
		name  string
		token string
	}{
		{"LF U+000A", raw(0x5c, 'n')},
		{"CR U+000D", raw(0x5c, 'r')},
		{"digit one U+0031", "1"},
		{"</script> U+003C", "</script>"},
		{"C1 control U+0080", raw(0xc2, 0x80)},
		{"o-diaeresis U+00F6", raw(0xc3, 0xb6)},
		{"euro U+20AC", raw(0xe2, 0x82, 0xac)},
		{"emoji U+1F600 (surrogate D83D)", raw(0xf0, 0x9f, 0x98, 0x80)},
		{"dalet+dagesh U+FB33", raw(0xef, 0xac, 0xb3)},
	}

	prev := -1
	for _, o := range order {
		idx := strings.Index(out, o.token)
		if idx < 0 {
			t.Fatalf("key %s missing from output % x", o.name, out)
		}
		if idx <= prev {
			t.Errorf("key %s at index %d not strictly after previous %d (UTF-16 ordering violated)", o.name, idx, prev)
		}
		prev = idx
	}
}

func TestCanonicalizeIsIdempotent(t *testing.T) {
	in := `{"z":[1,{"y":2,"x":3}],"a":"hello"}`
	once, err := Canonicalize([]byte(in))
	if err != nil {
		t.Fatalf("first pass: %v", err)
	}
	twice, err := Canonicalize(once)
	if err != nil {
		t.Fatalf("second pass: %v", err)
	}
	if string(once) != string(twice) {
		t.Errorf("not idempotent\nonce:  %q\ntwice: %q", once, twice)
	}
}

func TestCanonicalizeErrors(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantErr error
	}{
		{"duplicate key top level", `{"a":1,"a":2}`, ErrDuplicateKey},
		{"duplicate key nested", `{"x":{"a":1,"a":2}}`, ErrDuplicateKey},
		{"duplicate key in array element", `[{"k":1,"k":2}]`, ErrDuplicateKey},

		{"float fractional", `1.5`, ErrNonInteger},
		{"float trailing zero", `1.0`, ErrNonInteger},
		{"float exponent lower", `1e2`, ErrNonInteger},
		{"float exponent upper", `1E2`, ErrNonInteger},
		{"float nested in object", `{"a":2.5}`, ErrNonInteger},
		{"float nested in array", `[1,2,3.0]`, ErrNonInteger},

		{"trailing object", `{}{}`, ErrTrailingData},
		{"trailing scalar", `1 2`, ErrTrailingData},
		{"trailing comma garbage", `[1,2],`, ErrTrailingData},

		{"empty input", ``, ErrInvalidJSON},
		{"whitespace only", "   \n\t", ErrInvalidJSON},
		{"unterminated object", `{`, ErrInvalidJSON},
		{"unterminated array", `[1,2`, ErrInvalidJSON},
		{"bare word", `nul`, ErrInvalidJSON},
		{"unexpected close", `}`, ErrInvalidJSON},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Canonicalize([]byte(tt.in))
			if err == nil {
				t.Fatalf("Canonicalize(%q) = nil error, want %v", tt.in, tt.wantErr)
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("Canonicalize(%q) error = %v, want errors.Is %v", tt.in, err, tt.wantErr)
			}
		})
	}
}

func TestCanonicalizeValue(t *testing.T) {
	type inner struct {
		B int    `json:"b"`
		A string `json:"a"`
	}
	v := struct {
		Z inner `json:"z"`
		A []int `json:"a"`
	}{
		Z: inner{B: 1, A: "x"},
		A: []int{3, 2, 1},
	}
	got, err := CanonicalizeValue(v)
	if err != nil {
		t.Fatalf("CanonicalizeValue: %v", err)
	}
	want := `{"a":[3,2,1],"z":{"a":"x","b":1}}`
	if string(got) != want {
		t.Errorf("CanonicalizeValue\n got: %q\nwant: %q", got, want)
	}
}

func TestCanonicalizeValueRejectsFloat(t *testing.T) {
	_, err := CanonicalizeValue(map[string]any{"amount": 1.5})
	if !errors.Is(err, ErrNonInteger) {
		t.Errorf("CanonicalizeValue(float) error = %v, want ErrNonInteger", err)
	}
}

func TestValidateIJSON(t *testing.T) {
	if err := ValidateIJSON([]byte(`{"a":1,"b":[2,3]}`)); err != nil {
		t.Errorf("ValidateIJSON(valid) = %v, want nil", err)
	}
	if err := ValidateIJSON([]byte(`{"a":1,"a":2}`)); !errors.Is(err, ErrDuplicateKey) {
		t.Errorf("ValidateIJSON(dup) = %v, want ErrDuplicateKey", err)
	}
}

func TestCompareUTF16(t *testing.T) {
	tests := []struct {
		name string
		a, b []uint16
		want int
	}{
		{"equal", []uint16{1, 2}, []uint16{1, 2}, 0},
		{"a less at first diff", []uint16{1, 2}, []uint16{1, 3}, -1},
		{"a greater at first diff", []uint16{1, 3}, []uint16{1, 2}, 1},
		{"a is prefix of b", []uint16{1}, []uint16{1, 2}, -1},
		{"b is prefix of a", []uint16{1, 2}, []uint16{1}, 1},
		{"both empty", nil, nil, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := compareUTF16(tt.a, tt.b); got != tt.want {
				t.Errorf("compareUTF16(%v, %v) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

// TestCanonicalizeDeepNesting guards against state mishandling on moderately
// deep structures.
func TestCanonicalizeDeepNesting(t *testing.T) {
	const depth = 200
	in := strings.Repeat(`{"a":`, depth) + `1` + strings.Repeat(`}`, depth)
	got, err := Canonicalize([]byte(in))
	if err != nil {
		t.Fatalf("deep nesting: %v", err)
	}
	if string(got) != in {
		t.Errorf("deep nesting mismatch")
	}
}
