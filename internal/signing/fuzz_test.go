package signing

import (
	"testing"
)

func FuzzCanonicalize(f *testing.F) {
	f.Add([]byte(`{"b":2,"a":1}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"nested":{"z":1,"a":2}}`))
	f.Add([]byte(`{"arr":[3,1,2],"key":"val"}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`"just a string"`))
	f.Add([]byte(`[]`))
	f.Add([]byte(``))
	f.Add([]byte(`{"unicode":"AB"}`))
	f.Add([]byte(`{"deep":{"a":{"b":{"c":1}}}}`))

	f.Fuzz(func(t *testing.T, input []byte) {
		out, err := Canonicalize(input)
		if err != nil {
			return
		}
		// Idempotency: canonicalizing the output should produce the same bytes.
		out2, err := Canonicalize(out)
		if err != nil {
			t.Fatalf("canonicalize(canonicalize(input)) failed: %v", err)
		}
		if string(out) != string(out2) {
			t.Fatalf("not idempotent:\n  first:  %s\n  second: %s", out, out2)
		}
	})
}

func FuzzValidateIJSON(f *testing.F) {
	f.Add([]byte(`{"a":1}`))
	f.Add([]byte(`{"a":1,"a":2}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(``))
	f.Add([]byte(`not json`))
	f.Add([]byte(`{"nested":{"x":1,"x":2}}`))

	f.Fuzz(func(t *testing.T, input []byte) {
		_ = ValidateIJSON(input)
	})
}
