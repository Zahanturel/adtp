package credential

import (
	"testing"
)

func FuzzParseUCAN(f *testing.F) {
	f.Add("eyJhbGciOiJFZERTQSIsInR5cCI6ImFkdHAvdWNhbi8xIn0.eyJpc3MiOiJkaWQ6a2V5Ono2TWsiLCJhdWQiOiJkaWQ6a2V5Ono2TWsiLCJleHAiOjk5OTk5OTk5OTl9.AAAA")
	f.Add("")
	f.Add("not.a.jwt")
	f.Add("a]]][[.b.c")
	f.Add("eyJ0eXAiOiJ4In0.eyJ4IjoxfQ.AAAA")
	f.Add(".....")
	f.Add("eyJhbGciOiJFZERTQSJ9.e30.")

	f.Fuzz(func(t *testing.T, input string) {
		u, err := ParseUCAN(input)
		if err != nil {
			return
		}
		if u == nil {
			t.Fatal("nil UCAN without error")
		}
	})
}

func FuzzParseRestrictBlock(f *testing.F) {
	f.Add([]byte(`{"typ":"adtp/cav/1","iss":"did:key:z6Mk","aud":"did:key:z6Mk","exp":9999999999,"caveats":[],"dl":3}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`[]`))
	f.Add([]byte(``))
	f.Add([]byte(`{"typ":"adtp/cav/1","caveats":[{"type":"time_window","start":1,"end":2}],"dl":-1}`))
	f.Add([]byte(`{"typ":"wrong","iss":"x","aud":"y","exp":1,"caveats":[],"dl":0}`))

	f.Fuzz(func(t *testing.T, input []byte) {
		b, err := ParseRestrictBlock(input)
		if err != nil {
			return
		}
		if b == nil {
			t.Fatal("nil RestrictBlock without error")
		}
	})
}

func FuzzUnmarshalConstraints(f *testing.F) {
	f.Add([]byte(`[{"type":"time_window","start":1,"end":2}]`))
	f.Add([]byte(`[{"type":"budget","dim":"tokens","limit":100,"scope":"leaf","meter":"verifier"}]`))
	f.Add([]byte(`[{"type":"param_limit","field":"max_tokens","max":4096}]`))
	f.Add([]byte(`[{"type":"unknown_future_type","foo":"bar"}]`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`null`))
	f.Add([]byte(`[{}]`))
	f.Add([]byte(`not json`))

	f.Fuzz(func(t *testing.T, input []byte) {
		var cs Constraints
		_ = cs.UnmarshalJSON(input)
	})
}
