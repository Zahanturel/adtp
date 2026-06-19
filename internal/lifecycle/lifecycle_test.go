package lifecycle

import (
	"errors"
	"testing"
)

func TestNewAgent(t *testing.T) {
	a := NewAgent("did:key:zAgent", "did:key:zSponsor")
	if a.State != StateRegistered {
		t.Errorf("state = %q, want REGISTERED", a.State)
	}
	if a.RegisteredAt == 0 {
		t.Errorf("RegisteredAt not set")
	}
}

func TestValidTransitions(t *testing.T) {
	valid := []struct {
		from AgentState
		to   AgentState
	}{
		{StateRegistered, StateActive},
		{StateActive, StateSuspended},
		{StateActive, StateCompromised},
		{StateActive, StateExpired},
		{StateActive, StateDecommissioned},
		{StateSuspended, StateActive},
		{StateSuspended, StateDecommissioned},
		{StateCompromised, StateDecommissioned},
		{StateExpired, StateActive},
		{StateExpired, StateDecommissioned},
	}
	for _, tt := range valid {
		t.Run(string(tt.from)+"_to_"+string(tt.to), func(t *testing.T) {
			a := &Agent{DID: "did:key:zA", State: tt.from}
			if err := Transition(a, tt.to, "did:key:zAdmin", "test"); err != nil {
				t.Fatalf("Transition(%s->%s) = %v, want nil", tt.from, tt.to, err)
			}
			if a.State != tt.to {
				t.Errorf("state = %q, want %q", a.State, tt.to)
			}
			if len(a.StateHistory) != 1 || a.StateHistory[0].From != tt.from || a.StateHistory[0].To != tt.to {
				t.Errorf("history not recorded: %+v", a.StateHistory)
			}
		})
	}
}

func TestInvalidTransitions(t *testing.T) {
	invalid := []struct {
		from AgentState
		to   AgentState
	}{
		{StateRegistered, StateSuspended},
		{StateRegistered, StateDecommissioned},
		{StateRegistered, StateCompromised},
		{StateActive, StateRegistered},
		{StateActive, StateActive},
		{StateSuspended, StateCompromised},
		{StateSuspended, StateExpired},
		{StateExpired, StateSuspended},
		{StateExpired, StateCompromised},
		// Terminal states admit nothing.
		{StateCompromised, StateActive},
		{StateCompromised, StateSuspended},
		{StateDecommissioned, StateActive},
		{StateDecommissioned, StateRegistered},
	}
	for _, tt := range invalid {
		t.Run(string(tt.from)+"_to_"+string(tt.to), func(t *testing.T) {
			a := &Agent{DID: "did:key:zA", State: tt.from}
			err := Transition(a, tt.to, "did:key:zAdmin", "test")
			if err == nil {
				t.Fatalf("Transition(%s->%s) = nil, want error", tt.from, tt.to)
			}
			if !errors.Is(err, ErrInvalidTransition) && !errors.Is(err, ErrTerminalState) {
				t.Errorf("err = %v, want invalid or terminal", err)
			}
			if a.State != tt.from {
				t.Errorf("state changed to %q on failed transition", a.State)
			}
		})
	}
}

func TestTerminalStates(t *testing.T) {
	if !Terminal(StateCompromised) || !Terminal(StateDecommissioned) {
		t.Errorf("COMPROMISED and DECOMMISSIONED must be terminal")
	}
	for _, s := range []AgentState{StateRegistered, StateActive, StateSuspended, StateExpired} {
		if Terminal(s) {
			t.Errorf("%s should not be terminal", s)
		}
	}
}

func TestActivatedAtSetOnce(t *testing.T) {
	a := &Agent{DID: "did:key:zA", State: StateRegistered}
	if err := Transition(a, StateActive, "did:key:zAdmin", "issue"); err != nil {
		t.Fatalf("activate: %v", err)
	}
	first := a.ActivatedAt
	if first == 0 {
		t.Fatal("ActivatedAt not set")
	}
	// Suspend then reactivate; ActivatedAt must not be overwritten.
	if err := Transition(a, StateSuspended, "did:key:zAdmin", "anomaly"); err != nil {
		t.Fatalf("suspend: %v", err)
	}
	if err := Transition(a, StateActive, "did:key:zSponsor", "reinstate"); err != nil {
		t.Fatalf("reinstate: %v", err)
	}
	if a.ActivatedAt != first {
		t.Errorf("ActivatedAt overwritten: %d != %d", a.ActivatedAt, first)
	}
}

func TestUnknownState(t *testing.T) {
	a := &Agent{DID: "did:key:zA", State: AgentState("BOGUS")}
	if err := Transition(a, StateActive, "did:key:zAdmin", "x"); !errors.Is(err, ErrInvalidTransition) {
		t.Errorf("err = %v, want ErrInvalidTransition", err)
	}
}
