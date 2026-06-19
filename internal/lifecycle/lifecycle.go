// Package lifecycle implements the agent lifecycle state machine (specification
// Section 17): the six states an agent moves through and the legal transitions
// between them.
package lifecycle

import (
	"errors"
	"fmt"
	"time"
)

// AgentState is one of the six agent lifecycle states.
type AgentState string

const (
	StateRegistered     AgentState = "REGISTERED"
	StateActive         AgentState = "ACTIVE"
	StateSuspended      AgentState = "SUSPENDED"
	StateCompromised    AgentState = "COMPROMISED"
	StateExpired        AgentState = "EXPIRED"
	StateDecommissioned AgentState = "DECOMMISSIONED"
)

// Lifecycle errors.
var (
	ErrInvalidTransition = errors.New("invalid state transition")
	ErrTerminalState     = errors.New("agent is in a terminal state")
)

// StateTransition records one state change and who triggered it.
type StateTransition struct {
	From   AgentState `json:"from"`
	To     AgentState `json:"to"`
	At     int64      `json:"at"`
	By     string     `json:"by"`
	Reason string     `json:"reason"`
}

// Agent is a sponsored principal and its lifecycle state.
type Agent struct {
	DID          string            `json:"did"`
	SponsorDID   string            `json:"sponsor_did"`
	State        AgentState        `json:"state"`
	RegisteredAt int64             `json:"registered_at"`
	ActivatedAt  int64             `json:"activated_at,omitempty"`
	StateHistory []StateTransition `json:"state_history,omitempty"`
}

// NewAgent returns an agent in the REGISTERED state.
func NewAgent(did, sponsorDID string) *Agent {
	return &Agent{
		DID:          did,
		SponsorDID:   sponsorDID,
		State:        StateRegistered,
		RegisteredAt: time.Now().Unix(),
	}
}

// validTransitions maps each state to the states it may legally move to.
// DECOMMISSIONED admits no successor; COMPROMISED admits only DECOMMISSIONED
// (forensic completion) and never a return to a usable state.
var validTransitions = map[AgentState]map[AgentState]struct{}{
	StateRegistered: {
		StateActive: {},
	},
	StateActive: {
		StateSuspended:      {},
		StateCompromised:    {},
		StateExpired:        {},
		StateDecommissioned: {},
	},
	StateSuspended: {
		StateActive:         {}, // REINSTATED — authority is checked by the revocation model
		StateDecommissioned: {},
	},
	StateExpired: {
		StateActive:         {},
		StateDecommissioned: {},
	},
	StateCompromised: {
		StateDecommissioned: {},
	},
	StateDecommissioned: {},
}

// Terminal reports whether a state can never return to a usable (ACTIVE) state.
// COMPROMISED is terminal even though it may still move to DECOMMISSIONED.
func Terminal(state AgentState) bool {
	return state == StateCompromised || state == StateDecommissioned
}

// CanTransition reports whether from may legally move to to.
func CanTransition(from, to AgentState) bool {
	_, ok := validTransitions[from][to]
	return ok
}

// Transition moves the agent to toState, recording the transition in its
// history. It returns ErrTerminalState if the agent cannot move at all, or
// ErrInvalidTransition if the specific move is not permitted. The authority
// ordering for reinstatement (SUSPENDED -> ACTIVE) is enforced by the revocation
// authority model, not here.
func Transition(agent *Agent, toState AgentState, byDID, reason string) error {
	allowed, known := validTransitions[agent.State]
	if !known {
		return fmt.Errorf("aitp/lifecycle: %w: unknown state %q", ErrInvalidTransition, agent.State)
	}
	if len(allowed) == 0 {
		return fmt.Errorf("aitp/lifecycle: %w: %s admits no transitions", ErrTerminalState, agent.State)
	}
	if _, ok := allowed[toState]; !ok {
		return fmt.Errorf("aitp/lifecycle: %w: %s -> %s", ErrInvalidTransition, agent.State, toState)
	}

	now := time.Now().Unix()
	agent.StateHistory = append(agent.StateHistory, StateTransition{
		From:   agent.State,
		To:     toState,
		At:     now,
		By:     byDID,
		Reason: reason,
	})
	if toState == StateActive && agent.ActivatedAt == 0 {
		agent.ActivatedAt = now
	}
	agent.State = toState
	return nil
}
