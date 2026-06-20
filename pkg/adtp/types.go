// Package adtp defines the public HTTP API contract for the ADTP daemon: the
// request and response types and the external error codes. These types are the
// stable, documented external surface that SDKs serialize against.
package adtp

import (
	"encoding/json"

	"github.com/Zahanturel/adtp/internal/credential"
)

// Capability is a granted ability, re-exported from the credential package so
// the public contract has a single import.
type Capability = credential.Capability

// Caveats is a type-discriminated list of caveats (restrictions) for RESTRICT
// delegation.
type Caveats = credential.Constraints

// --- requests ---

// RegisterAgentRequest registers a new agent under a sponsor. The daemon
// generates the agent's DID and key.
type RegisterAgentRequest struct {
	SponsorDID string         `json:"sponsor_did"`
	Metadata   map[string]any `json:"metadata,omitempty"`
}

// IssueCredentialRequest issues a root credential to an agent.
type IssueCredentialRequest struct {
	AgentDID     string       `json:"agent_did"`
	Capabilities []Capability `json:"capabilities"`
	ExpSeconds   int64        `json:"exp_seconds"`
}

// DelegateRequest delegates from a parent credential to an audience.
type DelegateRequest struct {
	ParentCID    string       `json:"parent_cid"`
	AudienceDID  string       `json:"audience_did"`
	Mode         string       `json:"mode"` // "restrict" or "restate"
	Caveats      Caveats      `json:"caveats,omitempty"`
	Capabilities []Capability `json:"capabilities,omitempty"`
	DepthLeft    int          `json:"depth_left"`
	ExpSeconds   int64        `json:"exp_seconds"`
}

// VerifyRequest verifies a delegation chain against an action on a resource. If
// Invocation is empty the daemon builds and signs one with the leaf agent's key
// (custodial mode).
type VerifyRequest struct {
	ChainCIDs  []string        `json:"chain"`
	Invocation json.RawMessage `json:"invocation,omitempty"`
	Action     string          `json:"action"`
	Resource   string          `json:"resource"`
	Parameters map[string]any  `json:"parameters,omitempty"`
}

// RevokeRequest revokes a credential or identity.
type RevokeRequest struct {
	SubjectCID string `json:"subject_cid,omitempty"`
	SubjectDID string `json:"subject_did,omitempty"`
	Scope      string `json:"scope"`
	Status     string `json:"status"`
	Reason     string `json:"reason,omitempty"`
}

// --- responses ---

// RegisterAgentResponse is the result of registering an agent.
type RegisterAgentResponse struct {
	DID        string `json:"did"`
	SponsorDID string `json:"sponsor_did"`
	State      string `json:"state"`
}

// IssueCredentialResponse is the issued root credential.
type IssueCredentialResponse struct {
	CID   string `json:"cid"`
	Token string `json:"token"`
}

// DelegateResponse is the issued delegation.
type DelegateResponse struct {
	CID string `json:"cid"`
	Raw string `json:"raw"`
}

// VerifyResponse is the verification outcome.
type VerifyResponse struct {
	Authorized bool   `json:"authorized"`
	ChainDepth int    `json:"chain_depth"`
	RiskTier   string `json:"risk_tier"`
	Error      string `json:"error,omitempty"`
	ErrorCode  string `json:"error_code,omitempty"`
}

// RevokeResponse is the result of a revocation.
type RevokeResponse struct {
	Seq     int64  `json:"seq"`
	Status  string `json:"status"`
	Cascade int    `json:"cascade_count,omitempty"`
}

// StatusResponse reports a credential's revocation status.
type StatusResponse struct {
	CID     string `json:"cid"`
	Revoked bool   `json:"revoked"`
	Status  string `json:"status,omitempty"`
	Seq     int64  `json:"seq,omitempty"`
}

// AgentResponse reports an agent's lifecycle state.
type AgentResponse struct {
	DID          string `json:"did"`
	SponsorDID   string `json:"sponsor_did"`
	State        string `json:"state"`
	RegisteredAt int64  `json:"registered_at"`
	ActivatedAt  int64  `json:"activated_at,omitempty"`
}

// HealthResponse is the health-check body.
type HealthResponse struct {
	Status      string `json:"status"`
	PlatformDID string `json:"platform_did"`
}

// ErrorResponse is the body returned for any error.
type ErrorResponse struct {
	Error string `json:"error"`
	Code  string `json:"code,omitempty"`
}
