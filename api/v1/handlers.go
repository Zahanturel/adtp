// Package v1 implements the ADTP HTTP API (version 1) over the standard
// library net/http. The daemon is a managed (custodial) identity service: it
// generates and holds agent keys, issues and delegates credentials, verifies
// chains, and revokes — so a client can drive the whole flow without holding
// any key material itself.
package v1

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/adtp/adtp/config"
	"github.com/adtp/adtp/internal/audit"
	"github.com/adtp/adtp/internal/credential"
	"github.com/adtp/adtp/internal/delegation"
	"github.com/adtp/adtp/internal/identity"
	"github.com/adtp/adtp/internal/lifecycle"
	"github.com/adtp/adtp/internal/revocation"
	"github.com/adtp/adtp/internal/verify"
	"github.com/adtp/adtp/pkg/adtp"
	"github.com/adtp/adtp/store"
)

// Service ties the storage backend, the platform identity, and the engine
// together for the HTTP handlers.
type Service struct {
	Store       store.Store
	Keys        identity.KeyStore
	PlatformKey ed25519.PrivateKey
	PlatformDID string
	Config      *config.Config
	NonceCache  *verify.MemoryNonceCache
	Logger      *slog.Logger

	// APIKeys is the set of accepted API keys for api_key auth mode. Mutating
	// endpoints require one of these in the Authorization header.
	APIKeys map[string]bool

	// OIDC, when set, switches the auth gate to OIDC bearer-token validation; the
	// token's sub becomes the sponsor identity at registration.
	OIDC *OIDCVerifier

	// SIEM, when set, batches audit events to an external webhook.
	SIEM AuditExporter

	// StartTime is the daemon's boot time (UNIX seconds). Invocations whose iat
	// predates it are rejected (nonce-cache restart replay defense, Fix 12).
	StartTime int64

	listSeq atomic.Int64
}

func (s *Service) log() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

// AuditExporter receives a copy of each audit entry for external delivery
// (e.g. a SIEM webhook). The SIEM exporter satisfies it.
type AuditExporter interface {
	Enqueue(audit.AuditEntry)
}

// siemAuditLog tees appended entries to a SIEM exporter while delegating reads
// and chain verification to the primary (durable) log.
type siemAuditLog struct {
	primary  audit.AuditLog
	exporter AuditExporter
}

func (t siemAuditLog) Append(e audit.AuditEntry) error {
	err := t.primary.Append(e)
	t.exporter.Enqueue(e) // best-effort; never blocks or fails the primary write
	return err
}

func (t siemAuditLog) Query(f audit.AuditFilter) ([]audit.AuditEntry, error) {
	return t.primary.Query(f)
}

func (t siemAuditLog) VerifyChain() error { return t.primary.VerifyChain() }

// auditLog returns the audit log to write through: the store's durable log,
// teed to the SIEM exporter when one is configured.
func (s *Service) auditLog() audit.AuditLog {
	base := s.Store.Audit()
	if s.SIEM != nil {
		return siemAuditLog{primary: base, exporter: s.SIEM}
	}
	return base
}

// --- response helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, adtp.ErrorResponse{Error: msg, Code: code})
}

// maxBodyBytes bounds request bodies (matches the spec's transport ceilings),
// defending against memory-exhaustion via oversized payloads.
const maxBodyBytes = 64 * 1024

// readJSON decodes a size-limited JSON request body. It writes a 413 on an
// over-limit body and a 400 on malformed JSON, returning false in both cases so
// the handler can simply `return`.
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeErr(w, http.StatusRequestEntityTooLarge, adtp.CodeMalformed, "request body too large")
			return false
		}
		writeErr(w, http.StatusBadRequest, adtp.CodeMalformed, "invalid JSON body")
		return false
	}
	return true
}

// failErr logs the internal error server-side and returns only a generic public
// message plus an external ADTP code, so internal details never leak to clients
// (oracle minimization, Section 10.6).
func (svc *Service) failErr(w http.ResponseWriter, status int, code, publicMsg string, err error) {
	svc.log().Error(publicMsg, "status", status, "error", err)
	writeErr(w, status, code, publicMsg)
}

// --- handlers ---

func handleRegisterAgent(svc *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req adtp.RegisterAgentRequest
		if !readJSON(w, r, &req) {
			return
		}
		// In OIDC mode the sponsor identity is the authenticated subject (sub),
		// not a client-supplied value; in api_key mode it comes from the body.
		sponsor := req.SponsorDID
		if p, ok := principalFromContext(r.Context()); ok && p != "" {
			sponsor = p
		}
		if sponsor == "" {
			writeErr(w, http.StatusBadRequest, adtp.CodeMalformed, "sponsor_did is required")
			return
		}

		did, key, err := identity.GenerateDID()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "", "key generation failed")
			return
		}
		if err := svc.Keys.Store(did, key); err != nil {
			writeErr(w, http.StatusInternalServerError, "", "could not persist agent key")
			return
		}
		agent := lifecycle.NewAgent(did, sponsor)
		if err := lifecycle.Transition(agent, lifecycle.StateActive, svc.PlatformDID, "agent registered"); err != nil {
			writeErr(w, http.StatusInternalServerError, "", "lifecycle error")
			return
		}
		if err := svc.Store.PutAgent(agent); err != nil {
			writeErr(w, http.StatusInternalServerError, "", "could not persist agent")
			return
		}
		_ = svc.auditLog().Append(audit.AuditEntry{EventType: audit.EventAgentRegistered, AgentID: did})
		svc.log().Info("agent registered", "did", did, "sponsor", sponsor)

		writeJSON(w, http.StatusCreated, adtp.RegisterAgentResponse{
			DID: did, SponsorDID: sponsor, State: string(agent.State),
		})
	}
}

func handleIssueCredential(svc *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req adtp.IssueCredentialRequest
		if !readJSON(w, r, &req) {
			return
		}
		if _, err := identity.ParseDID(req.AgentDID); err != nil {
			writeErr(w, http.StatusBadRequest, adtp.CodeMalformed, "agent_did is not a valid did:key")
			return
		}
		if len(req.Capabilities) == 0 || req.ExpSeconds <= 0 {
			writeErr(w, http.StatusBadRequest, adtp.CodeMalformed, "capabilities and a positive exp_seconds are required")
			return
		}
		if _, err := svc.Store.GetAgent(req.AgentDID); err != nil {
			writeErr(w, http.StatusNotFound, "", "agent is not registered")
			return
		}

		now := time.Now().Unix()
		token, err := credential.CreateUCAN(credential.UCANPayload{
			Iss: svc.PlatformDID, Aud: req.AgentDID, Att: req.Capabilities,
			Prf: []string{}, Exp: now + req.ExpSeconds, Nbf: now, Iat: now,
		}, svc.PlatformKey)
		if err != nil {
			svc.failErr(w, http.StatusBadRequest, adtp.CodeMalformed, "invalid credential", err)
			return
		}
		cid, err := svc.Store.PutCredential([]byte(token))
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "", "could not store credential")
			return
		}
		if err := svc.Store.Register(cid, []string{cid}); err != nil {
			writeErr(w, http.StatusInternalServerError, "", "could not register credential")
			return
		}
		_ = svc.auditLog().Append(audit.AuditEntry{EventType: audit.EventDelegationIssued, AgentID: req.AgentDID, CredCID: cid})
		svc.log().Info("credential issued", "cid", cid, "agent", req.AgentDID)

		writeJSON(w, http.StatusCreated, adtp.IssueCredentialResponse{CID: cid, Token: token})
	}
}

func handleDelegate(svc *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req adtp.DelegateRequest
		if !readJSON(w, r, &req) {
			return
		}
		if req.ParentCID == "" || req.AudienceDID == "" {
			writeErr(w, http.StatusBadRequest, adtp.CodeMalformed, "parent_cid and audience_did are required")
			return
		}
		parentRaw, err := svc.Store.Get(req.ParentCID)
		if err != nil {
			writeErr(w, http.StatusNotFound, "", "parent credential not found")
			return
		}

		mode := req.Mode
		if mode == "" {
			mode = "restrict"
		}
		switch mode {
		case "restrict":
			svc.delegateRestrict(w, req, parentRaw)
		case "restate":
			svc.delegateRestate(w, req, parentRaw)
		default:
			writeErr(w, http.StatusBadRequest, adtp.CodeMalformed, "mode must be 'restrict' or 'restate'")
		}
	}
}

func (svc *Service) delegateRestrict(w http.ResponseWriter, req adtp.DelegateRequest, parentRaw []byte) {
	parent, delegatorDID, err := parentRef(parentRaw, req.ParentCID)
	if err != nil {
		svc.failErr(w, http.StatusBadRequest, adtp.CodeDenied, "parent cannot delegate", err)
		return
	}
	key, err := svc.Keys.Load(delegatorDID)
	if err != nil {
		writeErr(w, http.StatusForbidden, adtp.CodeDenied, "delegator key not held by this daemon")
		return
	}
	_, raw, err := credential.CreateRestrictBlock(parent, req.AudienceDID, req.DepthLeft, req.Caveats, key)
	if err != nil {
		svc.failErr(w, http.StatusBadRequest, adtp.CodeMalformed, "invalid delegation", err)
		return
	}
	cid := svc.storeAndRegister(w, raw)
	if cid == "" {
		return
	}
	svc.log().Info("restrict delegation issued", "cid", cid, "audience", req.AudienceDID)
	writeJSON(w, http.StatusCreated, adtp.DelegateResponse{CID: cid, Raw: base64.RawURLEncoding.EncodeToString(raw)})
}

func (svc *Service) delegateRestate(w http.ResponseWriter, req adtp.DelegateRequest, parentRaw []byte) {
	u, err := asUCAN(parentRaw)
	if err != nil {
		writeErr(w, http.StatusBadRequest, adtp.CodeMalformed, "RESTATE requires a UCAN parent")
		return
	}
	if len(req.Capabilities) == 0 {
		writeErr(w, http.StatusBadRequest, adtp.CodeMalformed, "capabilities are required for RESTATE")
		return
	}
	if !credential.CapabilitiesSubset(req.Capabilities, u.Payload.Att) {
		writeErr(w, http.StatusForbidden, adtp.CodeDenied, "restated capabilities exceed the parent")
		return
	}
	key, err := svc.Keys.Load(u.Payload.Aud)
	if err != nil {
		writeErr(w, http.StatusForbidden, adtp.CodeDenied, "delegator key not held by this daemon")
		return
	}
	token, err := credential.CreateRestateHop(u, req.AudienceDID, req.Capabilities, key)
	if err != nil {
		svc.failErr(w, http.StatusBadRequest, adtp.CodeMalformed, "invalid delegation", err)
		return
	}
	cid := svc.storeAndRegister(w, []byte(token))
	if cid == "" {
		return
	}
	svc.log().Info("restate delegation issued", "cid", cid, "audience", req.AudienceDID)
	writeJSON(w, http.StatusCreated, adtp.DelegateResponse{CID: cid, Raw: base64.RawURLEncoding.EncodeToString([]byte(token))})
}

// storeAndRegister stores a delegation, registers its chain, and audits it,
// returning the CID or "" after writing an error response.
func (svc *Service) storeAndRegister(w http.ResponseWriter, raw []byte) string {
	cid, err := svc.Store.PutCredential(raw)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "", "could not store delegation")
		return ""
	}
	chain, err := delegation.BuildChain(cid, svc.Store, svc.Config.Verify.MaxChainDepth)
	if err != nil {
		svc.failErr(w, http.StatusBadRequest, adtp.CodeMalformed, "delegation chain invalid", err)
		return ""
	}
	chainCIDs := make([]string, len(chain.Elements))
	for i, e := range chain.Elements {
		chainCIDs[i] = e.CID
	}
	if err := svc.Store.Register(cid, chainCIDs); err != nil {
		writeErr(w, http.StatusInternalServerError, "", "could not register delegation")
		return ""
	}
	_ = svc.auditLog().Append(audit.AuditEntry{EventType: audit.EventDelegationIssued, CredCID: cid})
	return cid
}

func handleVerify(svc *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req adtp.VerifyRequest
		if !readJSON(w, r, &req) {
			return
		}
		if len(req.ChainCIDs) == 0 || req.Action == "" || req.Resource == "" {
			writeErr(w, http.StatusBadRequest, adtp.CodeMalformed, "chain, action, and resource are required")
			return
		}
		leafCID := req.ChainCIDs[0]

		inv, err := svc.invocationFor(req, leafCID)
		if err != nil {
			writeErr(w, http.StatusBadRequest, adtp.CodeMalformed, err.Error())
			return
		}

		cfg := svc.verifierConfig()
		res := verify.Verify(nil, inv, cfg)

		resp := adtp.VerifyResponse{
			Authorized: res.OK,
			RiskTier:   cfg.RiskTierFn(req.Resource).String(),
		}
		if res.Chain != nil {
			resp.ChainDepth = len(res.Chain.Elements)
		}
		if !res.OK && res.Error != nil {
			resp.Error = "verification failed"
			resp.ErrorCode = adtp.ExternalCode(res.Error)
		}
		svc.log().Info("verification", "authorized", res.OK, "resource", req.Resource, "latency_ms", res.LatencyMs)
		writeJSON(w, http.StatusOK, resp)
	}
}

// invocationFor returns the invocation to verify: the client-supplied one, or a
// daemon-built one signed with the leaf agent's key (custodial mode).
func (svc *Service) invocationFor(req adtp.VerifyRequest, leafCID string) (*verify.UCANInvocation, error) {
	if len(req.Invocation) > 0 {
		var inv verify.UCANInvocation
		if err := json.Unmarshal(req.Invocation, &inv); err != nil {
			return nil, jsonError("invalid invocation")
		}
		return &inv, nil
	}
	raw, err := svc.Store.Get(leafCID)
	if err != nil {
		return nil, jsonError("leaf credential not found")
	}
	leafAud, err := audienceOf(raw)
	if err != nil {
		return nil, jsonError("could not read leaf audience")
	}
	key, err := svc.Keys.Load(leafAud)
	if err != nil {
		return nil, jsonError("leaf agent key not held; supply an invocation")
	}
	return verify.CreateInvocation(leafCID, req.Action, req.Resource, req.Parameters, key, svc.PlatformDID, "")
}

func handleRevoke(svc *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req adtp.RevokeRequest
		if !readJSON(w, r, &req) {
			return
		}
		if req.SubjectCID == "" && req.SubjectDID == "" {
			writeErr(w, http.StatusBadRequest, adtp.CodeMalformed, "subject_cid or subject_did is required")
			return
		}
		scope := revocation.RevocationScope(req.Scope)
		status := revocation.RevocationStatus(req.Status)
		// The daemon revokes as the platform authority; reject statuses or scopes
		// the platform may not set.
		if err := revocation.ValidateAuthority(revocation.AuthPlatform, status, scope); err != nil {
			svc.failErr(w, http.StatusForbidden, adtp.CodeDenied, "revocation not permitted", err)
			return
		}

		if status == revocation.StatusCompromised && req.SubjectCID != "" {
			report, err := revocation.ExecuteCascade(req.SubjectCID, svc.Store, svc.Store, nil, svc.auditLog(), svc.PlatformKey)
			if err != nil {
				svc.failErr(w, http.StatusInternalServerError, "", "cascade failed", err)
				return
			}
			svc.log().Info("compromise cascade", "cid", req.SubjectCID, "descendants", report.DescendantCount)
			writeJSON(w, http.StatusOK, adtp.RevokeResponse{
				Seq: report.PrimaryEntry.Seq, Status: string(status), Cascade: report.DescendantCount,
			})
			return
		}

		subject := req.SubjectCID
		if subject == "" {
			subject = req.SubjectDID
		}
		seq := svc.Store.CurrentSeq(subject) + 1
		auth := revocation.RevocationAuth{DID: svc.PlatformDID, Basis: revocation.AuthPlatform, Proof: subject}
		entry, err := revocation.CreateRevocationEntry(
			revocation.RevocationSubject{CID: req.SubjectCID, DID: req.SubjectDID}, scope, status, auth, seq, "", svc.PlatformKey)
		if err != nil {
			svc.failErr(w, http.StatusForbidden, adtp.CodeDenied, "invalid revocation request", err)
			return
		}
		if err := svc.Store.Revoke(*entry); err != nil {
			svc.failErr(w, http.StatusConflict, "", "could not apply revocation", err)
			return
		}
		_ = svc.auditLog().Append(audit.AuditEntry{EventType: audit.EventRevocationPosted, CredCID: req.SubjectCID, Payload: map[string]any{"status": req.Status}})
		svc.log().Info("revocation posted", "subject", subject, "status", req.Status)
		writeJSON(w, http.StatusOK, adtp.RevokeResponse{Seq: seq, Status: string(status)})
	}
}

func handleGetRevocationList(svc *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		entries, err := svc.Store.RevocationEntries()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "", "could not read revocations")
			return
		}
		list, err := revocation.CreateRevocationList(entries, svc.PlatformDID, "", svc.listSeq.Add(1), svc.PlatformKey)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "", "could not sign revocation list")
			return
		}
		writeJSON(w, http.StatusOK, list)
	}
}

func handleGetStatus(svc *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cid := r.PathValue("cid")
		entry, err := svc.Store.GetStatus(cid)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "", "status lookup failed")
			return
		}
		if entry == nil {
			writeJSON(w, http.StatusOK, adtp.StatusResponse{CID: cid, Revoked: false})
			return
		}
		writeJSON(w, http.StatusOK, adtp.StatusResponse{CID: cid, Revoked: true, Status: string(entry.Status), Seq: entry.Seq})
	}
}

func handleGetAgent(svc *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		did := r.PathValue("did")
		agent, err := svc.Store.GetAgent(did)
		if err != nil {
			writeErr(w, http.StatusNotFound, "", "agent not found")
			return
		}
		writeJSON(w, http.StatusOK, adtp.AgentResponse{
			DID: agent.DID, SponsorDID: agent.SponsorDID, State: string(agent.State),
			RegisteredAt: agent.RegisteredAt, ActivatedAt: agent.ActivatedAt,
		})
	}
}

func handleHealth(svc *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, adtp.HealthResponse{Status: "ok", PlatformDID: svc.PlatformDID})
	}
}

// --- internal helpers ---

func (svc *Service) verifierConfig() *verify.VerifierConfig {
	tier := parseTier(svc.Config.Verify.DefaultRiskTier)
	return &verify.VerifierConfig{
		VerifierDID:      svc.PlatformDID,
		TrustedRootDIDs:  map[string]bool{svc.PlatformDID: true},
		MaxChainDepth:    svc.Config.Verify.MaxChainDepth,
		ClockSkewSeconds: svc.Config.Verify.ClockSkewSeconds,
		RiskTierFn:       func(string) verify.RiskTier { return tier },
		ProofStore:       svc.Store,
		RevocationCache:  svc.Store,
		AuditLog:         svc.auditLog(),
		NonceCache:       svc.NonceCache,
		Logger:           svc.log(),
		StartTime:        svc.StartTime,
		// MeteringEnabled stays false: no metering backend is wired up, so budget/
		// max_calls/parameter_schema caveats fail closed rather than silently pass.
		MeteringEnabled: false,
	}
}

func parseTier(s string) verify.RiskTier {
	switch s {
	case "HIGH":
		return verify.TierHigh
	case "LOW":
		return verify.TierLow
	case "ANALYTICS":
		return verify.TierAnalytics
	default:
		return verify.TierMedium
	}
}

// parentRef derives the delegation parent and the delegator DID from a parent
// credential's bytes.
func parentRef(raw []byte, cid string) (credential.DelegationParent, string, error) {
	if isBlock(raw) {
		b, err := credential.ParseRestrictBlock(raw)
		if err != nil {
			return credential.DelegationParent{}, "", err
		}
		return delegation.ParentFromBlock(b, cid), b.Aud, nil
	}
	u, err := credential.ParseUCAN(string(raw))
	if err != nil {
		return credential.DelegationParent{}, "", err
	}
	parent, err := delegation.ParentFromUCAN(u, cid)
	if err != nil {
		return credential.DelegationParent{}, "", err
	}
	return parent, u.Payload.Aud, nil
}

func asUCAN(raw []byte) (*credential.UCAN, error) {
	return credential.ParseUCAN(string(raw))
}

func audienceOf(raw []byte) (string, error) {
	if isBlock(raw) {
		b, err := credential.ParseRestrictBlock(raw)
		if err != nil {
			return "", err
		}
		return b.Aud, nil
	}
	u, err := credential.ParseUCAN(string(raw))
	if err != nil {
		return "", err
	}
	return u.Payload.Aud, nil
}

func isBlock(raw []byte) bool {
	for _, b := range raw {
		switch b {
		case ' ', '\t', '\n', '\r':
			continue
		case '{':
			return true
		default:
			return false
		}
	}
	return false
}

type apiError struct{ msg string }

func (e apiError) Error() string { return e.msg }

func jsonError(msg string) error { return apiError{msg} }
