package verify

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"

	"github.com/Zahanturel/adtp/internal/audit"
	"github.com/Zahanturel/adtp/internal/credential"
	"github.com/Zahanturel/adtp/internal/delegation"
	"github.com/Zahanturel/adtp/internal/identity"
	"github.com/Zahanturel/adtp/internal/revocation"
)

// RevocationCache reports the latest revocation entry for a subject (a
// credential CID or principal DID) at verification step 6, or nil if the subject
// is active. It is satisfied by revocation.MemoryRevocationCache.
type RevocationCache interface {
	GetStatus(ctx context.Context, subject string) (*revocation.RevocationEntry, error)
}

// RegistrationChecker reports whether a credential's chain is recorded in the
// registration index. It is satisfied by store.Store (which embeds
// revocation.RegistrationStore).
type RegistrationChecker interface {
	Contains(ctx context.Context, credentialCID, chainCID string) bool
}

// TrustPolicy describes a trusted external organization for cross-org
// authorization (a simplified precursor to the ORG_TRUST document of Phase 5).
type TrustPolicy struct {
	Platforms          []string
	MaxDelegationDepth int
}

// InvocationContext is the runtime context against which caveats are evaluated
// (Section 7.3, step 8).
type InvocationContext struct {
	Action     string
	Resource   string
	Parameters map[string]any
	Now        int64
	// MeteringEnabled reports whether a metering/enforcement backend is wired up.
	// When false, cumulative (budget, max_calls) and enforcement-time
	// (parameter_schema) caveats cannot be honored and therefore fail closed.
	MeteringEnabled bool
}

// ---- element field accessors ----

func elemIss(e delegation.ChainElement) string {
	if e.Token != nil {
		return e.Token.Payload.Iss
	}
	return e.Block.Iss
}

func elemAud(e delegation.ChainElement) string {
	if e.Token != nil {
		return e.Token.Payload.Aud
	}
	return e.Block.Aud
}

func elemExp(e delegation.ChainElement) int64 {
	if e.Token != nil {
		return e.Token.Payload.Exp
	}
	return e.Block.Exp
}

func elemNbf(e delegation.ChainElement) int64 {
	if e.Token != nil {
		return e.Token.Payload.Nbf
	}
	return e.Block.Nbf
}

func elemParentCID(e delegation.ChainElement) string {
	if e.Block != nil {
		return e.Block.Prf
	}
	if len(e.Token.Payload.Prf) == 1 {
		return e.Token.Payload.Prf[0]
	}
	return ""
}

func elemDelegableDepth(e delegation.ChainElement) (int, bool) {
	if e.Block != nil {
		return e.Block.DL, true
	}
	for _, c := range e.Token.Payload.Att {
		if c.Can != credential.CanAgentDelegate {
			continue
		}
		for _, con := range c.Constraints {
			if dd, ok := con.(credential.DelegationDepthConstraint); ok {
				return dd.Max, true
			}
		}
	}
	return 0, false
}

// ---- the thirteen steps ----

// step0Structural validates each element's structural invariants: an expiry is
// present, and size limits hold. The typ/alg/ucv tags and the I-JSON profile are
// already enforced when elements are parsed during chain building.
func step0Structural(chain *delegation.Chain) error {
	for i, e := range chain.Elements {
		if elemExp(e) <= 0 {
			return verr(0, CodeMalformed, nil, "element %d has no expiry", i)
		}
		if e.Token != nil {
			if len(e.Token.Payload.Att) > credential.MaxCapabilities {
				return verr(0, CodeMalformed, nil, "element %d exceeds capability limit", i)
			}
		} else {
			if len(e.Block.Cav) > credential.MaxCaveatsPerBlock {
				return verr(0, CodeMalformed, nil, "element %d exceeds caveat limit", i)
			}
			// SD-7: an unrecognized crit extension must be rejected. No crit
			// extensions are defined in this version, so any entry fails closed.
			if len(e.Block.Crit) > 0 {
				return verr(0, CodeMalformed, nil, "element %d carries unrecognized crit extension %q", i, e.Block.Crit[0])
			}
		}
	}
	return nil
}

// step1BuildChain resolves and assembles the chain, translating chain-build
// failures into verification codes.
func step1BuildChain(ctx context.Context, leafCID string, store delegation.ProofStore, maxDepth int) (*delegation.Chain, error) {
	chain, err := delegation.BuildChain(ctx, leafCID, store, maxDepth)
	if err != nil {
		return nil, mapChainError(err)
	}
	return chain, nil
}

func mapChainError(err error) *VerificationError {
	switch {
	case errors.Is(err, delegation.ErrCircularChain):
		return verr(1, CodeCircular, err, "circular delegation")
	case errors.Is(err, delegation.ErrChainTooDeep):
		return verr(1, CodeChainTooDeep, err, "chain too deep")
	case errors.Is(err, delegation.ErrChainTooWide):
		return verr(1, CodeMalformed, err, "chain exceeds capability+caveat limit")
	case errors.Is(err, delegation.ErrBranchingUnsupported):
		return verr(1, CodeBranching, err, "branching unsupported")
	case errors.Is(err, delegation.ErrProofNotFound):
		return verr(1, CodeProofCacheMiss, err, "proof not found")
	case errors.Is(err, delegation.ErrModeMixing):
		return verr(1, CodeChainBroken, err, "illegal mode mixing")
	case errors.Is(err, delegation.ErrCIDMismatch):
		return verr(1, CodeCIDMismatch, err, "cid mismatch")
	default:
		return verr(1, CodeChainBroken, err, "chain build")
	}
}

// step2Linkage checks per-hop linkage: issuer equals parent audience, prf pins
// the parent, the validity window does not widen, and depth-left strictly
// decreases (Section 11 step 2).
func step2Linkage(chain *delegation.Chain) error {
	for i := 0; i+1 < len(chain.Elements); i++ {
		child, parent := chain.Elements[i], chain.Elements[i+1]
		if elemIss(child) != elemAud(parent) {
			return verr(2, CodeChainBroken, nil, "hop %d: iss %q != parent aud %q", i, elemIss(child), elemAud(parent))
		}
		if elemParentCID(child) != parent.CID {
			return verr(2, CodeChainBroken, nil, "hop %d: prf does not pin parent", i)
		}
		if elemExp(child) > elemExp(parent) {
			return verr(2, CodeExpiryEscalate, nil, "hop %d: exp %d > parent %d", i, elemExp(child), elemExp(parent))
		}
		if elemNbf(child) < elemNbf(parent) {
			return verr(2, CodeChainBroken, nil, "hop %d: nbf %d < parent %d", i, elemNbf(child), elemNbf(parent))
		}
		if child.Block != nil {
			if pdl, ok := elemDelegableDepth(parent); ok && child.Block.DL >= pdl {
				return verr(2, CodeAttenuation, nil, "hop %d: dl %d not below parent %d", i, child.Block.DL, pdl)
			}
		}
	}
	return nil
}

// step3RootTrust checks that the root issuer is a trusted root or a platform
// named by a trust policy, returning whether the chain is cross-organizational.
func step3RootTrust(chain *delegation.Chain, config *VerifierConfig) (bool, error) {
	rootIss := elemIss(chain.Root())
	if config.TrustedRootDIDs[rootIss] {
		return false, nil
	}
	for _, p := range config.TrustPolicies {
		for _, platform := range p.Platforms {
			if platform == rootIss {
				return true, nil
			}
		}
	}
	return false, verr(3, CodeUntrustedRoot, nil, "root issuer %q is not trusted", rootIss)
}

// step4Signatures verifies every hop's signature under its resolved issuer key.
func step4Signatures(chain *delegation.Chain) error {
	for i, e := range chain.Elements {
		pub, err := identity.ResolveDID(elemIss(e))
		if err != nil {
			return verr(4, CodeDIDResolution, err, "element %d: resolve issuer %q", i, elemIss(e))
		}
		if e.Token != nil {
			if err := e.Token.Verify(pub); err != nil {
				return verr(4, CodeSigInvalid, err, "element %d: token signature", i)
			}
		} else if err := e.Block.Verify(pub); err != nil {
			return verr(4, CodeSigInvalid, err, "element %d: block signature", i)
		}
	}
	return nil
}

// step5Temporal checks that now falls within every element's validity window,
// widened by the clock-skew tolerance.
func step5Temporal(chain *delegation.Chain, now, clockSkew int64) error {
	for i, e := range chain.Elements {
		if now > elemExp(e)+clockSkew {
			return verr(5, CodeExpired, nil, "element %d expired at %d", i, elemExp(e))
		}
		if now < elemNbf(e)-clockSkew {
			return verr(5, CodeNotYetValid, nil, "element %d not valid until %d", i, elemNbf(e))
		}
	}
	return nil
}

// step6Revocation denies on any revoked, suspended, compromised, cascaded, or
// decommissioned subject. A nil cache means no revocation source is configured.
func step6Revocation(ctx context.Context, chain *delegation.Chain, cache RevocationCache, tier RiskTier, logger *slog.Logger) error {
	if cache == nil {
		return nil
	}
	subjects := make(map[string]struct{})
	for _, e := range chain.Elements {
		subjects[e.CID] = struct{}{}
		subjects[elemAud(e)] = struct{}{}
	}
	for subject := range subjects {
		entry, err := cache.GetStatus(ctx, subject)
		if err != nil {
			if tier == TierHigh {
				return verr(6, CodeRevocUnavailable, err, "revocation lookup for %q", subject)
			}
			// Lower tiers degrade-accept (Section 13.4): proceed despite the lookup
			// failure, but make the fail-open decision loud rather than silent.
			if logger != nil {
				logger.Warn("revocation lookup failed; degrade-accepting below HIGH tier (fail-open)",
					"subject", subject, "tier", tier.String(), "error", err)
			}
			continue
		}
		if entry == nil {
			continue // active
		}
		if e := statusError(entry.Status); e != nil {
			return e
		}
	}
	return nil
}

func statusError(status revocation.RevocationStatus) *VerificationError {
	switch status {
	case revocation.StatusRevoked, revocation.StatusDecommissioned:
		return verr(6, CodeRevoked, nil, "subject status %s", status)
	case revocation.StatusSuspended:
		return verr(6, CodeSuspended, nil, "subject status %s", status)
	case revocation.StatusCompromised, revocation.StatusCascade:
		return verr(6, CodeCompromised, nil, "subject status %s", status)
	default:
		return nil // REINSTATED or any non-denying status
	}
}

// step7Attenuation enforces integrity per hop. RESTRICT hops are escalation-free
// by construction (the earlier structural checks suffice); RESTATE hops require
// capability_leq plus a valid att_seal.
func step7Attenuation(chain *delegation.Chain) error {
	for i := 0; i+1 < len(chain.Elements); i++ {
		child := chain.Elements[i]
		if child.Mode != delegation.ModeRestate {
			continue
		}
		parent := chain.Elements[i+1]
		if parent.Token == nil {
			return verr(7, CodeChainBroken, nil, "hop %d: RESTATE parent is not a token", i)
		}
		if !credential.CapabilitiesSubset(child.Token.Payload.Att, parent.Token.Payload.Att) {
			return verr(7, CodeAttenuation, nil, "hop %d: restated capabilities exceed parent", i)
		}
		seal := child.Token.Header.Seal
		if seal == nil {
			return verr(7, CodeAttenuation, nil, "hop %d: RESTATE hop missing att_seal", i)
		}
		pub, err := identity.ResolveDID(child.Token.Payload.Iss)
		if err != nil {
			return verr(7, CodeDIDResolution, err, "hop %d: resolve seal signer", i)
		}
		if err := credential.VerifyAttSeal(seal, child.Token.Payload.Att, pub); err != nil {
			return verr(7, CodeAttenuation, err, "hop %d: att_seal", i)
		}
		if seal.Aud != child.Token.Payload.Aud || seal.Prf != elemParentCID(child) {
			return verr(7, CodeAttenuation, nil, "hop %d: att_seal aud/prf mismatch", i)
		}
	}
	return nil
}

// step8Authorization matches the request against the effective capability set
// (the nearest token's att) and then evaluates every constraint and caveat on
// the path against the invocation context.
func step8Authorization(chain *delegation.Chain, ctx InvocationContext) (*credential.Capability, error) {
	att := effectiveAtt(chain)
	var matched *credential.Capability
	for i := range att {
		if att[i].Can == ctx.Action && credential.URICovers(att[i].With, ctx.Resource) {
			matched = &att[i]
			break
		}
	}
	if matched == nil {
		return nil, verr(8, CodeCapInsufficient, nil, "no capability authorizes %q on %q", ctx.Action, ctx.Resource)
	}

	for _, con := range matched.Constraints {
		if err := evaluateConstraint(con, ctx); err != nil {
			return nil, verr(8, CodeCapInsufficient, err, "capability constraint %s", con.Kind())
		}
	}
	for _, e := range chain.Elements {
		if e.Block == nil {
			continue
		}
		for _, caveat := range e.Block.Cav {
			if err := evaluateConstraint(caveat, ctx); err != nil {
				return nil, verr(8, CodeCapInsufficient, err, "caveat %s", caveat.Kind())
			}
		}
	}
	return matched, nil
}

// effectiveAtt returns the capability set that binds the leaf: the att of the
// nearest token walking from the leaf toward the root. RESTRICT blocks carry no
// att, so the binding set is the most-recent RESTATE hop's att, or the root's.
func effectiveAtt(chain *delegation.Chain) []credential.Capability {
	for _, e := range chain.Elements {
		if e.Token != nil {
			return e.Token.Payload.Att
		}
	}
	return nil
}

// step9CrossOrg validates cross-organizational chains against the matching trust
// policy (bilateral, non-transitive). Same-org chains pass trivially.
func step9CrossOrg(chain *delegation.Chain, policies []TrustPolicy, crossOrg bool) error {
	if !crossOrg {
		return nil
	}
	rootIss := elemIss(chain.Root())
	for _, p := range policies {
		for _, platform := range p.Platforms {
			if platform != rootIss {
				continue
			}
			if p.MaxDelegationDepth > 0 && chain.Depth > p.MaxDelegationDepth {
				return verr(9, CodeCrossOrg, nil, "chain depth %d exceeds policy max %d", chain.Depth, p.MaxDelegationDepth)
			}
			return nil
		}
	}
	return verr(9, CodeCrossOrg, nil, "no trust policy for root issuer %q", rootIss)
}

// step10PoP performs proof-of-possession and channel-binding checks.
func step10PoP(inv *UCANInvocation, leafAudDID string, config *VerifierConfig) error {
	if inv == nil {
		return verr(10, CodePoPFailed, nil, "no invocation supplied")
	}
	// Reject invocations created before this daemon instance booted: the nonce
	// cache for that period is gone, so replays could otherwise slip through.
	if config.StartTime > 0 && inv.Iat < config.StartTime {
		return verr(10, CodePoPFailed, nil, "invocation iat %d predates this daemon instance (start %d)", inv.Iat, config.StartTime)
	}
	if err := VerifyInvocation(inv, config.VerifierDID, leafAudDID, config.NonceCache); err != nil {
		return err
	}
	if config.ExpectedChannelBinding != "" && inv.CB != config.ExpectedChannelBinding {
		return verr(10, CodePoPFailed, nil, "channel binding mismatch")
	}
	return nil
}

// step11Registration verifies that the leaf credential was registered before
// first use (Section 11 step 11). A nil checker means no registration store is
// configured: degrade-accept for backwards compatibility. At HIGH tier an
// unregistered leaf fails closed; at lower tiers it degrade-accepts.
func step11Registration(ctx context.Context, chain *delegation.Chain, tier RiskTier, checker RegistrationChecker, logger *slog.Logger) error {
	if checker == nil {
		return nil
	}
	leafCID := chain.Leaf().CID
	if checker.Contains(ctx, leafCID, leafCID) {
		return nil
	}
	if tier == TierHigh {
		return verr(11, CodeUnregistered, nil, "leaf credential %s is not registered", leafCID)
	}
	if logger != nil {
		logger.Warn("leaf credential not registered; degrade-accepting below HIGH tier",
			"cid", leafCID, "tier", tier.String())
	}
	return nil
}

// step12Audit records the verification outcome as a hash-linked audit entry
// (Section 11 step 12, Section 14).
func step12Audit(chain *delegation.Chain, leafAud string, log audit.AuditLog, now int64) error {
	if log == nil {
		return nil
	}
	return log.Append(audit.AuditEntry{
		EventType: audit.EventCapabilityInvoked,
		AgentID:   leafAud,
		CredCID:   chain.Leaf().CID,
		Ts:        now,
		Payload:   map[string]any{"result": "ALLOW"},
	})
}

// evaluateConstraint checks one constraint or caveat against the invocation
// context. Verification-time predicates are enforced here; cumulative
// (budget, max_calls) and enforcement-time (parameter_schema) predicates are
// satisfied structurally and metered or enforced downstream. An unmodeled type
// fails closed (Section 8.2).
func evaluateConstraint(c credential.Constraint, ctx InvocationContext) error {
	switch v := c.(type) {
	case credential.TimeWindowConstraint:
		if ctx.Now < v.Start || ctx.Now >= v.End {
			return fmt.Errorf("now %d outside [%d,%d)", ctx.Now, v.Start, v.End)
		}
		return nil
	case credential.ResourceRestrictConstraint:
		if !credential.URICovers(v.Resource, ctx.Resource) {
			return fmt.Errorf("resource %q not covered by %q", ctx.Resource, v.Resource)
		}
		return nil
	case credential.MethodRestrictConstraint:
		method, ok := ctx.Parameters["method"].(string)
		if !ok {
			return fmt.Errorf("no method parameter")
		}
		for _, m := range v.Methods {
			if m == method {
				return nil
			}
		}
		return fmt.Errorf("method %q not allowed", method)
	case credential.ParamLimitConstraint:
		raw, present := ctx.Parameters[v.Field]
		if !present {
			return nil
		}
		n, ok := numericParam(raw)
		if !ok {
			// A non-integer or out-of-int64-range value cannot be safely bounded;
			// fail closed rather than truncate/overflow it past the limit.
			return fmt.Errorf("parameter %q is not an integer within int64 range", v.Field)
		}
		if n > v.Max {
			return fmt.Errorf("parameter %q = %d exceeds %d", v.Field, n, v.Max)
		}
		return nil
	case credential.BudgetConstraint, credential.MaxCallsConstraint:
		// Cumulative caveats require a metering backend. Without one they cannot be
		// honored, so a delegation restricted only by such a caveat must not be
		// silently treated as unrestricted: fail closed.
		if !ctx.MeteringEnabled {
			return fmt.Errorf("%s caveat requires a metering backend (not configured)", c.Kind())
		}
		return nil
	case credential.DelegationDepthConstraint:
		return nil // issuance-time only
	case credential.ParameterSchemaConstraint:
		if !ctx.MeteringEnabled {
			return fmt.Errorf("parameter_schema caveat requires an enforcement backend (not configured)")
		}
		return nil
	default:
		return fmt.Errorf("unevaluable caveat type %q", c.Kind())
	}
}

// numericParam coerces an invocation parameter to int64. Integer Go values pass
// through; a float64 (the type JSON numbers decode to) is accepted only when it
// is integral and within int64 range. Non-integers and out-of-range magnitudes
// return false so the caller fails closed instead of truncating or overflowing.
func numericParam(v any) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int64:
		return n, true
	case float64:
		if n != math.Trunc(n) || n < math.MinInt64 || n >= math.MaxInt64 {
			return 0, false
		}
		return int64(n), true
	default:
		return 0, false
	}
}
