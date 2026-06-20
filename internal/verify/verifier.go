package verify

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/Zahanturel/adtp/internal/audit"
	"github.com/Zahanturel/adtp/internal/credential"
	"github.com/Zahanturel/adtp/internal/delegation"
)

// slowThresholdMs is the latency above which a verification is reported slow
// (Section 11 performance budget: online-revocation path ≤ 10 ms).
const slowThresholdMs = 10.0

// VerifierConfig holds a verifier's policy and dependencies.
type VerifierConfig struct {
	// VerifierDID is this verifier's identity; an invocation's aud must equal it.
	VerifierDID string
	// TrustedRootDIDs are the platform roots this verifier trusts directly.
	TrustedRootDIDs map[string]bool
	// MaxChainDepth caps delegation hops (default 10).
	MaxChainDepth int
	// ClockSkewSeconds is the temporal tolerance (default 60).
	ClockSkewSeconds int64
	// RiskTierFn classifies a resource's risk tier (default MEDIUM).
	RiskTierFn func(resource string) RiskTier
	// ProofStore resolves chain credentials by CID.
	ProofStore delegation.ProofStore
	// NonceCache defeats invocation replay.
	NonceCache NonceCache
	// RevocationCache reports subject revocation status (nil disables step 6).
	RevocationCache RevocationCache
	// RegistrationStore checks whether a credential is registered (nil
	// disables step 11, degrade-accept).
	RegistrationStore RegistrationChecker
	// TrustPolicies authorize cross-organizational roots.
	TrustPolicies []TrustPolicy
	// AuditLog records outcomes (nil disables step 12).
	AuditLog audit.AuditLog
	// ExpectedChannelBinding, when set, must match the invocation's cb.
	ExpectedChannelBinding string
	// StartTime, when > 0, is the daemon's boot time (UNIX seconds). Invocations
	// whose iat predates it are rejected: the in-memory nonce cache was empty
	// before boot, so a pre-boot invocation could otherwise be replayed once.
	StartTime int64
	// NowFn overrides the clock for testing (nil uses the system clock).
	NowFn func() int64
	// OnSlow, when set, is invoked for verifications slower than slowThresholdMs.
	OnSlow func(*VerificationResult)
	// MeteringEnabled reports whether a metering/enforcement backend is wired up.
	// When false (default), cumulative caveats (budget, max_calls) and
	// enforcement-time caveats (parameter_schema) fail closed instead of being
	// silently accepted as unrestricted.
	MeteringEnabled bool
	// Logger receives operational warnings such as degrade-accepted revocation
	// lookups. nil uses slog.Default().
	Logger *slog.Logger
}

func (c *VerifierConfig) logger() *slog.Logger {
	if c.Logger != nil {
		return c.Logger
	}
	return slog.Default()
}

func (c *VerifierConfig) now() int64 {
	if c.NowFn != nil {
		return c.NowFn()
	}
	return time.Now().Unix()
}

func (c *VerifierConfig) clockSkew() int64 {
	if c.ClockSkewSeconds > 0 {
		return c.ClockSkewSeconds
	}
	return 60
}

func (c *VerifierConfig) tierFor(resource string) RiskTier {
	if c.RiskTierFn != nil {
		return c.RiskTierFn(resource)
	}
	return TierMedium
}

// VerificationResult is the outcome of Verify.
type VerificationResult struct {
	OK                   bool
	Chain                *delegation.Chain
	AuthorizedCapability *credential.Capability
	Error                *VerificationError
	LatencyMs            float64
}

// Verify runs the 13-step algorithm (Section 11) for an invocation, failing fast
// on the first violation. The leaf credential is identified by the invocation's
// run.delegation CID and resolved from the proof store; token, when non-nil, is
// the inline leaf UCAN and is made resolvable for the walk.
func Verify(ctx context.Context, token *credential.UCAN, inv *UCANInvocation, config *VerifierConfig) *VerificationResult {
	start := time.Now()
	res := &VerificationResult{}

	finish := func() *VerificationResult {
		res.LatencyMs = float64(time.Since(start).Microseconds()) / 1000.0
		if res.LatencyMs > slowThresholdMs && config.OnSlow != nil {
			config.OnSlow(res)
		}
		return res
	}
	fail := func(e *VerificationError) *VerificationResult {
		res.OK = false
		res.Error = e
		// Audit the denial so attack probing leaves a trail (the audit log is not
		// ALLOW-only). Best-effort: an audit failure must not change the outcome.
		if config.AuditLog != nil {
			var credCID, agentID string
			if res.Chain != nil && len(res.Chain.Elements) > 0 {
				credCID = res.Chain.Leaf().CID
				agentID = elemAud(res.Chain.Leaf())
			}
			_ = config.AuditLog.Append(audit.AuditEntry{
				EventType: audit.EventCapabilityDenied,
				AgentID:   agentID,
				CredCID:   credCID,
				Ts:        config.now(),
				Payload:   map[string]any{"result": "DENY", "code": string(e.Code), "step": e.Step},
			})
		}
		return finish()
	}

	if inv == nil {
		return fail(verr(10, CodePoPFailed, nil, "no invocation supplied"))
	}
	leafCID := inv.Run.DelegationCID
	if leafCID == "" {
		return fail(verr(0, CodeMalformed, nil, "invocation has no delegation CID"))
	}

	store := effectiveStore(config, token)

	chain, err := step1BuildChain(ctx, leafCID, store, config.MaxChainDepth)
	if err != nil {
		return fail(asVErr(err))
	}
	res.Chain = chain

	if e := asVErr(step0Structural(chain)); e != nil {
		return fail(e)
	}
	if e := asVErr(step2Linkage(chain)); e != nil {
		return fail(e)
	}
	crossOrg, e3 := step3RootTrust(chain, config)
	if e3 != nil {
		return fail(asVErr(e3))
	}
	if e := asVErr(step4Signatures(chain)); e != nil {
		return fail(e)
	}
	if e := asVErr(step5Temporal(chain, config.now(), config.clockSkew())); e != nil {
		return fail(e)
	}

	tier := config.tierFor(inv.Run.Resource)
	if e := asVErr(step6Revocation(ctx, chain, config.RevocationCache, tier, config.logger())); e != nil {
		return fail(e)
	}
	if e := asVErr(step7Attenuation(chain)); e != nil {
		return fail(e)
	}

	invCtx := InvocationContext{
		Action:          inv.Run.Action,
		Resource:        inv.Run.Resource,
		Parameters:      inv.Run.Parameters,
		Now:             config.now(),
		MeteringEnabled: config.MeteringEnabled,
	}
	authorized, e8 := step8Authorization(chain, invCtx)
	if e8 != nil {
		return fail(asVErr(e8))
	}
	res.AuthorizedCapability = authorized

	if e := asVErr(step9CrossOrg(chain, config.TrustPolicies, crossOrg)); e != nil {
		return fail(e)
	}
	if e := asVErr(step10PoP(inv, elemAud(chain.Leaf()), config)); e != nil {
		return fail(e)
	}
	if e := asVErr(step11Registration(ctx, chain, tier, config.RegistrationStore, config.logger())); e != nil {
		return fail(e)
	}
	_ = step12Audit(chain, elemAud(chain.Leaf()), config.AuditLog, config.now())

	res.OK = true
	return finish()
}

// asVErr coerces a step error into a *VerificationError.
func asVErr(err error) *VerificationError {
	if err == nil {
		return nil
	}
	var ve *VerificationError
	if errors.As(err, &ve) {
		return ve
	}
	return verr(0, CodeMalformed, err, "internal verification error")
}

// effectiveStore returns the proof store to walk, overlaying the inline leaf
// token (if any) so it resolves by CID without separate storage.
func effectiveStore(config *VerifierConfig, token *credential.UCAN) delegation.ProofStore {
	var base delegation.ProofStore = emptyStore{}
	if config.ProofStore != nil {
		base = config.ProofStore
	}
	if token == nil {
		return base
	}
	return overlayStore{base: base, cid: token.CID(), raw: []byte(token.String())}
}

type emptyStore struct{}

func (emptyStore) Get(_ context.Context, cid string) ([]byte, error) {
	return nil, fmt.Errorf("%w: %s", delegation.ErrProofNotFound, cid)
}

type overlayStore struct {
	base delegation.ProofStore
	cid  string
	raw  []byte
}

func (o overlayStore) Get(ctx context.Context, cid string) ([]byte, error) {
	if cid == o.cid {
		return o.raw, nil
	}
	return o.base.Get(ctx, cid)
}
