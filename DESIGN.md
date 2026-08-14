# Design notes

Why ADTP is shaped the way it is, what was rejected on the way there, and what the
implementation taught that the design did not anticipate.

Read [README.md](README.md) first for what the thing does.

## The property everything else follows from

The requirement was not "attenuate capabilities." Macaroons solved that in 2014. The
requirement was **revoke a delegation and have every descendant stop working**, which is a
different problem, and it constrains the credential format more tightly than attenuation
does.

To deny a descendant when you revoke its ancestor, a verifier must be able to get from the
descendant to the ancestor. That means the child has to *name* the parent, and name it in a
way the child cannot lie about. Everything else in this design is downstream of that one
sentence:

- The child carries `prf`, the parent's content hash.
- The hash is over the parent's **complete serialized bytes including its signature**, so
  pinning the hash pins content and signature together — you cannot swap in a different but
  validly-signed parent.
- Verification therefore always walks to the root, because it cannot check the chain
  without resolving every link.
- And once you are walking the whole chain anyway, checking each element against revocation
  state is nearly free.

That last step is the revocation guarantee. It is not a clever algorithm; it is a
consequence of the chain being walkable and the walk being mandatory.

## Why UCAN, and not macaroons, biscuits, or scoped JWTs

**Scoped JWTs — rejected because there is no chain.** A JWT with `scope: "read:files"` names
no parent. When an agent delegates, it either hands over the same token or gets a new one
minted by the issuer, and in neither case does the resulting token record that a delegation
happened. There is nothing to walk, so transitive revocation is not implementable at any
price: you can revoke the token you name (RFC 7009) and that is the end of your reach.
Scope subsetting is also string comparison, with all the prefix-matching hazards that
implies. The one thing JWTs bring — ubiquitous tooling — UCAN brings too, because a UCAN
*is* a JWS.

**Macaroons — rejected for the verification model, not the attenuation model.** Macaroons
got the attenuation idea right first, and RESTRICT is closer to a macaroon than to anything
in the UCAN spec: append caveats, never restate authority, intersect at verification. The
disqualifier is HMAC. A macaroon is verified with the root secret, so any party that can
*check* a macaroon can also *mint* one. That is workable inside one trust domain and
useless across organizations, which was a stated goal. It also forfeits non-repudiation —
an HMAC chain cannot prove *which* party added a caveat, only that someone holding the
lineage did — and non-repudiation is most of the point of an audit log for autonomous
agents. Third-party caveats exist and would recover some of this, at the cost of a
discharge protocol in the hot path.

**Biscuits — the closest call, and rejected on trusted-computing-base size.** Biscuits are
public-key (Ed25519), append-only, and offline-verifiable, so they clear the bar macaroons
failed. Their attenuation blocks give the same "can only add" property RESTRICT gives. The
difference is what authorization *is*: in Biscuit it is Datalog evaluation, so a Datalog
engine sits in the trusted computing base. That engine is more expressive than anything
here — genuinely more expressive, and for policy-rich environments it is the better tool —
but it is also more surface to get wrong, and its behaviour on adversarial input is harder
to bound than a fixed vocabulary of eight caveat types with a `default:` branch that
denies.

This was a judgment call about which risk to take, not a claim that Biscuit is worse. If
the goal had been expressive authorization policy rather than bounded revocable delegation,
Biscuit would be the right answer. It is worth saying plainly that a RESTRICT block is
close to "a Biscuit block with a closed caveat vocabulary instead of Datalog," and that the
closed vocabulary is the entire delta.

**UCAN — chosen for `prf`.** Not for its attenuation story, which ADTP largely does not use.
UCAN's `prf` field is an explicit, content-addressed pointer from child to parent, and that
is the property the revocation requirement demanded. Riding the JWS compact format for the
root credential also means existing JWT tooling parses it, which lowers the cost of the
whole thing being unfamiliar.

What UCAN cost: `prf` is an array, which invites multi-proof chains where a credential
derives authority from several parents. That turns the chain into a DAG, and authorization
into a union across branches — which reintroduces exactly the set arithmetic RESTRICT was
built to avoid. ADTP rejects branching outright
([`internal/delegation/chain.go`](internal/delegation/chain.go): more than one `prf` is
`ErrBranchingUnsupported`). This is a real capability given up. Multi-parent delegation is
a reasonable thing to want and this design cannot express it.

## RESTRICT versus RESTATE: the same protocol with two different trusted computing bases

This is the most interesting thing in the codebase, and the two modes are worth comparing
directly because they make the cost of semantic comparison legible.

**RESTATE** is conventional delegation. The child restates its capability set and the
verifier checks containment:

```go
// internal/verify/steps.go, step 7
if !credential.CapabilitiesSubset(child.Token.Payload.Att, parent.Token.Payload.Att) {
    return verr(7, CodeAttenuation, nil, "hop %d: restated capabilities exceed parent", i)
}
```

`CapabilitiesSubset` calls `CapabilityLeq`
([`internal/credential/capability_leq.go`](internal/credential/capability_leq.go)) — 115
lines that must decide, for every pair of constraint kinds, whether the child is at least as
tight as the parent. Whether one URI covers another. Whether a `nil` budget window means
"unbounded" (it does, for a parent) or "broader than the parent's" (it does, for a child).
Whether an unmodeled constraint type is safe to permit (it is not; the `default:` branch
returns false). Every one of those decisions is load-bearing: get one wrong and a child
mints authority its parent never held.

The code is careful. It fails closed on unknown types, it fails closed on URIs that fail
canonicalization, it requires `delegation_depth` to attenuate strictly while everything else
attenuates non-strictly. It is also, unavoidably, **trusted computing base** — and the file
says so in its own doc comment rather than leaving it to be discovered.

**RESTRICT** deletes the problem. The block carries no capability set, so step 7 has nothing
to compare and skips the hop entirely:

```go
for i := 0; i+1 < len(chain.Elements); i++ {
    child := chain.Elements[i]
    if child.Mode != delegation.ModeRestate {
        continue   // RESTRICT: escalation-free by construction, nothing to check
    }
    ...
}
```

The invariants that make this safe are all structural checks on scalars, done in step 2:
`child.exp <= parent.exp`, `child.nbf >= parent.nbf`, `child.dl < parent.dl`,
`child.iss == parent.aud`, `child.prf == parent.CID`. Integer and string comparisons, no
semantics. Authority is computed at invocation time as the root's capability set
intersected with every caveat on the path — and because step 8 walks *every block in the
chain*, a child cannot escape a parent's caveat by omitting it.

The distinction that matters: in RESTATE, a malicious delegator writes a broader capability
into a field and the verifier's job is to *notice*. In RESTRICT there is no such field, so
the verifier has no such job.

That removes one class of attack. It does not leave nothing behind, and an earlier version of
this document claimed it did — "the attack surface is not reduced; it is absent," with the
only residue being a forged Ed25519 signature or a SHA-256 collision on `prf`. That was
wrong, and the shape of the error is worth keeping on the page.

RESTRICT replaces capability *comparison* with a set of scalar invariants. A comparison can
be subtly wrong; a scalar invariant can be flatly missing — and a missing invariant does not
present as an attack surface at all until someone probes for it, because there is no code to
audit. `dl` had a ceiling and no floor: `child.dl < parent.dl` was enforced at verification,
`child.dl >= 0` was enforced only in the minting path, and a block at `dl=-1` under a parent
at `dl=0` verified end to end (F14 in [SECURITY_AUDIT.md](SECURITY_AUDIT.md)). No comparison
code was involved, nothing was forged, and no collision was needed.

The defensible claim is narrower: RESTRICT makes the verifier's obligations *enumerable* —
a handful of scalar checks in place of a semantic subset test. Enumerable is a real
advantage, and it is worth only as much as the enumeration is complete and enforced at every
point the object is admitted.

Eight adversarial vectors in
[`internal/verify/adversarial_test.go`](internal/verify/adversarial_test.go) attack RESTRICT
with a real signing key and arbitrary forged payloads — depth escalation, depth *de-escalation*
below zero, expiry escalation, `nbf` regression, issuer/audience linkage break, caveat removal
by a child, revoked-credential replay, unknown-constraint smuggling. Each asserts the specific
step and error code that caught it. None target RESTATE.

The negative-depth vector was added after an external audit exploited it: the original seven
probed `dl` upward only, and the verifier bounded it only from above, so `dl=-1` under a
parent at `dl=0` verified end to end. That is recorded as F14 in
[SECURITY_AUDIT.md](SECURITY_AUDIT.md), along with the withdrawal of the claim it falsified.

**The uncomfortable part.** ADTP ships both. RESTATE exists for compatibility with protocol
v0.2 — a version with no implementations and no users. So the codebase carries 115 lines of
trusted computing base, an entire `att_seal` mechanism, and a mode-mixing rule
(`RESTATE`-after-`RESTRICT` is prohibited, because restating an intersection would drag
semantic comparison back in) in order to be compatible with nothing. That is the single
clearest thing this implementation revealed, and it is addressed under "what I would do
differently."

### On `att_seal`

RESTATE hops carry a second signature over the canonicalized capability set. It is worth
being precise about what it does, because an earlier version of the spec overclaimed it and
the correction is instructive.

The seal defends against **serialization differentials**: the gap between the bytes that
were signed and the structure the application parsed — duplicate-key smuggling, encoding
divergence. Forcing the verifier to recompute a digest over the *parsed, canonicalized*
capabilities and match it against the sealed digest closes that gap.

It does **not** extend the trust model, because the seal signer is the hop issuer — the same
key that signed the token. A malicious issuer signs escalated capabilities and then signs a
seal over them just as willingly. The v0.2 claim that `att_seal` made delegation integrity
sound independently of `CapabilityLeq` was withdrawn, and
[`internal/credential/attseal.go`](internal/credential/attseal.go) states the narrower
property in its doc comment. RESTRICT needs no seal at all, because it commits to no
capability set.

## Why did:key, not did:web

`did:key` puts the public key inside the identifier. Resolution is parsing:

```go
// internal/identity/didkey.go
func ResolveDID(did string) (ed25519.PublicKey, error) { return ParseDID(did) }
```

No network call in the verification path. No DNS, no TLS handshake, no registry, no cache
staleness, no availability dependency on someone else's web server during an authorization
decision. For agents — which are numerous, short-lived, and created programmatically — that
is the right trade. `did:web` would put a DNS-and-HTTPS fetch inside every verification, and
introduce domain seizure as a key-substitution attack that only certificate pinning
mitigates.

What `did:key` gives up, in order of how much it matters:

**Rotation is identity change.** The key *is* the name, so rotating the key produces a
different agent. Every delegation naming the old identity becomes undeliverable. The
protocol design answers this with a dual-signed continuity record binding audit lineage
across the rotation without transferring credentials; it is not implemented.

**A static `did:key` is a global correlator.** The same agent presents the same identifier to
every verifier it ever talks to, so verifiers can correlate activity and infer delegation
topology and sponsor relationships. The mitigations — pairwise identifiers per counterparty,
and a delegation-gateway pattern where a boundary agent reissues fresh single-hop grants to
hide internal structure — are designed and not implemented. Anyone deploying this should
know that full delegation chains leak organizational structure to every relying party.

**No human-meaningful names.** `did:key:z6Mkve...` identifies precisely and communicates
nothing.

The intended shape was `did:key` for agents and `did:web` with pinned root keys for
organizations, which is why `ResolveDID` exists as a separate name from `ParseDID` — it
marks the seam where a network-resolving method would attach. Only the agent half was built,
which is the direct reason cross-organizational trust is unreachable in the daemon: the
`TrustPolicy` type exists, and nothing constructs one.

## Why the wire identifiers still say AITP

The project was renamed from Agent **I**dentity and Trust Protocol to Agent **D**elegation
and Trust Protocol. Three identifiers did not follow it:

- `DomainPrefix = "AITP1"` — the signature domain separator
  ([`internal/signing/sign.go`](internal/signing/sign.go))
- `/.well-known/aitp` — verifier and organization metadata
- `_aitp` — the reserved key in JSON-RPC transport bindings

The signing input is `"AITP1" || 0x00 || JCS(object minus its sig field)`. That string is
not a name anyone reads; it is a constant inside a hash preimage. Its only job is domain
separation — making a signature over an ADTP object fail to validate as a signature over
anything else — and the only property that matters for that job is **stability**. Changing
it to `"ADTP1"` would change every signing input, which invalidates every signature ever
produced and makes every stored credential unverifiable. The benefit would be cosmetic
consistency in a string that appears in no user interface and no error message.

The same reasoning covers `/.well-known/aitp` and `_aitp`: they are wire identifiers that
other implementations key on, and a rename is a compatibility break bought for tidiness.

The honest caveat: this repository has no users, so nothing would actually break today. The
freeze is a discipline rather than a necessity. But a protocol that renames its domain
separator when the marketing changes has not really frozen anything, and `docs/PROTOCOL.md`
documents the prefix as frozen. The rule worth keeping is: **identifiers that appear in a
hash preimage or on the wire are frozen at first publication; identifiers that appear in
prose are free.** The `typ` tags (`adtp/ucan/1`, `adtp/cav/1`, …) were renamed under that
rule, before the spec was published in this repository and while there was demonstrably
nothing to break.

## Scope

The protocol was designed as a research disclosure, and it covers considerably more than has
been built. This repository is a reference implementation of the core: identity, chains,
RESTRICT and RESTATE delegation, verification, revocation, audit.

Designed and specified, not implemented:

- **Transparency-log-backed registration** — an append-only Merkle log with witness
  cosigning, signed registration timestamps, and consistency proofs, gating authorization at
  the higher risk tiers. What exists instead is a local hash-linked audit log and a local
  registration index.
- **`on_behalf_of` dual-chain verification** — dual-principal authorization for
  confused-deputy mitigation. Invocations carrying the field are *rejected* rather than
  silently accepted, so the gap fails closed
  ([`internal/verify/pop.go`](internal/verify/pop.go)).
- **TLS-exporter channel binding** — the `cb` field is compared as an opaque string; there is
  no RFC 8446 exporter integration.
- **Session credentials** — symmetric-keyed data plane with lifetime pinned to the tier's
  revocation-staleness bound.
- **Budget metering** — the caveat vocabulary exists and is signed correctly; the counters
  and receipt chains do not, so those caveats deny.
- **did:web organizational federation** — trust documents, pinned root keys, trust bundles,
  key-rotation ceremony.
- **Transport bindings** — MCP over HTTP and stdio, A2A task metadata.

The protocol specification describes all of these as normative. The implementation does not
have them. Both statements are true at once, which is ordinary for a spec that preceded its
implementation, and the specification should be read as design intent rather than as a
description of this binary.

## What I would do differently

**Not ship RESTATE.** It is the only reason a capability-comparison function exists in the
trusted computing base, and it buys compatibility with a protocol version that never had an
implementation. Removing it would delete `CapabilityLeq`, the `att_seal` machinery, the
mode-mixing rule, and roughly a third of the conceptual surface — and would let the central
claim be stated without a qualifier. The lesson generalizes: a compatibility mode for a
predecessor with no users is not compatibility, it is a second system to secure.

**Stop overloading risk tiers.** `RiskTier` currently answers two unrelated questions: how
sensitive is this resource, and what should happen when the revocation store is unreachable.
Those are different decisions with different owners, and fusing them means you cannot say
"this resource is low-sensitivity" without also saying "and I will accept possibly-revoked
credentials for it during an outage." They should be separate settings, and the fail-open
one should be explicit enough that nobody sets it by accident.

**Enforce `Scope` or delete it.** Revocation entries carry `credential` / `subtree` /
`identity`, the authority model validates which actors may use which scope, and then
verification ignores the field entirely — every denying status denies the whole subtree. The
behaviour is safe but the field is decorative, and a decorative security field is worse than
no field, because people build policy on it.

**Decide the key-custody model before designing the API.** The daemon is custodial: it
generates agent keys, holds them, and signs on each agent's behalf. That is a defensible
design, but it was implicit rather than chosen, and the storage layer was built for
credentials while keys lived only in a `sync.Map`. The result was a service that looked
durable with PostgreSQL configured and was not. Keys now persist, in plaintext, which is
the honest version of custody rather than the safe one; HSM-backed custody is still the
right destination.

**Do not define a caveat you cannot enforce.** `budget`, `max_calls`, and `parameter_schema`
are fully specified, correctly signed, and always denied, because the metering engine does
not exist. Failing closed is right — treating an unenforceable budget as unlimited would be
the dangerous alternative — but shipping the vocabulary ahead of the engine produced three
types that are documented, valid, and useless.

**And the one the implementation actually taught:** the revocation completeness argument was
wrong about its own mechanism. The design credited completeness to a registration invariant
— every authorized chain is registered, therefore enumerable, therefore cascadable. The code
achieves it a different way: step 1 must reconstruct the chain to its root, step 6 checks
every element in it, so a revoked ancestor denies its subtree whether or not anything was
ever enumerated. The chain walk is strictly more robust than the invariant, because it does
not depend on the index being complete. The design had been reasoning about the wrong
guarantee for two revisions, and only writing the verifier made that visible.
