# ADTP v0.3 — Protocol Specification

## Agent Delegation and Trust Protocol

---

## Reading this document

**Part I is normative and describes what the daemon in this repository actually does.**
Every mechanism in Part I is implemented, tested, and reachable through `adtpd`.

**Appendix A is a roadmap.** Its sections were specified before they were built and none of
them are built. They are retained because they record design intent, and they are segregated
because mixing them with Part I forced every serious reader to do reconciliation work before
they could evaluate anything. A previous revision of this document described roughly 40% more
system than the binary implements, without saying so.

Section numbers are preserved from the pre-segregation revision, so Appendix A's sections are
numbered 12, 14, 15, 16, 19, 20, 21 and 23 rather than renumbered. External references still
resolve; the numbering is non-contiguous on purpose.

Where Part I describes something implemented but not enforced — the metering-dependent caveats
are the main case — it says so at that point.

---

## 1. What ADTP Is

A cryptographic protocol for AI agent identity, delegation, and credential lifecycle.

**What it is for.** Producing a non-repudiable, per-hop, issuer-signed, hash-linked record of
which agent authorized which sub-agent to do what, such that revoking any element of that
record denies the entire subtree beneath it at verification time, without enumerating
descendants. Transitive denial is the property this protocol is organized around; everything
else serves it.

**Architecture (implemented).** UCAN-compatible JWT root credentials rooted in did:key,
Ed25519 only. One attenuation mode: RESTRICT — monotone caveat blocks, with no
set-containment comparison in chain validation. Proof-of-possession invocations. Risk-tiered
revocation with an explicit authority model and cascade. A hash-linked local audit log. A
local registration index.

**Prior art, stated up front.** Restriction-only attenuation is established prior art —
macaroons (NDSS 2014), Biscuit v2/v3, UCAN 1.0's `cmd`+`pol`, and the object-capability
caretaker pattern all express it, and AIP ([arXiv 2603.24775](https://arxiv.org/abs/2603.24775),
[draft-prakash-aip-00](https://datatracker.ietf.org/doc/draft-prakash-aip/)) ships the same
model. This protocol arrived at it independently, which is not the same as arriving at it
first. The closed caveat vocabulary versus Biscuit's Datalog is an engineering tradeoff — a
smaller trusted computing base for strictly less expressiveness — not a discovery. See the
README's Prior art section and DESIGN.md.

**Not in this document's normative part:** transparency logs, session credentials,
organizational federation, transport bindings, post-quantum migration. See Appendix A.

---
## 2. Entity Definitions

**Principal:** Any entity that can authorize actions. Tuple: `(id, key_material, authority_scope)`.

**Sponsor:** A principal (human or organization) recorded at agent registration; ultimately accountable for the agent. Holds: registration cosignature duty for HIGH-tier agents, unilateral identity-revocation right (Section 13.1), and sponsorship-transfer right (ATL-logged, Section 17).

**Agent:** A principal with a sponsor, an operational scope, an activity horizon, delegation capability (restriction-only in RESTRICT mode), and a registration record.

**Credential:** Root credential = UCAN JWT (`iss` platform did:web, `aud` agent did:key, `att` capabilities array max 100, `prf` = [], `exp` mandatory, `nbf`, `iat`, `alg`, `ucv`). Non-root hop = RESTRICT block (Section 8.2). A non-root UCAN token is rejected.

**Attenuation Block (cav):** Signed restriction-only delegation object (Section 8.2). Adds caveats; never restates authority.

**Delegation Chain:** Root credential plus ordered hops linked by `prf` CIDs. Per hop: `hop.iss == parent.aud`; `exp` non-increasing; `nbf` non-decreasing; depth-left strictly decreasing where present. Max depth: 10 default, 100 hard. Max 1,000 capabilities + caveats total per chain.

**Trust Relationship:** Bilateral org-to-org via signed ORG_TRUST document (Section 15). Non-transitive.

**Registry:** The role that records registrations and serves lookups. MAY be co-located with an ATL operator. Protocol-defined interface; operator-neutral (no vendor coupling in the protocol).

**Verifier:** Relying party executing the verification algorithm (Section 11); publishes `/.well-known/aitp` metadata (Section 16.4).

**Transparency Log (ATL):** Section 14. **Witness:** independent cosigner of ATL checkpoints.

---

## 3. Canonical Signing Discipline

These rules apply to every signed structure in the protocol. They exist to eliminate the ambiguous-input and cross-protocol-confusion bug classes at the root.

- **SD-1:** Every signed non-JWT object is a single JSON object with a mandatory `typ` field of the form `adtp/<kind>/<version>`. Kinds: `cav`, `seal`, `inv`, `rev`, `trust`, `bundle`, `ckpt`, `sess`, `rcpt`, `cont`, `meta`.
- **SD-2:** Signature input = ASCII `"AITP1"` || 0x00 || JCS(object with `sig` field removed). The `"AITP1"` prefix is frozen; changing it would invalidate all existing signatures. Domain separation is provided by the prefix plus `typ`. Raw concatenation of variable-length fields appears nowhere in the protocol.
- **SD-3:** I-JSON (RFC 7493) required for all signed structures. Duplicate keys MUST be rejected at parse time. All numeric protocol values are integers; monetary amounts are in minor units. No floats in signed objects.
- **SD-4:** JWTs (root UCANs) retain JWS compact form for ecosystem compatibility; the header MUST carry `typ: "adtp/ucan/1"` and `alg`; the payload is subject to SD-3.
- **SD-5:** CID profile: CIDv1, raw codec (0x55), multihash sha2-256, computed over the complete serialized credential bytes (JWS compact bytes for JWTs; JCS bytes including `sig` for objects). `prf` therefore pins both content and signature.
- **SD-6:** Verifiers MUST verify signatures over the received raw bytes, then parse. Any divergence between the raw-byte hash and the re-serialized hash of the parsed object ⇒ REJECT.
- **SD-7:** Unknown fields in signed objects are permitted (covered by the signature, ignored by processing) unless listed in a `crit` array (X.509-style). An unrecognized `crit` entry ⇒ REJECT.

---

## 4. Security Properties

Status vocabulary: **SOUND-BY-CONSTRUCTION** (structural; violation requires breaking a cryptographic primitive), **SOUND** (reduction argument to standard assumptions), **DEPENDENT** (correct iff a named component is correct), **ARGUED** (informal). No property is labeled VERIFIED — no formal model has been published.

**Read the "In this build" column first.** Several properties are stated over mechanisms that
Appendix A defers. Where a mechanism is not implemented, the property's status in this
document describes the design, not the daemon.

| ID | Property | Mechanisms | Status | In this build |
|----|----------|-----------|--------|---------------|
| P1 | Mutual Authentication | Ed25519 PoP + pinned org root keys | SOUND (argued) | **Partial** — Ed25519 PoP holds. Org root pinning is roadmap (§15). |
| P2 | Delegation Integrity | Monotone-by-construction: chain escalation requires forging an issuer signature or a SHA-256 collision. No set-containment comparison in chain validation; per-hop invariants are scalar. Authorization-time URI coverage remains and is not part of this property | **SOUND-BY-CONSTRUCTION** | **Holds.** See SECURITY_AUDIT.md F14 for a case where a *missing* scalar invariant was exploitable — structural does not mean self-enforcing. |
| P3 | Non-repudiation | Issuer signature per hop | SOUND (EUF-CMA) | **Holds** for the per-hop signature chain, which is the property this protocol is organized around. Transparency-log inclusion, which earlier revisions folded into this row, is roadmap (§14) and is not required for it. |
| P4 | Proof-of-Possession | Invocation signature + nonce + cache-restart quarantine | SOUND (argued) | **Partial.** Signature, nonce and quarantine hold. Channel binding is compared when configured but nothing supplies a TLS exporter. `on_behalf_of` is unimplemented and rejected. If `verify.allow_custodial_invocation` is enabled the daemon signs the invocation itself, and the property does not hold on that path — it defaults to off. |
| P5 | Revocability | Authority model + tiered staleness + explicit cascade + mandatory root-walk at verification | SOUND (argued) | **Holds for the verification path**, which is the strong claim: every ancestor CID and audience is checked on every verification, so revoking any ancestor denies the subtree. Does **not** hold for *published* state — explicit cascade entries are written only for `COMPROMISED`, so `/v1/status/{cid}` may report a denied credential as unrevoked. Earlier revisions attributed completeness to a "registration invariant"; that attribution was wrong, and the operative mechanism is the chain walk. |
| P6 | Auditability | Hash-linked local log | SOUND (SHA-256; truncation detectable) | **Partial.** The log is hash-linked and truncation is detectable. Its append error is discarded at step 12, so an audit outage never denies. Witness-cosigned checkpoints are roadmap (§14). |
| P7 | Offline Verifiability | Self-contained chains + cached revocation | HOLDS for MEDIUM/LOW/ANALYTICS only; HIGH requires online revocation | Holds as stated. |
| P8 | Scope Containment | Existential authorization + P2; no union operation; multi-proof prohibited | SOUND-BY-CONSTRUCTION | **Holds.** Branching is rejected outright. |
| P9 | Session Security | — | — | **Not applicable.** Sessions are roadmap (§12). |
| P10 | Minimal Disclosure | Pairwise DIDs, hash-only audit parameters | ARGUED | **Partial.** Audit parameters are hashed. Delegation Gateway is roadmap. |

**Not a property, but the largest gap:** the control plane authenticates callers and does not
authorize them. Any valid API key can revoke as the platform authority, verify as any agent
whose custodial key the daemon holds, and enumerate the store. See SECURITY_AUDIT.md F17.

---

## 5. Threat Model

**13 adversary classes:** the v0.2 twelve — A_net, A_cred, A_key, A_orch, A_reg, A_collude, A_dos, A_ghost, A_compose, A_econ, A_strategic, A_temporal — plus **A_parser** (serialization/parsing-differential adversary exploiting divergence between signed bytes and the application's parsed view).

**Named attacks and controls:** Delegation Escalation (requires signature forgery). Phantom Delegation (issuer signatures + CID pinning per SD-5). Confused Deputy (on_behalf_of dual-authorization). Circular Delegation (seen-CID set + depth limits + Section 8.6). Replay (nonce + iat window + channel binding + sessions). Filter Poisoning (per-issuer filter governance, Section 13.5). Budget Exhaustion / Salami Invocation (budget caveats, Section 7.6). Domain Seizure (org root key pinning, Section 15.1). Log Split-View (witness cosigning + gossip, Section 14.2). Cache-Restart Replay (quarantine, Section 10.5).

**Explicit non-goals:** Sybil resistance, reputation, agent behavioral safety, content authenticity. ADTP authenticates and authorizes; accountability anchors to sponsors; reputation systems may consume ATL data but are out of scope.

---

## 6. Cryptographic Primitives

- **Signing:** Ed25519 (current). Post-quantum migration to hybrid Ed25519+ML-DSA-65 composite signatures is planned for a future version; see Section 18 for the roadmap. Agents MAY remain Ed25519 through v1.x (short-lived leaves; signatures require contemporaneous security only). SLH-DSA-128s is under consideration for offline org root anchors.
- **Algorithm policy:** Verifiers publish minimum acceptable algorithms per role (root / intermediate / leaf / invocation) in `/.well-known/aitp`. A chain is REJECTED if its root algorithm is below the minimum regardless of leaf strength — anchor downgrade dominates.
- **Hashing:** SHA-256 everywhere (chain linkage, CIDs, ATL Merkle tree). Hash-based ATL proofs are PQ-durable (Section 14.5).
- **Canonicalization:** RFC 8785 JCS under SD-3 (I-JSON, integers only).
- **Identity:** did:key (agents); did:web as locator + pinned root keys as authority (organizations, Section 15.1).
- **Channel binding:** TLS Exporter (RFC 8446/5705), label `EXPORTER-ADTP-channel-binding`, empty context, 32 bytes. The exporter output is carried in the invocation's `cb` field and covered by the invocation signature (this removes the v0.2 circularity of deriving exporter context from the invocation itself). Verifier recomputes the exporter on its side of the TLS session and compares.

---

## 7. Capabilities, Constraints, and Caveats

### 7.1 Capability types
Five types: `tool/invoke`, `resource/read`, `resource/write`, `agent/delegate`, `api/call`. Closed set per `ucv`; new types require a version bump. Capabilities are critical by definition: a verifier that does not implement a type MUST NOT authorize actions against it and MUST reject invocations targeting it (fail closed). Chains containing unknown types remain valid for actions against known types.

### 7.2 URI profile (normative)
Applied at issuance and verification:
- RFC 3986 normalization: lowercase scheme and host; remove default ports; IDN hosts in A-label (punycode) form.
- Dot-segments (`.` or `..`) anywhere in a capability URI path ⇒ REJECT (no resolution is attempted).
- Percent-decoding of unreserved characters only; encoded separators (`%2F`, `%5C`, `%00`) ⇒ REJECT.
- Capability URIs carry no query and no fragment; parameter limits are expressed as constraints/caveats, never query strings.
- Trailing slash is significant.
- `URI_COVERS(parent, child)`: equal scheme, equal authority, parent path is a prefix of child path on whole-segment boundaries; a single `*` segment matches exactly one non-empty segment; `**` is reserved and undefined in v1.x.
- Verifiers MUST re-canonicalize and compare byte-equal to the issued form; mismatch ⇒ REJECT.

### 7.3 Constraint semantics — evaluation time
- **Invocation time:** every constraint and caveat on the path MUST be evaluated against the invocation context — `(action, resource, parameters, now, channel, metering state)`. Any unsatisfied predicate ⇒ DENY. This evaluation is verification step 8 and is not optional.

### 7.4 time_window
`[start, end)` half-open, UNIX seconds, integers (SD-3).

### 7.4.1 action_restrict
Narrows the set of abilities (`can` values) exercisable through the chain, intersecting whatever the path already permits.

```
{ "type": "action_restrict",
  "actions": [<can>, ...] }        // non-empty; each drawn from the closed set of Section 7.1
```

An action name outside the closed set of this `ucv` ⇒ REJECT at issuance. Conjunctive with every other caveat, so the effective action set is the intersection along the path and a child can only narrow it. Distinct from `method_restrict`, which is a predicate over an invocation *parameter*: `action_restrict` constrains the ability, not the payload.

Without it the `can` field is compared exactly once in the whole verifier — against the root's `att` at step 8 — so a root holding two abilities over one URI space cannot delegate either one alone. Read-only delegation was inexpressible before this caveat existed.

### 7.5 parameter_schema
v0.x: deep_equals (conservative). v1.0: decidable fragment **ADTP-PS1** — a conjunction of per-field predicates from {`const`, `enum`, integer `range [min, max]`, string `max_length`, regex from an RE1 subset (no backreferences, no lookaround)}. Implication checking is field-wise and decidable. Predicates outside the fragment are permitted as caveats: a caveat requires only evaluation, never implication.

### 7.6 Budget (cumulative authority metering)
Caveat:

```
{ "type": "budget",
  "dim": "<unit URI: iso4217:INR | calls | tokens | ...>",
  "limit": <int>,
  "window": <time_window> | null,        // null = credential lifetime
  "scope": "leaf" | "chain",
  "meter": "verifier" | "receipts" }
```

Semantics: **cumulative** across invocations within the window.
- `meter: "verifier"` — the verifier maintains a durable counter keyed `(scope CID, dim, window)`. Multi-node verifiers MUST serialize on a shared counter; per-node split counters are non-conformant.
- `meter: "receipts"` — on each allow the verifier returns a signed receipt `{ typ: "adtp/rcpt/1", scope_cid, dim, amount, cum, seq, window, sig }`. The invoker MUST present the latest receipt on the next invocation; a missing or forked receipt chain ⇒ DENY. Receipts are per-verifier.
- **Cross-verifier shared budgets** require either a metering service (interface in Section 16.5; operationally a product, not a protocol dependency) or **budget pre-splitting**: a delegator divides a budget into disjoint child branches, each carrying its own budget caveat; the parent's caveat remains as a conjunctive ceiling.
- Per-invocation maxima are a distinct caveat: `{ "type": "param_limit", "field": ..., "max": ... }`.

### 7.7 Lifetime profile
`exp` is mandatory on every credential and block; absence ⇒ structurally invalid at step 0.

| Role / Tier | Maximum lifetime |
|---|---|
| Org root key | 5 years (rotation ceremony, Section 15.2) |
| Platform root credential | 90 days |
| Intermediate hop | ≤ parent and ≤ 30 days |
| Leaf, HIGH | 1 hour |
| Leaf, MEDIUM | 24 hours |
| Leaf, LOW | 7 days |
| Leaf, ANALYTICS | 30 days |
| Invocation | 300 seconds |
| Session | min(leaf exp, tier staleness bound) — Section 12 |

### 7.8 Composition
The `att` array is a disjunction for authorization (match any). Caveat lists are conjunctive always. No union or amplification operation exists; multi-proof chains are prohibited in v1.x (P8).

### 7.9 Size limits
≤ 100 capabilities per token; ≤ 50 caveats per block; ≤ 1,000 capabilities + caveats per chain. Byte-identical duplicate entries collapse and count once.

---

## 8. Delegation Protocol

### 8.1 Root issuance
Platform issues a UCAN JWT: `iss` = platform did:web, `aud` = agent did:key, `att` = granted capabilities, `prf` = [], `exp` ≤ 90 days, header `typ: "adtp/ucan/1"`. The `agent/delegate` capability, if present, sets the initial depth-left (`dl`); its absence ⇒ the agent may not delegate.

### 8.2 RESTRICT block (primary mode)
Delegation A→B is a signed restriction object:

```
{ "typ": "adtp/cav/1",
  "iss": <A did:key>,            // MUST equal parent.aud
  "aud": <B did:key>,
  "prf": <CID(parent credential)>,
  "nbf": <int>, "exp": <int>,    // exp <= parent.exp; nbf >= parent.nbf
  "dl":  <int>,                  // = parent.dl - k, k >= 1
  "cav": [ <Caveat>, ... ],      // >= 1; conjunctive
  "crit": [ ... ],               // optional, SD-7
  "sig": <SD-2 signature by A> }
```

Effective authority of the leaf = root `att` ∧ every caveat on the path, evaluated at invocation time. A block adds restrictions only; no element below the root carries a capability set, and therefore **chain validation performs no set-containment comparison**. This is not the same as "no comparison": `URICovers` and `CanonicalizeURI` run at step 8 on every verification, and `evaluateConstraint` dispatches nine constraint types. What the structure removes is per-hop semantic comparison against a parent, where an error widens a credential; what remains runs once against the root's grant, where an error denies or misroutes a single request. Escalation via the chain requires forging an issuer signature or a SHA-256 collision on `prf` linkage. Unknown caveat types ⇒ REJECT (a restriction the verifier cannot evaluate must fail closed).

### 8.3 One delegation mode
There is no mode in which a hop restates a capability set. A chain is one root credential plus zero or more RESTRICT blocks; a non-root element carrying `att` is REJECTED at chain build.

RESTATE (the v0.2 compatibility form: a child UCAN with restated `att` ⊆ parent `att`, verified by `capability_leq` and sealed with `att_seal`) was specified through v0.2 and is **removed as of v0.2.0**. It existed for compatibility with a protocol version that never had an implementation, and it was the sole reason a capability-comparison function was in the trusted computing base. Removing it removed `capability_leq`, `att_seal`, the mode-mixing rule, and the `mode` parameter on the delegation API.

### 8.4 Mode mixing
Not applicable. One mode, no mixing rule.

### 8.5 Issuance registration
Online issuance (issuer has registry/ATL connectivity) SHOULD register at issuance: atomic write of the credential CID plus the `chain_contains_cid` array. Offline issuance is permitted; the chain becomes registered at first use (step 11, Section 11). **Cascade completeness invariant (specified; enforced at HIGH only in this build, against a local index — see Section 11 step 11):** no chain is authorized at HIGH or MEDIUM before all of its hops carry registration evidence (Section 13.6). Note that cascade completeness on the *verification* path does not depend on this invariant at all: it derives from the mandatory root-walk of step 1 plus the subject set of step 6. This replaces the v0.2 atomicity rule, which either centralized all issuance or silently broke cascade completeness for offline-minted chains.

### 8.6 Self-delegation
`iss == aud` is permitted only with a `dl` decrement and at least one caveat; otherwise REJECT (cycle and verification-budget hygiene; CID-distinct self-loops add no authority).

---

## 9. att_seal (Removed)

`att_seal` was a second signature over the canonicalized capability set of a RESTATE hop. It defended against serialization and parsing differentials only — it did not extend the trust model, because the seal signer was the hop issuer, the same key that signed the token. With RESTATE removed there is no hop that carries a capability set, so there is nothing to seal. The mechanism is gone from the implementation.

The differential it defended against is now handled where it actually arises, by SD-6: a RESTRICT block whose received bytes differ from the canonical re-serialization of the parsed object is REJECTED (see Section 3).

---

## 10. UCANInvocation (Proof-of-Possession)

```
{ "typ": "adtp/inv/1",
  "iss": <DID>,                 // presenter; MUST equal leaf aud
  "aud": <DID>,                 // target verifier
  "iat": <epoch>,               // within last 60 s
  "exp": <epoch>,               // <= iat + 300
  "nonce": <16 bytes>,
  "cb": <base64url(TLS-Exporter("EXPORTER-ADTP-channel-binding","",32))>,  // per 10.3/10.4
  "obo": {                      // OPTIONAL v0.x; REQUIRED v1.0 when acting for a distinct principal
    "principal": <DID>,
    "chain": [ <CID>, ... ],    // principal -> invoker authorization chain (inline or resolvable)
    "scope": { "action": ..., "resource": ... } },
  "run": {
    "delegation": <CID(leaf)>,
    "action": <string>,
    "resource": <URI>,
    "parameters": <map> },
  "sig": <SD-2 signature> }
```

- **10.1 on_behalf_of:** the authorization is itself an ADTP chain principal→invoker whose effective authority covers `run` scope. The verifier executes Section 11 on BOTH chains. This is the protocol-level confused-deputy control.
- **10.2 Resolution:** any referenced CID (chain hops, obo) is either inline in the transport envelope or fetchable from the issuer CAS / ATL CAS advertised in `/.well-known/aitp`. The verifier MUST verify the CID over fetched bytes (SD-5).
- **10.3 Channel binding:** REQUIRED for HIGH and MEDIUM over TLS transports; RECOMMENDED for LOW; not applicable for ANALYTICS. Mismatch with the verifier's own exporter output ⇒ DENY.
- **10.4 stdio binding:** on session start the server sends `{ ephemeral did:key, nonce }`. Invocations set `aud` to the ephemeral DID; replay to any other process fails the `aud` check. Ephemeral DID lifetime = process session.
- **10.5 Nonce:** 128-bit, fail-closed cache. Cache scope is the logical verifier service, not the node: multi-node deployments MUST share the cache or partition the nonce space deterministically (e.g., route by nonce prefix) so any replay within the validity window reaches the same authority. Cache instance identifier `_aitp_cache_instance` (128-bit random) is written at cache init; an ID change signals restart ⇒ 360 s quarantine: HIGH/MEDIUM deny fresh nonces unless channel binding is present and the session is fresh; LOW degraded-accept with audit flag; ANALYTICS accept.
- **10.6 Errors (oracle minimization):** external responses are limited to `{ ADTP_MALFORMED, ADTP_DENIED, ADTP_REVOKED, ADTP_RETRY }`. No per-step disclosure. Full reasons go to internal audit only.

---

## 11. Verification Algorithm (13 Steps)

**Nine of the thirteen steps can deny a request in this implementation.** The list below is
the specified algorithm; each step is annotated with what `adtpd` actually does, because
quoting "13 steps" without that annotation overstates the pipeline.

0. **Structural:** `typ`/`alg`/`ucv` acceptable; `exp` present everywhere; size limits (7.9); SD-3 parse with duplicate-key rejection; every root capability re-validated against the closed ability set and the canonical-URI profile; a RESTRICT block carrying zero caveats rejected. *(Implemented; can deny.)*
1. **Chain build:** walk `prf`, resolve CIDs (10.2), seen-CID cycle detection, depth ≤ policy, total capabilities + caveats ≤ 1,000; a non-root element carrying a capability set is rejected. *(Implemented; can deny.)*
2. **Linkage:** `hop.iss == parent.aud`; `hop.prf == CID(parent)`; `exp` non-increasing; `nbf` non-decreasing; `0 ≤ child.dl < parent.dl`. *(Implemented; can deny.)*
3. **Root trust anchor:** root `iss` ∈ trusted_root_dids. *(Implemented; can deny. Bundle-derived platforms are roadmap — Appendix A §15.)*
4. **Signatures:** every hop per SD-2/SD-4/SD-6. *(Implemented; can deny. Per-role algorithm minimums are moot: Ed25519 is the only agent algorithm.)*
5. **Temporal:** now ∈ [nbf − skew, exp + skew] for all hops; invocation `iat` within its freshness window. *(Implemented; can deny.)*
6. **Revocation:** latest-sequence status per subject (13.3), over **every element CID and every element audience** on the reconstructed chain; REVOKED / COMPROMISED / CASCADE / DECOMMISSIONED ⇒ DENY; SUSPENDED ⇒ DENY (resumable). *(Implemented; can deny. This is the step the protocol exists for.)*
7. **Attenuation integrity:** structural. Only the root carries a capability set, so no hop can widen one and the binding invariants are the scalar checks of steps 0–2. *(**No-op by design.** Retained for step-number stability and as the place any future capability-carrying hop would have to be checked — which would reintroduce set-containment comparison and must be argued for explicitly.)*
8. **Authorization:** action/resource matched against root `att` (existential); then every constraint and caveat on the path evaluated against the invocation context. A wildcard segment in the request resource is rejected (7.2). *(Implemented; can deny. Budget counters are **not** consulted — see 7.6; budget, max_calls and parameter_schema fail closed for want of a metering backend.)*
9. **Cross-org:** ORG_TRUST platform membership, depth bound, scope containment, trust-document freshness, root key pin. *(**Returns immediately.** Nothing populates trust policies from configuration, so no chain is ever classified cross-organizational. Roadmap — Appendix A §15.)*
10. **Proof-of-possession:** invocation signature under leaf `aud` key; `aud` == verifier; nonce unseen (10.5). *(Implemented; can deny. Channel binding is compared when configured but no TLS exporter supplies it. `obo` dual-chain is **not** implemented and invocations carrying `obo` are rejected outright. If `verify.allow_custodial_invocation` is enabled, the daemon may sign the invocation itself with the leaf's custodial key and then verify its own signature, which proves nothing about the caller; that setting defaults to off.)*
11. **First-use registration:** any hop lacking registration evidence. *(**Near-vacuous.** On the daemon path the leaf is checked against the store that registered it milliseconds earlier; below HIGH tier it degrade-accepts. ATL inclusion proofs and Signed Registration Timestamps are roadmap — Appendix A §14.)*
12. **Audit:** entries hash-linked and appended. *(Implemented, but **cannot fail verification** — the append error is discarded, so an audit-log outage never denies. Checkpoint cosigning into a transparency log is roadmap — Appendix A §14.)*

**Performance budgets** in earlier revisions of this section assumed the transparency log and
cross-org paths that Appendix A defers. They have not been re-measured against this build and
are withdrawn rather than restated.

---

## 13. Revocation Protocol

### 13.1 Authority matrix

| Authority | May set | Over | Proof |
|---|---|---|---|
| Platform (root issuer) | all statuses | any credential in chains rooted at it; agent identities it registered | root key signature |
| Hop issuer | REVOKED, SUSPENDED, REINSTATED | the hop it issued + descendants (subtree scope) | signature + the hop CID |
| Subject (agent) | REVOKED, COMPROMISED | credentials where it is `aud`; its own identity | self signature |
| Sponsor | REVOKED, COMPROMISED, DECOMMISSIONED | the sponsored agent identity (⇒ all roots where the agent is `aud`) | sponsor signature + registration record reference |
| Verifier | local denylist only | local | n/a (non-global) |

### 13.2 Entry format

```
{ "typ": "adtp/rev/1",
  "seq": <per-subject monotone int>,
  "subject": { "cid": ... } | { "did": ... },
  "scope": "credential" | "subtree" | "identity",
  "status": REVOKED | SUSPENDED | REINSTATED | COMPROMISED | DECOMMISSIONED | CASCADE,
  "authority": { "did": ..., "basis": platform_root | hop_issuer | subject | sponsor, "proof": <CID | chain> },
  "iat": <epoch>,
  "prev": <hash of previous entry>,
  "sig": <SD-2 signature> }
```

### 13.3 Semantics
Highest `seq` per subject wins. REINSTATED is valid only after SUSPENDED and only by an authority equal to or higher than the suspender (ordering: platform > sponsor > hop issuer > subject). COMPROMISED and DECOMMISSIONED are terminal for the subject: credentials are unrecoverable; identity must rotate.

### 13.4 Distribution
CDN-cached signed log plus emergency channel (≤ 30 s propagation target) for COMPROMISED and identity-scope entries. Staleness bounds: HIGH 0 (online) / MEDIUM 5 min / LOW 15 min / ANALYTICS 60 min.

### 13.5 Scaling
*(Roadmap, Appendix A §14.)* v1.0 would replace the flat list with filter cascades (CRLite-style) computed from the ATL-enumerated universe of registered credentials — zero false positives by construction. Sharded per root issuer. Per-issuer entry-rate and filter-size governance: an issuer inflating its shard via mass self-revocation degrades only its own shard (Filter Poisoning control).

### 13.6 Cascade
COMPROMISED / identity scope ⇒ explicit cascade: query `chain_contains_cid` (GIN-indexed, sourced from registration records) ⇒ batch CASCADE entries ⇒ emergency-channel push. **Completeness:** by the step-11 invariant, every chain ever authorized at HIGH or MEDIUM is registered, hence enumerable, hence cascaded. LOW/ANALYTICS chains may lag by at most their staleness bound plus asynchronous registration lag — a stated residual, not a silent gap. SUSPENDED remains implicit (chain walk at next check).

### 13.7 Reconciliation
At least every 24 h: walk registrations, verify `chain_contains_cid` integrity, repair, re-run cascades touched by any COMPROMISED event. Idempotent. Reconciliation events are ATL-logged.

---

## 17. Agent Lifecycle and Sponsor Controls

> **Implemented:** the state machine and its transitions. **Not implemented:** every ATL-logged
> record named below (registration records, sponsorship transfer, continuity records) — those
> depend on the transparency log of Appendix A §14. The daemon keeps this state locally.

States: REGISTERED → ACTIVE → { SUSPENDED ⇄ ACTIVE (via REINSTATED), COMPROMISED, EXPIRED } → DECOMMISSIONED.

**Registration record:** `{ agent did, sponsor did, operational scope, activity horizon, tier, signatures }` — sponsor cosignature REQUIRED for HIGH-tier agents — written as an ATL REG entry.

**Sponsor powers:** per 13.1 (unilateral identity revocation), registration cosign, and sponsorship transfer = a CONT-type ATL record dual-signed by old and new sponsor.

**Key rotation = new did:key identity.** All delegations invalidated (strict, by design). For long-lived agents, a **continuity record** `{ "typ": "adtp/cont/1", old_did, new_did, sig_old, sig_sponsor }` ATL-logged binds reputation and audit lineage to the new identity without transferring any credential.

---

## 18. Privacy Considerations

**Disclosure surface:** full chains expose delegation topology, agent DIDs, and sponsor linkage to every verifier; a static did:key is a global correlator.

**Controls:**
- Pairwise agent DIDs per counterpart organization: RECOMMENDED.
- **Delegation Gateway pattern:** an org-boundary agent holds the externally visible grant; internal chains terminate at the gateway; the gateway issues fresh single-hop external delegations. Internal topology never leaves the organization while internal audit linkage is preserved.
- No PII in capability URIs, caveats, or DIDs: MUST.
- Audit logs store SHA-256(parameters), never parameter values: MUST.
- ATL minimization per 14.1/14.6; retention bounded by legal duty, parameter hashes only.
- GDPR note: agent DIDs are plausibly personal data via sponsor identifiability; registry and log operators are controllers for those records.
- Cryptographic selective disclosure (BBS+-class) is a v2 research item and is explicitly not claimed in v1.x.

---

## 22. Known Limitations

Design limitations of the protocol. Limitations of *this implementation* are in the README
under Status and in SECURITY_AUDIT.md; the two lists are deliberately separate, because
conflating "the design does not do this" with "the code does not do this yet" is how a spec
stops being checkable.

1. **The caveat vocabulary is closed, and grows by version bump.** A restriction nobody
   anticipated is inexpressible until the vocabulary names it. `action_restrict` was added in
   v0.2.0 for exactly this reason: read-only delegation could not be expressed. Biscuit's
   Datalog does not have this limitation, at the cost of a larger trusted computing base.
   This is an accepted tradeoff, not an oversight — see DESIGN.md.
2. Cross-verifier shared budgets require a metering service or pre-splitting; there is no
   global atomic counter without coordination.
3. Key rotation invalidates all active delegations (strict by design); the continuity record
   preserves lineage only.
4. LOW/ANALYTICS cascade lag is bounded but nonzero (13.6).
5. No cryptographic selective disclosure until v2; privacy in v1.x is architectural.
6. did:web retains residual DNS/TLS dependence; pinning narrows exposure to first contact and
   rotation windows.
7. Channel binding is unavailable on some platforms; tier policy compensates.
8. **No formal verification.** No property in Section 4 is labeled VERIFIED and none should
   be read as such. A Tamarin model is an aspiration (Appendix A §23), not work in progress.
9. Multi-proof / branching chains excluded: authority from several parents would make the
   chain a DAG and authorization a union across branches, reintroducing the set arithmetic
   the design exists to avoid. This is a real capability given up.
10. Caveat predicate expressiveness (ADTP-PS1) is intentionally limited for decidability.
11. **Revocation completeness is a property of the verification path only.** Published
    revocation state (`/v1/status/{cid}`, the signed list) is incomplete for every status
    except `COMPROMISED`. A consumer that trusts the published list instead of verifying gets
    a wrong answer.

---

# Appendix A — Roadmap (not implemented)

**Nothing in this appendix is built.** These sections were written as design intent before
implementation and are retained for that reason alone. Do not read any of them as a
description of `adtpd`, and do not cite them as capabilities of this project.

Section numbers are those of the pre-segregation revision and are therefore non-contiguous.

## A.0 Honest positioning of this appendix

The four largest items here — a transparency log, session credentials, organizational
federation, and transport bindings — are all deferred. That is worth stating next to the
relevant comparison rather than leaving a reader to discover it.

**AIP** (Agent Interaction Protocol, [arXiv 2603.24775](https://arxiv.org/abs/2603.24775), now
[draft-prakash-aip-00](https://datatracker.ietf.org/doc/draft-prakash-aip/)) ships the same
restriction-only attenuation model as this protocol, and **ships transport bindings for MCP,
A2A and HTTP** — Section 16 below, which this project has specified and not built. On
transports, AIP is ahead. On attenuation, the two designs arrive at the same place, and any
claim of novelty there does not survive contact with the prior art listed in Section 1.

The axis on which the designs genuinely differ is revocation: **AIP explicitly defers
revocation to a future version**, and transitive denial via a mandatory root-walk is what this
protocol has and that specification does not. That is the comparison worth making, and it is
the only one this project should lead with.

---

## [ROADMAP] 12. ADTP-Session (Data Plane)

Issued after a successful ALLOW at verifier discretion (HIGH: MAY; other tiers: SHOULD on request):

```
{ "typ": "adtp/sess/1",
  "kid": <key id>,
  "chain": <CID(leaf)>,
  "aud": <verifier DID>,
  "scope_hash": SHA-256(JCS(authorized scope)),
  "iat": <epoch>,
  "exp": min(leaf.exp, iat + staleness(tier)),
  "cb_required": <bool>,
  "sig": <verifier signature> }
```

plus an out-of-band 256-bit session key (HKDF from the TLS exporter on TLS transports; server-generated for stdio).

**Per request:** HMAC-SHA-256 over `(kid, seq, ts, method, resource, SHA-256(JCS(parameters)))`; strictly monotone `seq`; `ts` within ±5 s. Cost: single-digit microseconds.

**Properties:** a session never extends authority (`scope_hash` pins it). Revocation latency ≤ the tier staleness bound *by construction*, because session lifetime and revocation staleness are the same budget. Budget caveats continue to be metered per request; exhaustion terminates the session (`ADTP_DENIED`). Full Section 11 is the control plane; sessions are the data plane for sub-millisecond and high-frequency agent interaction.

---

## [ROADMAP] 14. ADTP Transparency Log (ATL)

### 14.1 Structure
RFC 6962/9162-style append-only Merkle log (SHA-256). Entry types: **REG** (credential registration: CID, chain CIDs, issuer DID, tier), **REV** (revocation entries), **CKPT** (verifier audit checkpoints), **TRUST** (ORG_TRUST documents and bundles), **CONT** (identity continuity records). Data minimization: CIDs, DIDs, and minimal metadata only — never parameters or payloads. Where useful, ATL profiles SCITT rather than inventing log semantics.

### 14.2 Witnessing
Checkpoints cosigned by ≥ 2 independent witnesses; split-view detection via witness gossip; consistency proofs mandatory between checkpoints.

### 14.3 SRT (Signed Registration Timestamp)
The log's immediate promise of inclusion (the CT-SCT pattern); maximum merge delay 1 h. Verifiers accept an SRT to satisfy step 11 at low latency; audit reconciles SRT → inclusion.

### 14.4 Operation at scale
Multiple independent logs (the CT operational model); verifier policy lists accepted logs in `/.well-known/aitp`; sharding by log and by issuer supports ≥ 10^10 entries — known operational territory.

### 14.5 PQ durability
The integrity of historical records rests on hash-based inclusion and consistency proofs, not signatures. Audit history therefore survives a future signature-algorithm break; checkpoints are re-cosigned under post-quantum algorithms during migration.

### 14.6 Privacy and abuse controls
Rate-limited registration per issuer. No public enumeration API for agent→sponsor mappings; that linkage is available to authorized audit access only.

---

## [ROADMAP] 15. Cross-Org Trust

### 15.1 Org identity = locator + pinned authority
did:web is the **locator**; the pinned root key set is the **authority**. ORG_TRUST MUST include `root_keys` (multibase). Verifiers match the resolved `https://{domain}/.well-known/did.json` document against the pin; mismatch ⇒ DENY plus alert. No TOFU. Domain capture (registrar hijack, expiry, seizure) therefore cannot silently swap org keys.

### 15.2 Rotation ceremony
Publish `next_key` dual-signed (current + next) at least 2× the trust-cache TTL before activation; the rotation event is ATL-logged (TRUST entry). Emergency rotation requires an m-of-n org root quorum — organizations SHOULD provision 2-of-3 offline root keys. An unceremonied key change ⇒ verifiers DENY until manual re-pin.

### 15.3 ORG_TRUST

```
{ "typ": "adtp/trust/1",
  "from": <org DID>, "to": <org DID>,
  "platforms": [ <did:web>, ... ],     // exhaustive trusted platform list
  "root_keys": [ <multibase>, ... ],
  "max_delegation_depth": <int>,
  "capabilities": <scoped capability set>,
  "jurisdictions": [ "IN", "EU", ... ],
  "nbf": <int>, "exp": <int>,
  "sig": <SD-2 signature> }
```

Non-transitive: every did:web issuer in a presented chain MUST appear in `platforms`. Trust-cache TTL 5 min; cross-org never stale-accepts.

### 15.4 Trust Bundles
`{ "typ": "adtp/bundle/1", "coordinator": <DID>, "members": [ <ORG_TRUST>, ... ], "exp": <int>, "sig": ... }` — a distribution mechanism only. Verification remains bilateral: each member document is independently validated; a bundle never creates transitivity. Industry consortia use bundles to collapse the O(n^2) bilateral exchange problem.

### 15.5 Jurisdiction tags
Informative inputs to policy engines. The `jurisdiction` caveat type restricts honoring to verifiers whose self-asserted jurisdiction (in `/.well-known/aitp`) matches. A regulatory-scoping hook, not a security boundary.

### 15.6 did:web hardening
DNSSEC SHOULD; Certificate Transparency (≥ 2 logs) SHOULD; multi-resolution (≥ 2 geographically diverse resolvers) MUST for HIGH-tier cross-org.

---

## [ROADMAP] 16. Transport Bindings

**Body limit:** The daemon enforces a 64 KB maximum request body on all endpoints. Payloads exceeding this limit receive HTTP 413.

### 16.1 MCP-over-HTTP / generic HTTPS
`Authorization: ADTP-UCAN <base64url(chain)>` + `ADTP-Invocation: <token>`. Chains > 8 KB ⇒ `ADTP-UCAN-REF: <CID>` with CAS fetch (10.2). IANA registration planned for the scheme and headers. Channel binding per 10.3.

### 16.2 MCP-over-stdio
`_aitp` reserved key in JSON-RPC params: `{ "chain": [...] | "ref": <CID>, "invocation": ... }`. Ephemeral-DID binding per 10.4. > 64 KB ⇒ ref.

### 16.3 A2A
`metadata.aitp.{ chain | ref, invocation, obo }`. Mutual authentication via status-update tokens. Sub-delegation forms a verifiable delegation tree.

### 16.4 /.well-known/aitp (verifier and org metadata)

```
{ "org_did": ..., "root_keys": [...],
  "algs_min": { "root": ..., "intermediate": ..., "leaf": ..., "invocation": ... },
  "risk_tiers": ..., "channel_binding": ...,
  "accepted_logs": [...], "jurisdictions": [...],
  "endpoints": { "revocation": ..., "emergency": ..., "atl": ..., "cas": ..., "metering": ... },
  "ucv_supported": [...] }
```

Required for interoperability; cache ≤ 5 min.

### 16.5 Metering service interface (optional component)
Receipt aggregation and shared-budget counters across verifiers. The protocol defines the receipt format (7.6); the service is an operational product, not a protocol dependency.

---

## [ROADMAP] 19. Post-Quantum Migration

Signatures require contemporaneous unforgeability, not confidentiality; the exposure ordering is therefore anchor-first.

- **Phase 0 (now):** Ed25519; SHA-256 throughout; ATL hash proofs already PQ-durable (14.5).
- **Phase 1 (planned):** hybrid Ed25519+ML-DSA-65 composite for org roots, platform issuance, ORG_TRUST, bundles, checkpoints, and revocation entries. Leaf agents MAY remain Ed25519 (lifetimes ≤ 7 days cap exposure); all verifiers MUST verify hybrids. SLH-DSA-128s under consideration for offline org root anchors.
- **Phase 2 (roadmap):** pure ML-DSA acceptable; Ed25519-only roots rejected per verifier policy.

**Engineering consequences (planned):** ML-DSA-65 signatures (~3.3 KB) will push chains past header limits ⇒ the REF/CAS path (16.1) will become first-class. Per-role algorithm minimums (Section 6) will prevent anchor downgrade; mixed chains will be legal iff every hop meets its role minimum.

---

## [ROADMAP] 20. Competitive Position

The table in earlier revisions of this section was written from design intent, scored this
protocol against features it had not built, and marked competitor rows "None" or "Unknown"
without citation. It is withdrawn. What replaces it is narrower and checkable.

**Where this project is behind.** AIP ([arXiv 2603.24775](https://arxiv.org/abs/2603.24775),
[draft-prakash-aip-00](https://datatracker.ietf.org/doc/draft-prakash-aip/)) ships transport
bindings for MCP, A2A and HTTP. This project specifies them in §16 and has built none. AIP is
also in the IETF process; this is not.

**Where the designs are equivalent.** Restriction-only attenuation. AIP ships the same model,
and it is prior art in any case — macaroons (NDSS 2014), Biscuit v2/v3, UCAN 1.0's `cmd`+`pol`,
and the object-capability caretaker pattern all express it. No novelty claim on this axis
survives examination, and none is made.

**Where this project is ahead, and it is one thing.** AIP defers revocation to a future
version. This protocol makes transitive denial structural: the verifier cannot compute
authority without reconstructing the chain to its root, so every ancestor's revocation state is
checked on every verification, and revoking any ancestor denies the whole subtree without
enumerating descendants. UCAN's own revocation specification declines to guarantee this.

**Biscuit deserves a precise comparison rather than a table cell.** A Biscuit token carries its
ancestor blocks inline and each block has a revocation identifier, so revoking a parent block
denies every attenuated descendant carrying it — subtree denial is achievable there. The
difference is that here the ancestor walk is structurally unavoidable, whereas a Biscuit
verifier already holds every block and must be *configured* to check their revocation
identifiers. That is a real difference in failure mode, not a difference in capability, and it
should not be overstated.

Any comparison in this section MUST be re-verified against current drafts before external use.

---

## [ROADMAP] 21. Conformance Profiles

| Profile | Requirements |
|---|---|
| Verifier-HIGH | Full Section 11; online revocation; channel binding; durable audit enqueue before allow; first-use SRT gating; sessions optional |
| Verifier-Standard | Section 11 with tier-appropriate staleness and async paths |
| Issuer-Platform | Registration at issuance; lifetime profile; hybrid signatures at v1.0 |
| Agent-SDK | RESTRICT issuance; receipt handling; pairwise DIDs |
| Log-Operator | Section 14; ≥ 2 witnesses; merge delay ≤ 1 h |

---

## [ROADMAP] 23. v1.0 Exit Criteria

1. **Tamarin model** covering: chain acceptance (no non-delegated action is authorized in RESTRICT mode), proof-of-possession replay resistance including cache restart, and the revocation propagation bound — proof or falsification, published.
2. **Two independent interoperating implementations** (Go + TypeScript) passing a conformance vector suite that includes URI-canonicalization and parser-differential corpora.
3. **ATL reference log operational** with two independent witnesses.
4. **Internet-Draft** extracted from Sections 2–16 (royalty-free), submitted.
5. **Hybrid signature suite** implemented behind the per-role algorithm policy.

---

*End of consolidated specification. Supersedes v0.2 in full.*
