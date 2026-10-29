# Security audit

An audit of this implementation against its own public claims, conducted 2026-08-14 against
commit `aaec7b9` and updated to reflect the changes made in response.

The method was to read the implementation and verify claims against it, treating
`docs/PROTOCOL.md` as a set of assertions to check rather than as a description of what
shipped. Line references are to the current tree.

Nothing here is softened. Several findings remain open.

## Summary

| | Count |
|---|---|
| Findings resolved | 9 |
| Findings open | 9 |
| Findings withdrawn as incorrect | 2 |
| Claims verified | 4 (1 confirmed, 2 partial, 1 **withdrawn — this audit got it wrong**) |
| Public claims cut or qualified | 14 |

## The four core claims

> **Update, v0.2.0.** RESTATE is removed from the protocol and the implementation, which
> resolves the RESTATE half of claims 1 and 2 by deleting the thing that was PARTIAL rather
> than by fixing it. `CapabilityLeq`, `constraintLeq`, `att_seal`, `checkModeMixing`, step
> 7's RESTATE branch, and the `mode` parameter on the delegations API are gone; a non-root
> element carrying a capability set is rejected at chain build. The verdicts below are left
> as written, because they were true of the code they were written against and because the
> reason RESTATE existed at all — compatibility with a version that had no implementations —
> is worth leaving legible.
>
> The correct post-removal claim is **"chain validation performs no set-containment
> comparison"**, not "the attack surface is absent". Comparison moved rather than vanished:
> `URICovers` and `CanonicalizeURI` still run at step 8 on every verification, and
> `evaluateConstraint` still dispatches nine constraint types across eight case arms. What
> changed is *where a mistake lands* — a per-hop comparison bug widened a credential, whereas
> an authorization-time bug denies or misroutes one request against a grant the platform
> signed. That is a real reduction and a smaller blast radius. It is not an absence, and F14
> is the standing evidence that scalar invariants have their own failure mode.

### 1. An agent cannot mint a capability broader than one it holds, and attenuation is enforced structurally by the token format rather than by a policy check — **PARTIAL**

**True for RESTRICT.** A RESTRICT block carries no capability set at all
([`internal/credential/restrict.go`](internal/credential/restrict.go)), so step 7 skips the
hop entirely ([`internal/verify/steps.go:297`](internal/verify/steps.go#L297)) and no
capability-comparison code executes. The binding invariants are scalar comparisons in step
2: `child.exp <= parent.exp`, `child.nbf >= parent.nbf`, `child.dl < parent.dl`,
`child.iss == parent.aud`, `child.prf == parent.CID`. A child cannot drop a parent's caveat
by omitting it, because step 8 evaluates every block in the chain. Escalation requires
forging an Ed25519 signature or a SHA-256 collision on `prf`.

**False for RESTATE.** `CapabilityLeq`
([`internal/credential/capability_leq.go:20`](internal/credential/capability_leq.go#L20)) is
115 lines of type-switched semantic comparison and is trusted computing base — precisely the
class of thing the claim says is absent. The file's own doc comment says so. `att_seal` does
not rescue it: the seal signer is the hop issuer, so it defends against serialization
differentials only.

**RESTATE is reachable** via `POST /v1/delegations` with `"mode":"restate"`. It is not
gated, deprecated in the API, or warned about at runtime.

**Verdict: PARTIAL.** True of the default mode, false of a mode one string away. The README
now states this distinction explicitly rather than claiming it system-wide.

### 2. Cascade revocation is complete — no path by which a descendant stays valid — **PARTIAL**

The mechanism is stronger than the claim's own framing. Step 1 always reconstructs the chain
to the root; step 6 builds its subject set from **every element CID and every element
audience** ([`internal/verify/steps.go:251`](internal/verify/steps.go#L251)), so a revoked
ancestor is always checked. This does not depend on the registration index, on enumeration,
or on a transparency log.

The claim was publicly attributed to a "registration invariant." That attribution was wrong
— the operative mechanism is the chain walk. The documentation has been corrected. This is
instance 1 of the pattern recorded as F20.

**A further limit, added after reading the UCAN Revocation spec.** Even with the chain walk,
this does not guarantee that a revoked *agent* loses a capability: the guarantee is
per-credential. An agent holding a second credential over the same resource keeps it. See
F20 instance 3.

Four qualifications, all still true:

1. **Explicit cascade fires only for `COMPROMISED`**
   ([`api/v1/handlers.go:431`](api/v1/handlers.go#L431)). Any other status writes one entry
   for the named subject. Verification still denies descendants, but `GET /v1/status/{cid}`
   reports them unrevoked and the published list omits them. Demonstrated: revoking a parent
   `REVOKED` yields `{"revoked":false}` for the child while `/v1/verify` on that same child
   returns `ADTP_REVOKED`.
2. **Fail-open below HIGH tier.** A revocation lookup *error* denies at HIGH and is
   degrade-accepted at MEDIUM/LOW/ANALYTICS
   ([`internal/verify/steps.go:263`](internal/verify/steps.go#L263)). Default is HIGH, so
   this is closed out of the box and a config change opens it.
3. **A `nil` cache skips step 6 entirely**
   ([`internal/verify/steps.go:246`](internal/verify/steps.go#L246)). Unreachable through the
   daemon; it is the library default.
4. **`Scope` is not read at verification**
   ([`internal/verify/steps.go:278`](internal/verify/steps.go#L278)). `credential`,
   `subtree`, and `identity` deny identically. Fails safe; the field is decorative here.

**Verdict: PARTIAL.** Complete for the verification path. Incomplete for published
revocation state under non-`COMPROMISED` statuses, and defeasible by configuration.

### 3. RESTRICT mode prevents escalation as the design describes — ~~**CONFIRMED**~~ **WITHDRAWN**

**This verdict was wrong and is withdrawn.** It was recorded as CONFIRMED on the reasoning
that *"every specified invariant is enforced twice — at issuance in `CreateRestrictBlock` and
again at verification in `step2Linkage` — so a forged block that bypasses the issuance path
still fails."* That premise is false. A later external audit found an invariant enforced at
issuance and **not** at verification, and it was exploitable.

**What the PoC showed.** `CreateRestrictBlock` rejected `childDL < 0`. Neither
`ParseRestrictBlock` nor `step2Linkage` did. `step2Linkage` bounded depth-left only from
above (`child.dl < parent.dl`), and `-1 < 0` satisfies that bound. So a holder of a block at
`dl=0` — an agent explicitly delegated no further delegation authority — signed a child at
`dl=-1` directly and it verified end to end: chain built, all thirteen steps passed, ALLOW.
The same move repeats at `-2`, `-3`, and onward, bounded only by `MaxChainDepth`. The
delegation-depth control was one-directional and therefore not a control at all.

**Why the audit missed it.** The adversarial suite probed `dl` in one direction only —
`dl_escalation` set `dl` *above* the parent's. Seven tests, none of which asked what happens
below zero. The double-enforcement claim was checked invariant-by-invariant against the
issuance path and assumed to mirror on the verification path rather than read there.
Symmetry was inferred, not verified, and the tests inherited the same blind spot.

**The defect is a class, not an instance.** The specific bug is one missing comparison. The
reasoning error underneath it is the inference *"validated in `Create*`, therefore enforced in
`Parse*`/verification"* — and this audit made that inference generally, not once. Every other
invariant it recorded as double-enforced rests on the same unchecked assumption and is
therefore suspect until read on both paths. Two consequences follow, and both are commitments
rather than observations:

- Every `Create*` validation in `internal/credential` is being re-checked against its
  corresponding `Parse*` and against the verification steps, looking for anything else the
  issuance path refuses that the admission path accepts. **That sweep has since been run;
  it found two more and is recorded as F16.**
- No future entry in this document may cite issuance-time validation as evidence about
  verification-time behaviour without naming the verification-side line that enforces it.
  See also F20, which generalises this: the same "plausible explanation accepted without
  checking the alternative" error has now produced three wrong public claims.

Two narrower lessons, both applying beyond this finding:

- A bound stated in one direction is not evidence of a bound in the other. `dl` had a
  documented ceiling and an undocumented floor that existed only in the minting path.
- "Enforced twice" is a claim about two specific code paths and must be read in both. This
  audit read one and asserted the pair.

*Both defects are now fixed and the claim is not re-asserted; see F14 and F15 under Resolved.
The verdict stays withdrawn rather than being re-run and upgraded — the point of leaving it
here is that the reasoning failed, not just the result.*

The two secondary observations from the original entry were checked again and do still hold.
Mode mixing (`RESTATE`-after-`RESTRICT`) is rejected structurally at chain build, and the
implementation is stricter than the specification in two places, both in the safe direction:
any `crit` entry is rejected outright, and unenforceable cumulative caveats fail closed
rather than passing as structurally satisfied.

The adversarial suite
([`internal/verify/adversarial_test.go`](internal/verify/adversarial_test.go)) now carries
nine cases covering eight distinct vectors — the seven originals plus negative `dl`, which is
asserted at both layers that were missing it. They forge blocks with a real signing key and
assert the denial along with the specific step and error code. They cover RESTRICT only;
nothing adversarial targets RESTATE.

### 4. Identity is did:key with Ed25519 throughout, no alternate key type, no unsigned path — **CONFIRMED**

`ParseDID` rejects any non-`did:key` prefix, any multibase other than `z`, any multicodec
other than `0xed 0x01`, and any decoded length other than 34 bytes. The UCAN header admits
`EdDSA` only — there is no `none` branch and no HMAC branch. Every credential object is
signed and verified: `ParseRestrictBlock` requires a non-empty `sig`, step 4 verifies every
element, and both stores refuse a revocation entry not validly signed by the authority it
names ([`internal/revocation/entry.go:113`](internal/revocation/entry.go#L113)).

**Boundary worth naming:** `api/v1/oidc.go` implements RSA/RS256 JWT verification. That is
control-plane operator authentication, not agent identity, and it accepts RS256 only —
rejecting `none` and HMAC, closing algorithm confusion. The claim holds for the protocol;
RSA exists in the binary for a different purpose.

## Findings

### Resolved

**F14 — Delegation depth was bypassable downward.** *(HIGH; found by external audit, not by
this one)* `CreateRestrictBlock` rejected `childDL < 0`; `ParseRestrictBlock` and
`step2Linkage` did not, and `step2Linkage` bounded `dl` only from above. A holder of a block
at `dl=0` signed a child at `dl=-1` and it verified end to end, then again at `-2` and
onward, bounded only by `MaxChainDepth`. This is the defect that falsifies claim 3 above.
*Resolved:* `dl < 0` is now rejected in `ParseRestrictBlock`
([`internal/credential/restrict.go`](internal/credential/restrict.go)) and in `step2Linkage`
([`internal/verify/steps.go`](internal/verify/steps.go)). Two tests cover it —
`dl_negative` through the full verifier and `dl_negative_at_linkage` directly against step 2,
for chains that reach the verifier without being re-parsed — plus a parser-level test in
`internal/credential/restrict_test.go`. All three fail against the unfixed code.

**F15 — SD-6 was unimplemented for RESTRICT blocks.** *(MEDIUM; found by external audit)*
`docs/PROTOCOL.md` SD-6 requires rejection on any divergence between the raw-byte hash and
the re-serialized hash of the parsed object. `RestrictBlock.Verify` re-marshals the parsed
struct before checking the signature, so a re-encoded block still verified; nothing compared
the received bytes to `CanonicalBytes()`. One credential therefore admitted unboundedly many
CIDs — `json.MarshalIndent` of a valid block yields different bytes, a different CID, and a
signature that still verifies. Consequence: credential-scoped revocation of a leaf is evaded
by re-encoding it once inline chain presentation ships. Not reachable today, because every
block the daemon resolves comes from its own store under a CID it verified.
*Resolved:* `ParseRestrictBlock` now compares the received bytes to the canonical
re-serialization and rejects on any difference.

**F20 — "Right outcome, wrong mechanism" is this project's characteristic documentation
failure, and it has now happened three times.** *(Method finding, not a vulnerability.)*

Three separate claims have been made in this repository's public documentation that described
a real behaviour and attributed it to the wrong cause:

1. **Cascade completeness was attributed to "a registration invariant."** The operative
   mechanism is the mandatory chain walk (claim 2 above). Corrected in the previous revision.
2. **RESTRICT was described as making "the attack surface absent."** Comparison moved rather
   than vanished, and the actual exploitable defect (F14) involved no comparison code at all.
   Corrected in v0.2.0.
3. **Transitive denial was claimed as closing a gap the UCAN Revocation spec leaves open.** The
   quoted sentence — "revocation of a particular proof does not guarantee that the Agent can no
   longer access to the capability in question" — is *equally true of this implementation*.
   Rejecting branching gives one **credential** one path to one root; it does not give one
   **agent** one credential. An agent holding two credentials over the same resource keeps the
   second when an ancestor of the first is revoked. The real guarantee is per-credential
   subtree denial, and the delta against UCAN is only that UCAN permits a single credential to
   derive authority from several parents. Corrected in this revision.

The shape is identical every time: a mechanism is observed to work, a plausible explanation is
attached without being checked against the alternative, and the explanation is stated with more
confidence than the observation supports. Instance 3 is the worst of the three, because the
claim was also repeated to a standards working group before it was checked.

The operational rule, alongside F19's: **a claim about *why* something works must name the code
path that makes it work, and must state what would have to be true for a competing explanation
to be the real one.** Where a claim compares this project to another system, the other system's
specification must be read and quoted rather than characterised from memory — which is how
instance 3 survived as long as it did.

**F19 — A test that passes against unfixed code has told you nothing.** *(Method finding, not
a vulnerability. Recorded because it changed the outcome of F18.)*

The JWKS locking defect was reported as "`keys()` holds the mutex across a 10-second fetch, so
one slow IdP serializes every authenticated request." The obvious fix is to stop holding the
lock across the fetch. That fix was written, a test was written with it, and **the test passed
against the original implementation** — in 11 seconds rather than 0.03, but passed.

That result was the finding. The test had not measured the stall; the stall had moved into the
test's own setup, where it was silently waited on rather than asserted. Had the run been
treated as confirmation, a fix that did not address the actual failure mode would have shipped
with a green test attesting that it did.

Reading it properly showed a worse bug than the one reported. A *successful* fetch populates
the cache, so callers queued behind it find it fresh and the cost is one timeout. A **failed or
hanging** fetch leaves the cache stale — so each queued caller acquired the mutex in turn,
issued its own request, and waited its own full timeout. N callers against an unresponsive IdP
cost N sequential timeouts, not one. The reported symptom was request serialization; the actual
behaviour was serialized amplification of the outage.

*Resolved:* concurrent refreshes are coalesced into a single in-flight request whose result
every waiter shares, and the cache lock is never held across the network call. Two tests, both
verified to fail against the original code: `8 upstream JWKS requests for 8 concurrent callers,
want 1`, and a fresh-cache read blocked more than two seconds behind a hung fetch.

The general rule, which applies to every other entry in this document: **a new test must be run
against the unfixed code and observed to fail before its passing run means anything.** Every
fix in F14, F15 and F18 was checked that way. Where a test could not be made to discriminate,
that is stated rather than glossed — see the note on the three benign asymmetries in F16.

**F18 — Control-plane and primitive defects.** Seven, found by the same external audit,
grouped because they were fixed together:

- **JWKS URL was not required to be HTTPS.** Config validation checked non-empty only and
  `oidc.go` did a plain `client.Get`. Over `http://` a network attacker substitutes their own
  signing key and mints bearer tokens the daemon accepts — a complete control-plane
  authentication bypass. *Resolved:* rejected at config load, so the daemon refuses to start
  rather than failing open at first request.
- **`rsaPublicKeyFromJWK` accepted any modulus size,** including 1024-bit.
  *Resolved:* 2048-bit minimum.
- **`httpJWKS.keys()` held the cache mutex across the network fetch.** One slow IdP stalled
  every authenticated request, including those whose cache entry was already fresh; and
  because a failed fetch leaves the cache stale, each queued caller then issued its own
  request and waited its own full timeout — N callers, N sequential timeouts. *Resolved:* the
  lock is no longer held across the fetch and concurrent refreshes are coalesced into one
  upstream request. Both properties are asserted by tests that fail against the old code.
- **JCS delegated string decoding to `encoding/json`,** which substitutes U+FFFD for lone
  surrogates and invalid UTF-8 instead of failing. `"\ud800"`, `"\udfff"`, and a genuine
  U+FFFD therefore canonicalized identically — one signature and one CID for three distinct
  documents, which is the parser-differential class SD-3 exists to close. RFC 8785 and I-JSON
  both require rejection. *Resolved:* a pre-decode pass validates UTF-8 and surrogate
  pairing.
- **`handleVerify` accepted `chain` as an array and used only element zero,** silently
  discarding the rest. *Resolved:* arrays longer than one element are rejected; ancestors are
  resolved from the proof store by walking `prf`, which is what actually happens.
- **A wildcard was accepted in the resource position of a verification request.** `*` is a
  legal sub-delim, so `tool://x/*` canonicalizes, and `URICovers` returns true via its
  `p == c` fast path — authorizing a glob that was never resolved to a target. *Resolved:*
  rejected at `/v1/verify` and again at step 8; the asymmetry between pattern position and
  resource position is documented in `CAPABILITIES.md`.
- **Proof of possession was self-satisfied.** With no client invocation the daemon minted one
  with the leaf agent's own custodial key and verified its own signature, making step 10
  vacuous on that path. *Resolved:* gated behind `verify.allow_custodial_invocation`,
  defaulting to **off**, and documented in the README. Gating was chosen over documenting
  because a verification step that silently proves nothing is worse than one that is absent —
  the default now matches what the pipeline claims to do.

**F16 — Issuance/admission sweep: two more invariants enforced only at issuance.** Prompted
by F14, every `Create*` validation in `internal/credential` was read against its `Parse*`
counterpart and against the thirteen steps. Two more were enforced nowhere on the admission
path:

- `Capability.Validate` — the ability set is closed per `ucv` and `with` must be canonical.
  `ParseUCAN` never called it and no step re-checked it, so a token carrying an unknown
  ability reached step 8, where it is matched by string equality against a request action
  that was itself unvalidated.
- `ErrNoCaveats` — Section 8.2 requires a RESTRICT block to carry at least one caveat.
  `CreateRestrictBlock` and `ValidateAgainstParent` both enforce it, but the verifier
  reimplements linkage in `step2Linkage` and never calls `ValidateAgainstParent`, so a
  forged zero-caveat block was a delegation hop that restricted nothing.

*Resolved:* both are enforced in `step0Structural`, with a comment recording why the
duplication exists. Neither was independently exploitable at the time — `att` reaches the
verifier only from a trusted root or a RESTATE hop, and a vacuous caveat achieves what a
zero-caveat block did — but both are the F14 pattern exactly.

Three further asymmetries were found and judged benign, each because the verification path
makes the invalid state unsatisfiable rather than because it validates: a negative `nbf`/`iat`
is simply a window in the past (step 5); `exp <= nbf` admits no `now` (step 5); and a
non-canonical `with` or `resource_restrict` resource makes `URICovers` return false, since it
canonicalizes internally and fails closed. Recorded rather than fixed, because "unsatisfiable
in practice" is a weaker guarantee than "rejected" and the reasoning should be re-checked if
those steps change.

**F1 — Agent keys were memory-only on every backend.** *(was: highest severity)*
The daemon wired `identity.NewMemoryKeyStore()` unconditionally, and it was the only
`KeyStore` implementation. Selecting the PostgreSQL backend did not make agent keys durable:
after a restart the daemon held no agent key, so `/v1/delegations` returned 403 and
`/v1/verify` could not build custodial invocations for any previously registered agent. The
service presented as durable and was not.

*Resolved:* a PostgreSQL-backed `KeyStore`
([`store/postgres/keystore.go`](store/postgres/keystore.go), schema version 2) now persists
agent keys, and `newStore` pairs each backend with its matching key store. The memory
backend now warns at startup that keys are not persisted. Keys are stored **in plaintext** —
read access to `agent_keys` is equivalent to impersonating every agent in it. That is the
honest form of custodial key handling, not a safe one; HSM-backed custody remains
unimplemented. Documented in the README under Status.

**F11 — No CodeQL or Dependabot.** Both workflows existed only on unmerged branches in the
working copy under audit. *Resolved:* both are present on `main`
(`.github/workflows/codeql.yml`, `.github/dependabot.yml`).

**F12 — `golang.org/x/time` was a direct dependency marked `// indirect`.** *Resolved:*
promoted in `go.mod`.

**F21 — `KeyStore.List` ordered by database collation, not byte order.** *(Correctness
finding, not a vulnerability; found by the scheduled CI run of 2026-10-27.)*
`identity.MemoryKeyStore.List` sorts with `sort.Strings` — byte order — while
`store/postgres/keystore.go` issued `ORDER BY did`, which uses the database's collation. DIDs
are mixed-case base58, and a linguistic collation such as `en_US.utf8` (the default in the
`postgres:16` image CI uses) folds case: it puts `...icgd` before `...iHJS`, where byte order
puts `'H'` (0x48) before `'c'` (0x63). The two backends therefore returned different orders
for the same key set, behind an interface whose doc comment promised "ascending order".

`TestPostgresKeyStoreList` generates its DIDs randomly, so it only caught this when the
generated pair happened to differ in case at the deciding position — it passed on 2026-10-20
and failed on 2026-10-27 with no change to the code in between. The fix was not to relax the
test: a divergence that appears under one backend and not the other is the defect.

*Resolved:* `ORDER BY did COLLATE "C"`, which makes the byte ordering explicit and
backend-independent. `FindDescendants` received the same treatment for
`ORDER BY credential_cid`; there it is latent rather than live, because CIDs are lowercase
base32 (`bafkrei...`) and byte order and `en_US.utf8` agree on that alphabet — stated here
rather than glossed, per F19's rule about tests that cannot discriminate.
`RevocationEntries` was left alone deliberately: its `ORDER BY` exists to drive `DISTINCT ON`,
which groups by equality rather than by collation order, so the collation cannot change which
entry wins per subject — and `MemoryRevocationCache.Entries` returns map-iteration order, so
there is no cross-backend ordering guarantee there to preserve.
`TestPostgresKeyStoreListIsByteOrdered` pins the behaviour with the DID pair from the CI
failure, and was observed to fail against the unfixed query.

### Withdrawn

Two findings were wrong, and both failed the same way: an empirical claim was asserted
without being run. They are kept here rather than deleted, because an audit that quietly
drops its own errors is not one you should trust.

**F10 — "golangci-lint v1.64.8 cannot parse a `go 1.26` directive."** **Wrong.** It was
reported with a hedge ("I did not run it") but asserted as a mechanical incompatibility.
Empirically, v1.64.8 runs clean against `go 1.26.5` across the whole repository — exit 0,
zero findings. The lint job was green, not red.

The linter was upgraded to v2.12.2 anyway, for the defensible reason that the v1 series is
end-of-life. v2 folds the former `stylecheck` and `quickfix` linters into `staticcheck` and
surfaced 11 previously unchecked findings; 9 were fixed, and 2 (`ST1003`, `QF1001`) are
excluded in `.golangci.yml` with reasons recorded inline.

**F13 — "No tags or releases exist, so the documented `go install` command fails."**
**Wrong.** `git tag` was never run. The tag `v0.1.0-alpha` exists on the remote at
`27d07ed`, with a GitHub prerelease published 2026-06-22, and the command works. The README
line was cut on that false premise and has been restored.

### Open

**F2 — Fail-open paths below HIGH risk tier.** Revocation lookup errors
([`internal/verify/steps.go:263`](internal/verify/steps.go#L263)) and unregistered leaf
credentials ([`internal/verify/steps.go:415`](internal/verify/steps.go#L415)) both
degrade-accept below HIGH. The default tier is HIGH, so both are closed on a default
install; a one-line config change opens both. Additionally, `docs/PROTOCOL.md` §4.8 requires
registration evidence at HIGH **and MEDIUM**; the code enforces it at HIGH only.
*Status: documented in the README, not changed. Risk tiers overload two unrelated
decisions — resource sensitivity and outage behaviour — which is discussed in DESIGN.md.*

**F3 — Issuance does not verify the parent chain's signatures.** `handleDelegate` →
`parentRef` ([`api/v1/handlers.go:577`](api/v1/handlers.go#L577)) parses the parent and mints
a child without verifying any signature, and `storeAndRegister`'s `BuildChain` call verifies
CIDs but not signatures. Not exploitable today — the parent comes from the daemon's own
store — but the daemon will mint children off a chain it has never validated. Defence in
depth is missing. *Open.*

**F4 — `/v1/admin/reconcile` has no privilege separation.** Any valid API key triggers a walk
of every credential in the store ([`api/v1/handlers.go:523`](api/v1/handlers.go#L523)). On a
large store this is a self-inflicted denial of service available to any key holder. *Open.*

**F5 — `/v1/revocation/list` is unauthenticated, unpaginated, and signs per request.** It
bypasses both auth and rate limiting ([`api/v1/middleware.go:15`](api/v1/middleware.go#L15))
and performs an unbounded read plus an Ed25519 signature on every call
([`api/v1/handlers.go:470`](api/v1/handlers.go#L470)). Public fetchability is intended; the
amplification is not. *Open.*

**F6 — Rate limiting is global, not per-client.** One `rate.Limiter` for the whole process
([`api/v1/middleware.go:67`](api/v1/middleware.go#L67)), so any single client can starve all
others. It is also disabled unless `rate_limit_rps` is set. *Open.*

**F7 — API key auto-generation.** With no keys configured the daemon generates one, writes it
to `api.key` at 0600, and logs a warning
([`cmd/adtpd/main.go:302`](cmd/adtpd/main.go#L302)). "I forgot to configure auth" produces a
running daemon rather than a refusal. Mitigated by the 0600 mode and the localhost-only
default bind. *Open, by design.*

**F8 — `MemoryNonceCache` never evicts.** Entries are refreshed past expiry but never
deleted from the `sync.Map`
([`internal/verify/pop.go:86`](internal/verify/pop.go#L86)), so memory grows with total
invocations over process lifetime. *Open.*

**F17 — The control plane has authentication but no authorization.** Any valid API key can
revoke as the platform authority ([`api/v1/handlers.go`](api/v1/handlers.go)), verify as any
agent whose custodial key the daemon holds, and enumerate the whole credential store. There
are no scopes, roles, or per-key restrictions: one key is total control. F4 and F5 are
symptoms of this, not separate problems. *Open; documented in the README under Status and
tracked for v0.3. Not softened: this is the single largest gap between what the daemon
authenticates and what it authorizes.*

**F9 — Revocation authority is authenticated but not authorized.**
`VerifyEntrySelfSignature` ([`internal/revocation/entry.go:113`](internal/revocation/entry.go#L113))
confirms an entry is signed by the DID it *names* as authority; it does not check that the
DID is a trusted root. Any Ed25519 key holder can produce an entry naming itself
`platform_root`. Unreachable through the daemon, which always constructs entries with the
platform key, but `MemoryRevocationCache.Revoke` and `PostgresStore.Revoke` are exported and
would accept one. `UpdateFromList` is the safe path — it takes an explicit issuer key.
*Open.*

### Also noted

- **Zero `TODO`/`FIXME`/`XXX`/`HACK` in the codebase.** The one deferred feature is declared
  and fails closed: `on_behalf_of` invocations are rejected outright
  ([`internal/verify/pop.go:148`](internal/verify/pop.go#L148)) rather than silently ignored.
- **No secrets in git history.** All blobs across the full history were scanned for
  `*.key`/`*.pem`/`*.env` paths and for private-key and cloud-token patterns. Clean.
- **PostgreSQL backend coverage is 5.5%** under a default `go test ./...`; its real tests are
  behind the `integration` build tag and require a live database. CI runs them; a local test
  run proves nothing about the production backend.
- **Cross-organizational trust is unreachable.** `TrustPolicy`
  ([`internal/verify/verifier.go:41`](internal/verify/verifier.go#L41)) is never populated
  from configuration. Its own comment calls it "a simplified precursor." The feature was cut
  from the README rather than described.
- **Metering is unimplemented and fails closed.** `budget`, `max_calls`, and
  `parameter_schema` always deny, because `MeteringEnabled` is hardcoded `false`
  ([`api/v1/handlers.go:558`](api/v1/handlers.go#L558)). Correct direction, surprising from
  outside; now documented in both the README and `CAPABILITIES.md`.

## Public claims that overstated the code

Every row was cut or qualified.

| Claim | Problem | Action |
|---|---|---|
| "Revocation is provably complete" / "guaranteed complete by construction" | Nothing is proven. Four qualifications apply. | Cut; replaced with the mechanism and its limits |
| "structural invariants that make escalation impossible" | True of RESTRICT, false of RESTATE | Qualified to RESTRICT |
| "capabilities can only narrow … not a policy check" | `CapabilityLeq` *is* a policy check | Qualified |
| "a registration invariant guarantees … No orphans … mathematical completeness" | Misattributes the mechanism; the chain walk is what works | Rewritten around step 6 |
| "cascade revocation is provably complete (not a 15-minute CRL polling window)" | Overclaim plus unsourced competitor characterization | Cut |
| "revocation has zero gap" | Four documented gaps | Cut |
| "22 pre-release security findings identified and resolved" | Traceable only to a commit message; no findings document | Cut |
| "For production, configure PostgreSQL" | Agent keys were not persisted on any backend | Fixed in code; custody model documented |
| "Go daemon (12,600+ lines)" | ~7,500 source + ~8,500 test; LOC is not a quality signal | Cut |
| "Cross-org bilateral trust" | Unreachable from the daemon | Cut |
| "Identity Provider: Entra, Okta, Auth0 via OIDC" | RS256 against a static JWKS; never tested against a live IdP | Qualified |
| "Audit/SIEM: Datadog, Splunk, Elastic via webhook" | Generic batched JSON POST, no vendor specifics | Qualified |
| "7 adversarial escalation vectors" | RESTRICT-only, and the seven missed one direction of the `dl` bound (F14) | Qualified; now eight vectors |
| `go install …@v0.1.0-alpha` | Audited as "no tags exist"; **that audit finding was wrong** — the tag and a published prerelease both exist and the command works | Restored, pointing at `v0.1.0` |
| Revoke example `"scope":"CREDENTIAL"` | Scope constants are lowercase; returns 403 | Fixed, and the casing pitfall called out |

### Documentation errors found while correcting the above

`CAPABILITIES.md` contained four factual errors, each verified against the running code
before correction:

- URI coverage was described as prefix matching. It is **positional and segment-counted**:
  `tool://x/*` covers `tool://x/a` but **not** `tool://x/a/b`.
- A bare `*` was documented as a valid `with` value for root credentials. It fails
  canonicalization (`expected scheme://authority form`).
- Unknown actions were documented as "passed through and matched literally." The action set
  is closed; `Capability.Validate` rejects them at issuance.
- Authorization was cited as verification step 9. It is step 8.

## Reproducing

```bash
go build ./... && go test ./...          # unit tests, in-memory backend
go test -tags e2e ./test/e2e/...         # end-to-end
go test -tags integration ./store/...    # needs ADTP_TEST_POSTGRES_DSN
golangci-lint run ./...                  # v2.12.2
```

Report vulnerabilities per [SECURITY.md](SECURITY.md). Do not open a public issue.
