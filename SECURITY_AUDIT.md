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
| Findings resolved | 5 |
| Findings open | 8 |
| Findings withdrawn as incorrect | 2 |
| Claims verified | 4 (1 confirmed, 2 partial, 1 **withdrawn — this audit got it wrong**) |
| Public claims cut or qualified | 14 |

## The four core claims

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
— the operative mechanism is the chain walk. The documentation has been corrected.

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
  issuance path refuses that the admission path accepts. Results will be recorded here.
- No future entry in this document may cite issuance-time validation as evidence about
  verification-time behaviour without naming the verification-side line that enforces it.

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
