# ADTP — Agent Delegation and Trust Protocol

[![CI](https://github.com/Zahanturel/adtp/actions/workflows/ci.yml/badge.svg)](https://github.com/Zahanturel/adtp/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/Zahanturel/adtp.svg)](https://pkg.go.dev/github.com/Zahanturel/adtp)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

ADTP is a protocol and Go daemon that produces a **non-repudiable, per-hop, issuer-signed,
hash-linked record of which agent authorized which sub-agent to do what** — and where
revoking any link in that record denies that chain and every chain descending from it, at
verification time, without enumerating descendants.

That is the contribution, and everything else here is in service of it. It is a
*per-credential* guarantee — not a guarantee that a revoked agent loses a capability it also
holds by some other credential, which no offline-capable protocol provides. See
[What this actually provides](#what-this-actually-provides) for where the line falls.

## The problem

An agent holds a credential that lets it call a search tool. It spawns a sub-agent to do
part of the job, and the sub-agent needs to call that tool too. Today the sub-agent gets
the credential itself — the same bearer token, the same API key, the same OAuth access
token.

Two things follow, and neither is a configuration mistake:

**The delegation is unbounded.** The sub-agent holds exactly what its parent held. If the
parent could write as well as read, so can the sub-agent. If the parent could delegate
onward, the sub-agent can too, to a fourth agent you never authorized and cannot see. The
credential carries no record that a delegation happened, so there is nothing to inspect
and nothing to narrow.

**Revocation does not reach the sub-agent.** You revoke the parent's credential. The
sub-agent is holding a copy of that same secret, or a token minted from it that names no
parent. A resource server checking that token sees a valid token. The sub-agent keeps
working until its token expires on its own schedule — which, for a token issued to a
long-running agent, may be hours. OAuth token revocation (RFC 7009) revokes the token you
name; it has no concept of the tokens derived from it. X.509 CRL and OCSP revoke a
certificate, not a delegation subtree.

So: an agent you have revoked can still act, through a delegate you cannot enumerate.

## What this actually provides

**Every hop is a record.** A delegation is not a copied secret and not a freshly minted
token that forgets where it came from. It is a signed object naming its issuer, its
audience, and the SHA-256 CID of its parent — content and signature together. The chain from
any leaf to its root is therefore an attributable statement: *this* agent, holding *this*
key, authorized *that* agent, at *this* time, under *these* caveats. Ed25519 signatures make
it non-repudiable per hop; an HMAC scheme cannot do this, because anyone who can verify can
also mint.

**Revoking any ancestor denies the whole subtree.** Verification cannot proceed without
reconstructing the chain to its root (step 1). Step 6 then checks the revocation state of
**every element's CID and every element's audience** on the reconstructed chain:

```go
subjects := make(map[string]struct{})
for _, e := range chain.Elements {
    subjects[e.CID] = struct{}{}
    subjects[elemAud(e)] = struct{}{}
}
```

The root-walk is not an optional enrichment a deployment can skip for latency — it is how
the verifier learns what the leaf is authorized to do at all. A revoked ancestor is
therefore always in the set being checked. This does not depend on enumerating descendants,
on a registration index, or on a transparency log.

**Be precise about what this is not.** The [UCAN Revocation
spec](https://ucan.xyz/revocation/) states that "revocation of a particular proof does not
guarantee that the Agent can no longer access to the capability in question," because the
agent may hold a second, unrevoked chain to the same capability. **That sentence is equally
true here, and an earlier version of this README wrongly claimed otherwise.** Forbidding
branching means one *credential* has one path to one root. It does not mean one *agent* holds
one credential. An agent with two credentials over the same resource keeps the second when
you revoke an ancestor of the first.

The guarantee is therefore per-credential, and stating it any wider is an overclaim: revoking
any element of a chain denies that chain and every chain descending from it. What UCAN allows
and this does not is a *single* credential deriving authority from several parents, so that
revoking one ancestor may leave the credential alive by another path. That difference is
bought by rejecting multi-parent delegation outright — a real capability given up, discussed
in [DESIGN.md](DESIGN.md).

Closing the gap properly would require confinement, and the UCAN spec is right that this is
not available: it would require every process to be online, which defeats the offline-capable
design both protocols want.

**Where that leaves the limits.** Verification is complete; the *published* revocation state
is not. The difference is documented under "Four qualifications on revocation" below, with a
worked example showing `/v1/status/{cid}` reporting `revoked:false` for a credential that
`/v1/verify` denies. Read that section before relying on any of this.

## Prior art

Restriction-only attenuation — a delegation that adds caveats and never restates authority —
is **established prior art, not a contribution of this project.** It was arrived at here
independently, which is not the same as arriving at it first. A reader who finds any of the
following before finding this section should discount the rest of the page, so it is stated
up front rather than in a footnote:

- **Macaroons** (Birgisson et al., NDSS 2014) got the attenuation model right first: append
  caveats, never restate authority, intersect at verification. A RESTRICT block is closer to
  a macaroon than to anything in the UCAN specification.
- **Biscuit** (v2/v3) is the closest system to this one — public-key, append-only attenuation
  blocks, offline-verifiable. Its authorization language is Datalog rather than a fixed
  caveat vocabulary.
- **UCAN 1.0** expresses attenuated delegation through `cmd` plus `pol`, covering much of
  what caveats do here.
- **The caretaker pattern** from the object-capability literature is the same idea again and
  older than all of it: hand out a revocable forwarder rather than the authority itself.
- **AIP** — Agent Interaction Protocol ([arXiv 2603.24775](https://arxiv.org/abs/2603.24775),
  now [draft-prakash-aip-00](https://datatracker.ietf.org/doc/draft-prakash-aip/)) — ships
  the same attenuation model, and ships transport bindings for MCP, A2A and HTTP that this
  project has specified and not built.

**On Biscuit, be precise about the delta.** A Biscuit token carries its ancestor blocks
inline and each block has a revocation identifier, so revoking a parent block denies every
attenuated descendant that carries it. Subtree denial is achievable there. The difference is
narrower than "Biscuit cannot do this": here the ancestor walk is *structurally unavoidable*,
because authority is not present in the leaf and must be computed from the root, whereas a
Biscuit verifier already holds every block and must be configured to check their revocation
identifiers. Whether that distinction matters to you depends on whether you would rather rely
on a step that cannot be skipped or one that can.

**On AIP:** it defers revocation to a future version. That is the axis on which these two
designs differ, and it is the axis this project should be judged on — not attenuation, where
AIP and this arrive at the same place.

**The closed caveat vocabulary versus Biscuit's Datalog is an engineering tradeoff, not a
discovery.** A fixed set of caveat types with a fail-closed `default:` branch is a smaller
trusted computing base than a Datalog evaluator and easier to bound on adversarial input. It
is also strictly less expressive, and the cost of that is visible in this repository's own
history: `action_restrict` was added in v0.2.0 because the vocabulary could not express
read-only delegation — a root holding `resource/read` and `resource/write` over one URI space
had no way to delegate either one alone. That is the vocabulary growing under pressure from
the first serious scenario anyone tried, which is precisely the failure mode a Datalog engine
does not have. Expect it to grow again. [DESIGN.md](DESIGN.md) works the tradeoff through in
full.

## How attenuation works

This is an implementation detail of the record above, not the headline.

A delegation is a signed block carrying **no capability set at all** — only `prf` (the
parent's content hash), a shrinking depth counter, a validity window that cannot widen, and
a list of caveats:

```json
{ "typ": "adtp/cav/1",
  "iss": "<parent's audience>", "aud": "<child>",
  "prf": "bafkrei...",           // content hash of the parent
  "nbf": 1786691217, "exp": 1786694817,
  "dl":  2,                      // in [0, parent's dl)
  "cav": [ {"type":"resource_restrict","resource":"tool://search.example/web"} ],
  "sig": "..." }
```

The leaf's authority is the root credential's capability set **intersected with every caveat
on the path**, evaluated when the request arrives. A block can only add caveats. There is no
field in which to write a broader permission, so **chain validation performs no
set-containment comparison** — there is no capability set below the root to compare against
anything.

Be precise about what that does and does not mean. Comparison did not leave the system; it
moved. `CanonicalizeURI` and `URICovers` still run at authorization
([`internal/verify/steps.go`](internal/verify/steps.go) step 8), on every verification, and
`evaluateConstraint` still dispatches nine constraint types. What the structure removes is
per-hop semantic comparison against a parent. The difference is where a mistake lands: in the
usual design a comparison bug widens a credential permanently; here a bug in `URICovers`
denies a request or authorizes one resource wrongly, against a grant the platform wrote and
signed. Fewer places to be wrong, and a smaller blast radius when you are. Not zero — and
[SECURITY_AUDIT.md](SECURITY_AUDIT.md) F14 is the standing evidence: an exploitable hole that
involved no comparison code at all.

Until v0.2.0 this was qualified further, because a second mode (RESTATE) did restate
capabilities and did run a 115-line comparison function. That mode is removed, along with
`CapabilityLeq`, the `att_seal` machinery, and the `mode` parameter on the delegations API.
There is one delegation mode.

## How it works

**Identity.** Every agent is a `did:key` wrapping an Ed25519 public key. Resolution is
local — the key is *in* the identifier, so there is no registry to consult and no network
call in the verification path. Ed25519 is the only algorithm; there is no `alg` negotiation
and no unsigned path.

**Chain.** A root credential is a UCAN-compatible JWT signed by the platform, naming an
agent as `aud`. Each delegation adds a block whose `prf` is the SHA-256-based CIDv1 of its
parent's complete serialized bytes, signature included. Pinning the hash pins content and
signature together.

**Verification** runs the specification's thirteen ordered steps, failing on the first
violation. **Nine of those thirteen can deny a request.** The number 13 comes from the spec,
and quoting it without saying which steps carry weight is how a pipeline sounds more thorough
than it is:

The nine that can deny: chain build, structural checks, per-hop linkage, root trust,
signatures, temporal validity, revocation, authorization, proof-of-possession.

The other four, and why:

- **Step 7 (attenuation integrity) is a no-op by design.** Since RESTATE was removed only the
  root carries a capability set, so no hop can widen one and there is nothing per-hop to
  check. This is the design working, not a feature missing — see
  [`internal/verify/steps.go`](internal/verify/steps.go).
- **Step 9 (cross-org policy) returns immediately.** Nothing populates `TrustPolicies` from
  configuration, so no chain is ever classified cross-organizational. This is a feature
  missing.
- **Step 11 (registration) is near-vacuous on the daemon path**: it checks the leaf against
  the store that registered it milliseconds earlier, and degrade-accepts below `HIGH` tier.
  It is a real check only for a credential registered by some other process.
- **Step 12 (audit) does work but cannot fail verification** — it writes a hash-linked entry
  and its error is discarded, so an audit-log outage never denies a request. That is a
  deliberate availability choice, stated here because "13 steps including audit" implies a
  gate that does not exist.

Two ordering choices among the nine matter: cycles are detected in step 1, before any
signature is verified, so a malicious cyclic chain costs one hash per hop rather than one
Ed25519 verify; and the replay nonce is consumed in step 10 only *after* the invocation
signature validates, so forged invocations cannot exhaust the cache.

**Revocation** is covered under [What this actually provides](#what-this-actually-provides)
above; the worked example below shows both what it catches and what it fails to publish.

### Worked example

Real output from this binary. Two agents, a root credential, one RESTRICT hop narrowing to
a single resource:

```
$ curl ... /v1/agents      -d '{"sponsor_did":"ops@example.com"}'
orchestrator: did:key:z6MkveVgqbmKY1d39iGoSTrdmyVeD15pqdHwqf2Ho1e8nbQc
sub-agent   : did:key:z6MkueaVZYW8ajXsDWNDioK7MahiyprxWZLiYVqtLY4JNMPf

$ curl ... /v1/credentials -d '{"agent_did":"<orchestrator>", "capabilities":[...]}'
root cid    : bafkreigcd2iejzrk6v2me6gcytpwvvcsbqamoojsg5bvmlewfzgdg7u5my

$ curl ... /v1/delegations -d '{"parent_cid":"<root>","audience_did":"<sub-agent>",
                                "depth_left":2,
                                "caveats":[{"type":"resource_restrict",
                                            "resource":"tool://search.example/web"}]}'
delegated   : bafkreifoqss3coqihrcmx7mqo7dgackh7glvok2nzctqv3qz3scsl5favu
```

The caveat binds — the sub-agent reaches `/web` and nothing else:

```
$ curl ... /v1/verify -d '{"chain":["<delegated>"],"action":"tool/invoke",
                           "resource":"tool://search.example/web"}'
{"authorized":true,"chain_depth":2,"risk_tier":"HIGH"}

$ curl ... /v1/verify -d '{"chain":["<delegated>"],"action":"tool/invoke",
                           "resource":"tool://search.example/internal"}'
{"authorized":false,"chain_depth":2,"risk_tier":"HIGH",
 "error":"verification failed","error_code":"ADTP_DENIED"}
```

Now revoke the **parent** with a plain `REVOKED`, which fires no cascade:

```
$ curl ... /v1/revoke -d '{"subject_cid":"<root>","scope":"credential","status":"REVOKED"}'
{"seq":1,"status":"REVOKED"}
```

The descendant is *not* recorded as revoked — no cascade entry was written for it:

```
$ curl ... /v1/status/<delegated>
{"cid":"bafkrei...l5favu","revoked":false}
```

And it is denied anyway, because step 6 checked the parent's CID while walking the chain:

```
$ curl ... /v1/verify -d '{"chain":["<delegated>"],"action":"tool/invoke",
                           "resource":"tool://search.example/web"}'
{"authorized":false,"chain_depth":2,"risk_tier":"HIGH",
 "error":"verification failed","error_code":"ADTP_REVOKED"}
```

That gap between the two answers is the honest shape of this feature. Verification is
complete; the *published* revocation state is not. `COMPROMISED` is the status that also
writes explicit cascade entries — on a three-hop chain:

```
$ curl ... /v1/revoke -d '{"subject_cid":"<root>","scope":"subtree","status":"COMPROMISED"}'
{"seq":1,"status":"COMPROMISED","cascade_count":2}

$ curl ... /v1/status/<hop1>   →  {"revoked":true,"status":"CASCADE","seq":1}
$ curl ... /v1/status/<hop2>   →  {"revoked":true,"status":"CASCADE","seq":1}
$ curl ... /v1/verify  (leaf)  →  {"authorized":false,"error_code":"ADTP_REVOKED"}
```

### Four qualifications on revocation

Stated plainly, because each is a real limit:

1. **Explicit cascade fires only for `COMPROMISED`.** Any other status writes one entry, for
   the named subject only. Verification still denies descendants via the chain walk, but
   `GET /v1/status/{cid}` and the published `/v1/revocation/list` will not mention them. A
   consumer that trusts the list instead of walking the chain gets a wrong answer.
2. **The lookup fails open below `HIGH` risk tier.** If the revocation store errors, `HIGH`
   denies; `MEDIUM`, `LOW`, and `ANALYTICS` log a warning and proceed. The default is `HIGH`,
   so this is closed out of the box and a config change opens it.
3. **A `nil` revocation cache skips step 6 entirely.** Not reachable through the daemon,
   which always wires the store in, but it is the zero-value default for anyone importing
   the verifier as a library.
4. **`Scope` is not read at verification.** `credential`, `subtree`, and `identity` scopes
   all deny identically once the entry exists. Fails safe, but the field is decorative on
   this path — do not build policy on it.

## Quickstart

Every command below was run against a build of this commit.

```bash
git clone https://github.com/Zahanturel/adtp.git
cd adtp && go build -o adtpd ./cmd/adtpd
./adtpd --config config.yaml
```

Or install a tagged build. `v0.1.0` is this release; `v0.1.0-alpha` is the earlier
prerelease and predates the corrections described in
[SECURITY_AUDIT.md](SECURITY_AUDIT.md):

```bash
go install github.com/Zahanturel/adtp/cmd/adtpd@v0.1.0
```

On first run the daemon generates a platform key and an API key, and tells you where:

```
level=WARN msg="memory backend: agent keys are not persisted; after a restart this daemon
    cannot delegate or sign invocations for any agent registered before it" backend=memory
level=INFO msg="generated platform identity" did=did:key:z6Mkh... key_path=platform.key
level=WARN msg="generated a random API key (no keys configured); read it from the file and
    store it securely" path=api.key
level=INFO msg="adtpd listening" addr=127.0.0.1:8080 tls=false backend=memory
```

```bash
export KEY=$(cat api.key)
auth() { curl -s -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" "$@"; }
```

Register two agents, issue a root credential, delegate, verify, revoke:

```bash
auth -X POST localhost:8080/v1/agents -d '{"sponsor_did":"ops@example.com"}'

auth -X POST localhost:8080/v1/credentials -d '{
  "agent_did":"<orchestrator-did>",
  "capabilities":[
    {"can":"tool/invoke","with":"tool://search.example/*"},
    {"can":"agent/delegate","with":"tool://search.example/*",
     "constraints":[{"type":"delegation_depth","max":3}]}],
  "exp_seconds":3600}'

auth -X POST localhost:8080/v1/delegations -d '{
  "parent_cid":"<root-cid>","audience_did":"<sub-agent-did>",
  "depth_left":2,
  "caveats":[{"type":"resource_restrict","resource":"tool://search.example/web"}]}'

auth -X POST localhost:8080/v1/verify -d '{
  "chain":["<delegated-cid>"],"action":"tool/invoke",
  "resource":"tool://search.example/web"}'

auth -X POST localhost:8080/v1/revoke -d '{
  "subject_cid":"<root-cid>","scope":"subtree","status":"COMPROMISED"}'
```

Two things that will bite you:

- **`scope` and `mode` are lowercase.** `"scope":"credential"`, `"subtree"`, `"identity"`.
  Passing `"CREDENTIAL"` returns `{"error":"revocation not permitted","code":"ADTP_DENIED"}`,
  because the authority model matches the scope string exactly.
- **A delegation restricted only by `budget`, `max_calls`, or `parameter_schema` will be
  issued and then denied at every invocation.** See the next section.

To issue a root credential that can delegate, it needs an `agent/delegate` capability
carrying a `delegation_depth` constraint; without one, delegation is refused at issuance.

[`examples/`](examples/) has a runnable [bash walkthrough](examples/quickstart/demo.sh) and
an [MCP tool-authorization example](examples/mcp-tool-auth/) in Python.

## Metering is not implemented

`budget`, `max_calls`, and `parameter_schema` need a metering backend this build does not
have. Rather than treat an unenforceable restriction as no restriction, the verifier fails
closed, so those three **always deny**:

```
$ curl ... /v1/delegations  (caveats: [{"type":"max_calls","limit":100}])
issued: bafkreiftwchryc7ci2gjsch4zjuvubt75qqixjki443o5paqhz5gxhrpv4

$ curl ... /v1/verify
{"authorized":false,"chain_depth":2,"risk_tier":"HIGH",
 "error":"verification failed","error_code":"ADTP_DENIED"}
```

This is the safe direction, but it looks like a bug from outside, so: it is deliberate, and
it is why those caveats are documented as present-but-unenforced in
[CAPABILITIES.md](CAPABILITIES.md).

## API

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/v1/agents` | POST | yes | Register an agent; daemon generates its DID and key |
| `/v1/agents/{did}` | GET | yes | Look up an agent's lifecycle state |
| `/v1/credentials` | POST | yes | Issue a root credential |
| `/v1/delegations` | POST | yes | Delegate: add caveats to a parent credential |
| `/v1/verify` | POST | yes | Run the 13-step pipeline against an action and resource |
| `/v1/revoke` | POST | yes | Post a revocation; `COMPROMISED` also cascades |
| `/v1/revocation/list` | GET | **no** | Signed revocation list |
| `/v1/status/{cid}` | GET | yes | Revocation status of one subject |
| `/v1/admin/reconcile` | POST | yes | Rebuild missing registration-index entries |
| `/health` | GET | **no** | Liveness and platform DID |

`/health` and `/v1/revocation/list` bypass authentication and rate limiting by design — the
list is meant to be publicly fetchable. Everything else needs
`Authorization: Bearer <api-key>`, or an OIDC bearer token when `auth.mode: oidc`.

See [CAPABILITIES.md](CAPABILITIES.md) for actions, constraints, and caveats.

## Status

This is a reference implementation of a protocol design. It is not production software. It
has no users, no released version, and no stability guarantees; the wire format may change
without a migration path.

**Implemented:** did:key/Ed25519 identity; UCAN credential chains; RESTRICT
delegation; the verification pipeline (nine of thirteen steps can deny — see above); signed
revocation entries and lists, with
`COMPROMISED` cascade and registration-index reconciliation; a hash-linked audit log; OIDC
bearer auth (RS256 against a JWKS URL); batched audit export to an HTTP webhook; in-memory
and PostgreSQL backends. RESTRICT is exercised by eight adversarial escalation vectors in
[`internal/verify/adversarial_test.go`](internal/verify/adversarial_test.go).

**Not implemented,** though named in the protocol design: transparency-log-backed
registration, `on_behalf_of` dual-chain verification (invocations carrying it are rejected
rather than silently accepted), TLS-exporter channel binding, session credentials, budget
metering, did:web organizational federation, and MCP/A2A transport bindings. These are
described in [docs/PROTOCOL.md](docs/PROTOCOL.md) Appendix A, which is explicitly a roadmap
and not a description of this binary. Worth naming plainly: AIP already ships the transport
bindings, so on that axis this project is behind, not ahead. See [DESIGN.md](DESIGN.md#scope)
and [Prior art](#prior-art).

**Agent keys are held by the daemon in plaintext.** This is a custodial service: it signs
on each agent's behalf, so it must be able to recover the key material. With the PostgreSQL
backend, keys persist in the `agent_keys` table as raw bytes — read access to that table is
equivalent to impersonating every agent in it. Protect it with encryption at rest and
restrictive grants. With the in-memory backend keys are not persisted at all, and after a
restart the daemon cannot delegate or sign for any previously registered agent; it warns
about this at startup. HSM-backed custody is not implemented.

**Cross-organizational trust** exists as a type (`TrustPolicy`: a platform DID list and a
depth bound) but nothing populates it from configuration, so it is unreachable through the
daemon.

**The control plane authenticates callers but does not authorize them: any valid API key can
revoke as the platform authority, verify as any agent whose key the daemon holds, and walk
the entire credential store.** There are no scopes, roles, or per-key restrictions of any
kind — one key is total control. Scoped API keys are tracked for v0.3.

**Proof of possession requires a client-signed invocation.** When `/v1/verify` is called
without one, the daemon can mint and sign an invocation using the leaf agent's custodial key
and then verify its own signature — which proves nothing about the caller and makes
verification step 10 vacuous. That path is disabled by default; set
`verify.allow_custodial_invocation: true` to enable it, and only where the caller is already
trusted to act for every agent in the key store.

**Windows:** the Makefile needs a POSIX shell. Use `go build -o adtpd.exe ./cmd/adtpd` and
`go test ./...` directly.

## Specification, design notes, license

- [docs/PROTOCOL.md](docs/PROTOCOL.md) — the specification. **Part I describes what this
  binary does; Appendix A is a roadmap of things that are not built.** They are segregated
  because a previous revision described roughly 40% more system than the code implements,
  without saying so.
- [DESIGN.md](DESIGN.md) — the long form of [Prior art](#prior-art): why UCAN over macaroons,
  biscuits, the caretaker pattern and scoped JWTs, and how this compares to AIP; why did:key
  over did:web; what this design gives up; what the implementation revealed.
- [SECURITY_AUDIT.md](SECURITY_AUDIT.md) — an audit of this implementation against its own
  claims, including what is still open.
- [SECURITY.md](SECURITY.md) — reporting a vulnerability.
- [CONTRIBUTING.md](CONTRIBUTING.md) — DCO sign-off (`git commit -s`); no CLA.


Licensed under [Apache 2.0](LICENSE).
