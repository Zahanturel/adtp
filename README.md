# ADTP — Agent Delegation and Trust Protocol

[![CI](https://github.com/Zahanturel/adtp/actions/workflows/ci.yml/badge.svg)](https://github.com/Zahanturel/adtp/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/Zahanturel/adtp.svg)](https://pkg.go.dev/github.com/Zahanturel/adtp)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

ADTP is a protocol and Go daemon for bounded, revocable delegation between software agents:
each agent holds its own Ed25519 keypair, every delegation is a signed link in a chain, and
revoking a link denies everything beneath it.

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

## The core design decision

Attenuation is a property of the token structure, not a check performed at policy
evaluation time.

The usual approach is a comparison. The child token restates its permissions, and the
verifier computes whether the child's set is a subset of the parent's — comparing scope
strings, or URI patterns, or Datalog predicates. That comparison function is then part of
the trusted computing base: every escalation bug in it is an escalation bug in the system.
It has to decide whether `read:files/*` covers `read:files/../etc/passwd`, whether
`budget<=100` refines `budget<=50`, whether an unrecognized field is safe to ignore. Get
any case wrong and a child mints authority its parent never held.

ADTP's primary mode, RESTRICT, removes the comparison instead of trying to make it
correct. A delegation is a signed block that carries **no capability set at all** — only
`prf` (the parent's content hash), a shrinking depth counter, a validity window that
cannot widen, and a list of caveats:

```json
{ "typ": "adtp/cav/1",
  "iss": "<parent's audience>", "aud": "<child>",
  "prf": "bafkrei...",           // content hash of the parent
  "nbf": 1786691217, "exp": 1786694817,
  "dl":  2,                      // strictly less than the parent's
  "cav": [ {"type":"resource_restrict","resource":"tool://search.example/web"} ],
  "sig": "..." }
```

The leaf's authority is the root credential's capability set **intersected with every
caveat on the path**, evaluated when the request arrives. A block can only add caveats.
There is no field in which to write a broader permission, so there is no subset check to
get wrong, and the verifier contains no capability-comparison code on this path
([`internal/verify/steps.go`](internal/verify/steps.go) step 7 skips it entirely for
RESTRICT hops). Escalating requires forging an Ed25519 signature or finding a SHA-256
collision on `prf`.

**This applies to RESTRICT, not to the whole system.** ADTP also has a compatibility mode,
RESTATE, where the child does restate its capabilities and the verifier does run a
comparison — `CapabilityLeq` in
[`internal/credential/capability_leq.go`](internal/credential/capability_leq.go), 115 lines
of type-switched semantic comparison. In RESTATE mode that function **is** trusted
computing base, exactly like the approach above. It is reachable today: `POST
/v1/delegations` with `"mode":"restate"`. It fails closed on constraint types it does not
model and on URIs that fail canonicalization, and `RESTATE` after `RESTRICT` is structurally
prohibited, but none of that makes it structural. Prefer RESTRICT, which is the default when
`mode` is omitted. See [DESIGN.md](DESIGN.md) for why both exist.

## How it works

**Identity.** Every agent is a `did:key` wrapping an Ed25519 public key. Resolution is
local — the key is *in* the identifier, so there is no registry to consult and no network
call in the verification path. Ed25519 is the only algorithm; there is no `alg` negotiation
and no unsigned path.

**Chain.** A root credential is a UCAN-compatible JWT signed by the platform, naming an
agent as `aud`. Each delegation adds a block whose `prf` is the SHA-256-based CIDv1 of its
parent's complete serialized bytes, signature included. Pinning the hash pins content and
signature together.

**Verification** runs 13 ordered steps, failing on the first violation. Two ordering
choices matter: cycles are detected in step 1, before any signature is verified, so a
malicious cyclic chain costs one hash per hop rather than one Ed25519 verify; and the
replay nonce is consumed in step 10 only *after* the invocation signature validates, so
forged invocations cannot exhaust the cache. The steps are chain build, structural checks,
per-hop linkage, root trust, signatures, temporal validity, revocation, attenuation
integrity, authorization, cross-org policy, proof-of-possession, registration, audit.

**Revocation** is where the chain shape pays off. Step 1 always reconstructs the chain to
its root. Step 6 then checks **every element's CID and every element's audience** against
revocation state ([`internal/verify/steps.go`](internal/verify/steps.go)):

```go
subjects := make(map[string]struct{})
for _, e := range chain.Elements {
    subjects[e.CID] = struct{}{}
    subjects[elemAud(e)] = struct{}{}
}
```

A revoked ancestor is therefore always in the set being checked, and its whole subtree is
denied. That does not depend on enumerating descendants, on a registration index, or on a
transparency log — it falls out of the fact that verification cannot proceed without
walking to the root.

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
                                "mode":"restrict","depth_left":2,
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
  "mode":"restrict","depth_left":2,
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
| `/v1/delegations` | POST | yes | Delegate (`restrict` default, or `restate`) |
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

**Implemented:** did:key/Ed25519 identity; UCAN credential chains; RESTRICT and RESTATE
delegation; the 13-step verification pipeline; signed revocation entries and lists, with
`COMPROMISED` cascade and registration-index reconciliation; a hash-linked audit log; OIDC
bearer auth (RS256 against a JWKS URL); batched audit export to an HTTP webhook; in-memory
and PostgreSQL backends. 258 tests and 5 fuzz targets; RESTRICT is exercised by 7
adversarial escalation tests in
[`internal/verify/adversarial_test.go`](internal/verify/adversarial_test.go).

**Not implemented,** though named in the protocol design: transparency-log-backed
registration, `on_behalf_of` dual-chain verification (invocations carrying it are rejected
rather than silently accepted), TLS-exporter channel binding, session credentials, budget
metering, did:web organizational federation, and MCP/A2A transport bindings. See
[DESIGN.md](DESIGN.md#scope).

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

**Windows:** the Makefile needs a POSIX shell. Use `go build -o adtpd.exe ./cmd/adtpd` and
`go test ./...` directly.

## Specification, design notes, license

- [docs/PROTOCOL.md](docs/PROTOCOL.md) — the protocol specification: wire formats, the 13
  steps, the revocation authority model, 13 adversary classes, 10 security properties.
- [DESIGN.md](DESIGN.md) — why UCAN over macaroons, biscuits, and scoped JWTs; why did:key
  over did:web; what this design gives up; what the implementation revealed.
- [SECURITY_AUDIT.md](SECURITY_AUDIT.md) — an audit of this implementation against its own
  claims, including what is still open.
- [SECURITY.md](SECURITY.md) — reporting a vulnerability.
- [CONTRIBUTING.md](CONTRIBUTING.md), [CLA.md](CLA.md).

Licensed under [Apache 2.0](LICENSE).
