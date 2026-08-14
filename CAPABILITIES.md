# ADTP Capability Reference

This document defines the actions, constraint types, and caveat types supported by the ADTP daemon. Use this as the reference when constructing API requests.

## Actions (`can`)

Capabilities use a `can` field to specify the permitted action.

| Action | Description |
|---|---|
| `tool/invoke` | Invoke a named tool |
| `resource/read` | Read a resource by URI |
| `resource/write` | Write to a resource by URI |
| `agent/delegate` | Create a sub-delegation chain |
| `api/call` | Call an external API endpoint |

This is a **closed set**. An unknown action is not passed through — `Capability.Validate` rejects it at issuance with `unknown capability type`, and adding an action requires a `ucv` version bump ([`internal/credential/capability.go`](internal/credential/capability.go)).

## Resource URIs (`with`)

The `with` field is a canonical URI scoping where the action applies. It must be in
`scheme://authority[/path]` form; the daemon canonicalizes and re-checks it, rejecting
anything that is not already canonical.

Matching is **positional and segment-counted**, not prefix-based. A `*` segment matches
exactly one non-empty segment. `**` is reserved and unsupported, so coverage never spans
more segments than the parent specifies:

```
URICovers("tool://x/*",   "tool://x/a")     = true    one segment matches one segment
URICovers("tool://x/*",   "tool://x/a/b")   = false   deeper path is NOT covered
URICovers("tool://x/*",   "tool://x/")      = false   the wildcard needs a non-empty segment
URICovers("tool://x",     "tool://x/a")     = false   segment counts differ
URICovers("tool://x/a/*", "tool://x/a/b")   = true
URICovers("tool://x/*/c", "tool://x/b/c")   = true    wildcards may sit mid-path
URICovers("tool://x/*",   "tool://y/a")     = false   authority must be equal
```

A bare `*` is **not** a valid `with` value — it fails canonicalization
(`expected scheme://authority form`). There is no "any resource" wildcard.

### `*` means different things in the two positions

`URICovers(pattern, resource)` is asymmetric, and the asymmetry is not visible in the
function's signature — it takes two URIs and its first test is string equality.

- **Pattern position** (a capability's `with`): a `*` path segment is a wildcard, as above.
  This is the grant.
- **Resource position** (a verification request's `resource`): there is no wildcard
  semantics. The resource names the single concrete thing being acted on.

Nothing in the URI profile enforces that distinction. `*` is a legal sub-delim, so
`tool://x/*` is a perfectly canonical URI and `URICovers("tool://x/*", "tool://x/*")`
returns **true** via the equality fast path — authorizing the pattern itself rather than any
resource it covers. A caller who passes a glob where a resource belongs would get an ALLOW
for something that was never resolved to a real target.

`/v1/verify` therefore rejects any request whose `resource` contains a `*` or `**` segment,
with 400 `AGENT_ERR_V017_MALFORMED`, and verification step 8 rejects it again for callers
that use the library directly.

At **verification step 8** (Authorization) the requested resource must be covered by the
matched capability's `with`. Any URI that fails canonicalization causes coverage to return
false, so malformed input fails closed.

## Metering is not implemented — three types always deny

Three of the types below need a metering or enforcement backend that this build does not
have. `MeteringEnabled` is hardcoded `false` in the daemon
([`api/v1/handlers.go`](api/v1/handlers.go)), and the verifier **fails closed** rather than
treating an unenforceable restriction as unrestricted
([`internal/verify/steps.go`](internal/verify/steps.go)):

| Type | Behaviour today |
|---|---|
| `budget` | Always denies with `CAPABILITY_INSUFFICIENT` |
| `max_calls` | Always denies with `CAPABILITY_INSUFFICIENT` |
| `parameter_schema` | Always denies with `CAPABILITY_INSUFFICIENT` |

A delegation whose **only** restriction is one of these is therefore unusable: it will be
issued successfully and then denied at every invocation. This is deliberate — silently
accepting a budget-restricted delegation as unrestricted would be the more dangerous
failure — but it looks like a bug from the outside, so it is stated here.

They remain documented because the wire format is stable and signatures over them verify;
only enforcement is missing. Metering is on the v0.2 roadmap.

## Constraint Types

Constraints are attached to capabilities in the `constraints` array. Each has a `type` discriminator.

### `time_window`

Restricts when the capability is valid.

```json
{"type": "time_window", "start": 1719000000, "end": 1719086400}
```

| Field | Type | Description |
|---|---|---|
| `start` | integer | UNIX timestamp, inclusive |
| `end` | integer | UNIX timestamp, exclusive. Must exceed `start` |

### `budget`

Meters cumulative usage along a delegation path. **Not enforced in this build — always denies.** See "Metering is not implemented" above.

```json
{"type": "budget", "dim": "tokens", "limit": 10000, "scope": "leaf", "meter": "verifier"}
```

| Field | Type | Description |
|---|---|---|
| `dim` | string | Dimension name (e.g. `"tokens"`, `"cost_usd"`) |
| `limit` | integer | Non-negative ceiling |
| `scope` | string | `"leaf"` (per-credential) or `"chain"` (cumulative) |
| `meter` | string | `"verifier"` (daemon-tracked) or `"receipts"` (externally-attested) |
| `window` | object | Optional `{start, end}` time window; defaults to credential lifetime |

### `param_limit`

Bounds a single invocation parameter per-call (distinct from cumulative budget).

```json
{"type": "param_limit", "field": "max_tokens", "max": 4096}
```

| Field | Type | Description |
|---|---|---|
| `field` | string | Parameter name to constrain |
| `max` | integer | Non-negative maximum value |

### `parameter_schema`

Pins the shape of invocation parameters. Compared by deep equality in v0.x. **Not enforced in this build — always denies.** See "Metering is not implemented" above.

```json
{"type": "parameter_schema", "schema": {"type": "object", "properties": {"query": {"type": "string"}}}}
```

| Field | Type | Description |
|---|---|---|
| `schema` | object | JSON Schema object. Must be valid I-JSON (no duplicate keys) |

### `delegation_depth`

Bounds further delegation depth. Used on `agent/delegate` capabilities to set the initial depth-left.

```json
{"type": "delegation_depth", "max": 5}
```

| Field | Type | Description |
|---|---|---|
| `max` | integer | Non-negative maximum delegation depth |

## Caveat Types (RESTRICT mode)

Caveats are used in RESTRICT mode delegations. They can only add restrictions, never remove them. Every caveat from every block in the chain is evaluated at verification step 8 — a child cannot drop a parent's caveat by omitting it, because the parent block is still walked.

### `time_window`

Same as the constraint type. Restricts when the delegated credential is valid.

```json
{"type": "time_window", "start": 1719000000, "end": 1719086400}
```

### `resource_restrict`

Narrows the resource URI the credential may target.

```json
{"type": "resource_restrict", "resource": "tool://search.example/query"}
```

| Field | Type | Description |
|---|---|---|
| `resource` | string | Canonical URI. Must match the URI canonicalization rules |

### `method_restrict`

Restricts the allowed methods or operations.

```json
{"type": "method_restrict", "methods": ["GET", "HEAD"]}
```

| Field | Type | Description |
|---|---|---|
| `methods` | string[] | At least one method required |

### `max_calls`

Rate-limits invocations. **Not enforced in this build — always denies.** See "Metering is not implemented" above.

```json
{"type": "max_calls", "limit": 100}
```

| Field | Type | Description |
|---|---|---|
| `limit` | integer | Non-negative invocation count ceiling |
| `window` | object | Optional `{start, end}` time window; defaults to credential lifetime |

### `delegation_depth`

Same as the constraint type. Bounds further delegation from this point in the chain.

```json
{"type": "delegation_depth", "max": 3}
```

## Unknown Types

Any constraint or caveat type not listed above is preserved byte-for-byte (for signature stability) and **fails closed** at verification time. This means future constraint types added to the protocol will be denied by older daemons rather than silently ignored.

## Example: Full Capability

```json
{
  "can": "tool/invoke",
  "with": "tool://search.example/*",
  "constraints": [
    {"type": "time_window", "start": 1719000000, "end": 1719086400},
    {"type": "param_limit", "field": "max_tokens", "max": 4096}
  ]
}
```

## Example: RESTRICT Delegation

```bash
curl -X POST localhost:8080/v1/delegations \
  -H "Authorization: Bearer <api-key>" \
  -d '{
    "parent_cid": "<cid>",
    "audience_did": "<did>",
    "mode": "restrict",
    "depth_left": 3,
    "caveats": [
      {"type": "resource_restrict", "resource": "tool://search.example/query"},
      {"type": "method_restrict", "methods": ["GET"]},
      {"type": "time_window", "start": 1719000000, "end": 1719086400}
    ]
  }'
```
