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

Actions follow a `namespace/verb` convention. Unknown actions are passed through and matched literally at verification time.

## Resource URIs (`with`)

The `with` field is a URI that scopes where the action applies. ADTP supports glob-style matching:

```
tool://search.example/query      exact tool
tool://search.example/*          all tools on that server
resource://db.example/customers  exact resource
resource://db.example/*          all resources on that server
*                                any resource (root credentials only)
```

At verification step 9 (Authorization), the requested resource must be covered by the capability's `with` URI. Coverage rules: an exact URI covers itself; a `*` suffix covers any path under the prefix.

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

Meters cumulative usage along a delegation path. Requires metering to be enabled.

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

Pins the shape of invocation parameters. Compared by deep equality in v0.x.

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

Caveats are used in RESTRICT mode delegations. They can only add restrictions, never remove them. Every caveat from every block in the chain is evaluated at verification step 8.

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

Rate-limits invocations. Requires metering to be enabled.

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
