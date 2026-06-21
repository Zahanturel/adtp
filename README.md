# ADTP — Agent Delegation and Trust Protocol

**Every AI agent gets its own cryptographic identity. Every delegation is a signed chain. Revocation is provably complete.**

ADTP is an open protocol and Go daemon that gives AI agents their own cryptographic identities instead of sharing human credentials. It enforces capability attenuation at the protocol level — not with policy checks, but with structural invariants that make escalation impossible.

Single binary. No runtime dependencies. Apache 2.0.

## Why this exists

AI agents today share human credentials. When Agent A delegates to Agent B, there is no cryptographic record. When you revoke access, downstream agents keep running.

This is not a configuration problem. It is a missing protocol.

ADTP provides:

- **did:key/Ed25519 identity** — every agent gets its own key pair, not a shared service account
- **UCAN credential chains** — every delegation is cryptographically signed and independently verifiable
- **RESTRICT mode** — capabilities can only narrow at each delegation step, never widen. This is a structural invariant, not a policy check
- **Provably-complete cascade revocation** — a registration invariant guarantees that revoking a credential kills every descendant. No orphans. Not eventual consistency — mathematical completeness
- **13-step verification pipeline** — from chain construction through cross-org policy evaluation to audit trail
- **Cross-org bilateral trust** — non-transitive, depth-bounded agreements between organizations without shared IAM

## Why not...

**...SPIFFE/SPIRE?** SPIFFE issues workload identities. ADTP issues *delegation chains*. SPIFFE tells you "this is Agent A." ADTP tells you "Agent A was authorized by Agent B, which was authorized by the platform root, with these specific capabilities, and none of them have been revoked." SPIFFE does not model capability attenuation or cascade revocation.

**...OAuth2 scopes?** OAuth2 scopes are string comparisons. ADTP's RESTRICT mode is a structural property — the code was tested against 7 adversarial escalation vectors with zero bypasses. OAuth2 also has no built-in cascade revocation across delegation chains.

**...a raw UCAN library?** UCAN gives you the token format. ADTP gives you the daemon: key management, chain verification, revocation tracking, cross-org trust, OIDC integration, and audit export. Using a UCAN library to build what ADTP does is like using `net/http` to build a web framework.

**...AIP (Agent Identity Protocol)?** AIP and ADTP solve the same problem. AIP uses Biscuit tokens with Datalog policies — more expressive, with framework adapters for CrewAI, ADK, and LangChain. ADTP makes different tradeoffs: RESTRICT mode is a structural invariant (not a policy you can misconfigure), and cascade revocation is provably complete (not a 15-minute CRL polling window). If your threat model requires proving that escalation is impossible by construction and that revocation has zero gap, ADTP is built for that. AIP compatibility is on the roadmap.

## Quickstart

```bash
git clone https://github.com/Zahanturel/adtp.git
cd adtp && make build
./adtpd --config config.yaml
# adtpd listening on 127.0.0.1:8080
# generated API key: <key>   <- copy this
```

Register an agent:
```bash
curl -H "Authorization: Bearer <api-key>" \
  -X POST localhost:8080/v1/agents \
  -d '{"sponsor_did":"did:key:z6Mk..."}'
```

Issue, delegate, verify, revoke:
```bash
# Issue a credential
curl -X POST localhost:8080/v1/credentials \
  -H "Authorization: Bearer <api-key>" \
  -d '{"issuer_did":"...","audience_did":"...","capabilities":[{"resource":"*","action":"read"}]}'

# Verify a chain
curl -X POST localhost:8080/v1/verify \
  -d '{"credential_cid":"bafy..."}'

# Revoke (cascades to all descendants)
curl -X POST localhost:8080/v1/revoke \
  -H "Authorization: Bearer <api-key>" \
  -d '{"credential_cid":"bafy..."}'
```

No external dependencies required — the default memory backend runs out of the box. For production, configure PostgreSQL in `config.yaml`.

## API

| Endpoint | Method | Description |
|---|---|---|
| `/v1/agents` | POST | Register a new agent identity |
| `/v1/agents/{did}` | GET | Look up an agent by DID |
| `/v1/credentials` | POST | Issue a UCAN credential |
| `/v1/delegations` | POST | Delegate capabilities to another agent |
| `/v1/verify` | POST | Verify a credential chain (13-step pipeline) |
| `/v1/revoke` | POST | Revoke a credential (cascade to all descendants) |
| `/v1/revocation/list` | GET | List all revoked credential CIDs |
| `/v1/status/{cid}` | GET | Check revocation status of a credential |
| `/health` | GET | Health check |

## Security

22 pre-release security findings identified and resolved. RESTRICT mode tested against 7 adversarial attack vectors — zero bypasses.

The protocol specification covers 13 adversary classes and 10 security properties: [PROTOCOL.md](docs/PROTOCOL.md).

## Integration

| Layer | Supported |
|---|---|
| Identity Provider | Entra, Okta, Auth0 via OIDC |
| Audit / SIEM | Datadog, Splunk, Elastic via webhook |
| Storage | In-memory (default), PostgreSQL |
| Runtime | Single static Go binary, ~15 MB |

ADTP exposes a REST API. Any agent framework with an HTTP client — MCP, A2A, LangGraph, CrewAI — can call it directly.

## Status

**v0.1.0-alpha** — core protocol implemented, tested, and audited.

- [x] Go daemon (12,600+ lines)
- [x] 13-step verification pipeline
- [x] RESTRICT mode with adversarial testing
- [x] Cascade revocation with completeness guarantee
- [x] OIDC integration
- [x] SIEM webhook export
- [ ] Python client SDK
- [ ] TypeScript client SDK
- [ ] MCP adapter
- [ ] Hosted infrastructure (Zerith Cloud)

## Building on Windows

The Makefile requires a Unix-compatible shell. Use Git Bash, WSL, or MSYS2. Alternatively:

```powershell
go build -o adtpd.exe ./cmd/adtpd
go test ./...
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All contributors must sign the [CLA](CLA.md).

## License

[Apache 2.0](LICENSE)
