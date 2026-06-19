# ADTP — Agent Delegation and Trust Protocol

> Cryptographic identity, delegation chains, and provably-complete revocation for AI agents.
> Single binary. Apache 2.0. Built by [Zerith](https://zerith.sh).

---

## The problem

AI agents share human credentials. Delegation chains are invisible. Revocation is best-effort.

When something goes wrong — and it will — there is no cryptographic record of who authorized what, to which agent, and what it was allowed to do.

## What ADTP does

- **did:key identity** per agent — no shared credentials, no service accounts
- **UCAN credential issuance** — every delegation is cryptographically signed
- **RESTRICT mode** — structural escalation prevention; no descendant can exceed ancestor permissions
- **13-step chain verification** — from structural validity to cross-org policy evaluation
- **Provably-complete cascade revocation** — a registration invariant guarantees every descendant is revoked *(patent pending)*
- **Cross-org bilateral trust** — non-transitive, depth-bounded agreements between organizations

## Quickstart

```bash
git clone https://github.com/Zahanturel/adtp.git
cd adtp && make build
./adtpd --config config.yaml
# → adtpd listening on 127.0.0.1:8080

# Register an agent
curl -H "Authorization: Bearer <api-key>" \
  -X POST localhost:8080/v1/agents \
  -d '{"sponsor_did":"did:key:z6Mk..."}'
```

## Integration

| Layer | Supported |
|---|---|
| Identity Provider | Entra, Okta, Auth0 via OIDC |
| SIEM / Audit | Datadog, Splunk, Elastic via webhook |
| Agent Platforms | MCP, A2A, LangGraph, CrewAI |

## Technical highlights

- Go daemon, single static binary. No runtime dependencies.
- Ed25519 signatures, post-quantum migration path to ML-DSA-65.
- RESTRICT mode: structural escalation prevention. No semantic comparison in the TCB.
- Thirteen-step credential chain verification.
- Apache 2.0 open source.

## Status

- [x] Go daemon (12,600+ lines)
- [x] India provisional patent filed (June 2026)
- [x] US provisional in progress
- [ ] Python client SDK
- [ ] TypeScript client SDK
- [ ] Hosted option

## Links

- [Zerith](https://zerith.sh) — project home
- [Landing page](https://zahanturel.github.io/adtp/)

## License

[Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0)
