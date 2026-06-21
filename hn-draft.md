# Show HN Draft — Submit Tuesday June 24, 5:30-7:30 PM IST

## Title
Show HN: ADTP – Cryptographic identity and delegation chains for AI agents

## URL
https://github.com/Zahanturel/adtp

## Author Comment (post immediately after submitting)

I built ADTP because AI agents today share human credentials. When Agent A delegates to Agent B, there's no cryptographic record of what was authorized, to whom, and with what limits. When you revoke access, downstream agents keep running.

ADTP is a Go daemon that gives each agent its own did:key/Ed25519 identity and issues UCAN delegation chains. The part I'm most proud of technically:

**RESTRICT mode** — capability attenuation is enforced structurally, not with policy checks. A delegated credential can only narrow its parent's permissions, never widen them. I tested this against 7 adversarial escalation vectors (scope widening, depth bypass, RESTRICT removal, caveat stripping, cross-org escalation, replay injection, malformed caveats). Zero bypasses.

**Cascade revocation** — when you revoke a credential, a registration invariant guarantees every descendant is already dead. Not a background job, not eventual consistency. Mathematical completeness enforced at the storage layer.

The protocol spec covers 13 adversary classes and 10 security properties: https://github.com/Zahanturel/adtp/blob/main/docs/PROTOCOL.md

Single binary, no runtime deps (memory backend), optional PostgreSQL. OIDC integration for Entra/Okta/Auth0. Apache 2.0.

I'm aware of AIP (Agent Identity Protocol), which solves the same problem with Biscuit tokens and Datalog policies. ADTP makes different tradeoffs — structural invariants over policy expressiveness, and provably-complete revocation over short-TTL tokens with CRL polling. AIP compatibility is on the roadmap. The README has a detailed comparison.

This is v0.1.0-alpha. I'd particularly appreciate feedback on the protocol design, the ADTP vs AIP tradeoffs, and the "Why not SPIFFE/OAuth2" framing in the README.

Happy to answer questions about the implementation.

---

## Pre-submission checklist
- [ ] Make 3-5 genuine comments on HN threads before Tuesday (build account history)
- [ ] Submit Tuesday June 24 between 5:30-7:30 PM IST (8-10 AM US Eastern)
- [ ] Post the author comment within 60 seconds of submission
- [ ] Stay online for 2-3 hours after posting to reply to every comment
