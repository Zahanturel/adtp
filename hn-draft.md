# Show HN Draft — Submit Tuesday June 24, 5:30-7:30 PM IST

## Title
Show HN: ADTP – When you revoke an AI agent's access, its sub-agents keep running

## URL
https://github.com/Zahanturel/adtp

## Author Comment (post immediately after submitting)

If you're building with MCP or A2A, you've probably hit this: Agent A needs to call a tool, so you give it your API key. Agent A spawns Agent B. Agent B spawns Agent C. Now three agents have your credentials, there's no record of who authorized what, and when you revoke A, B and C keep running.

This isn't a hypothetical. It's what happens today in every agent orchestration framework I've looked at. The root cause: agents don't have their own identities, so they borrow yours.

ADTP is a Go daemon that fixes this. Each agent gets a `did:key` (Ed25519) identity. Capabilities are issued as signed UCAN chains. When you delegate, the delegation is cryptographically bound to both parties, scoped to specific actions, and time-limited.

Two properties I'm most proud of:

1. **RESTRICT mode** — a delegated credential can only narrow permissions, never widen them. This is enforced structurally (not policy checks). I tested against 7 escalation vectors. Zero bypasses.

2. **Cascade revocation** — revoke a credential and every descendant is provably dead. Not eventual consistency, not a background job. A storage-layer invariant guarantees completeness.

Single binary, zero runtime deps (memory backend), optional PostgreSQL for production. OIDC for Entra/Okta/Auth0. Apache 2.0.

For those tracking the space: AIP (Agent Identity Protocol) solves the same problem with Biscuit tokens and Datalog policies. ADTP makes different tradeoffs — structural invariants over policy expressiveness, provably-complete revocation over short-TTL tokens with CRL polling. The README has a detailed comparison.

This is v0.1.0-alpha. I'd love feedback on: the protocol design, ADTP vs AIP tradeoffs, and whether the "Why not SPIFFE/OAuth2" framing in the README lands.

---

## Pre-submission checklist
- [ ] Make 3-5 genuine comments on HN threads before Tuesday (build account history)
- [ ] Submit Tuesday June 24 between 5:30-7:30 PM IST (8-10 AM US Eastern)
- [ ] Post the author comment within 60 seconds of submission
- [ ] Stay online for 2-3 hours after posting to reply to every comment
