# Session handoff — 2026-08-15

Working state of `github.com/Zahanturel/adtp` at the end of the v0.2.0 release session.
Delete this file once it has been read; it is a note to the next session, not documentation.

## Where things stand

`main` is at `954c22e`, working tree clean, everything pushed. **v0.2.0 is tagged and
released** with six platform binaries and `checksums.txt`. All five CI jobs green on the
tagged commit and on every commit since, including `postgres-integration` — the only place
the PostgreSQL key store has ever executed.

Nothing is in flight. Nothing is waiting on a decision.

## Standing rules from this session

1. **Never post anything on the user's behalf** — GitHub comments, issues, PRs, emails,
   anywhere — unless they explicitly say so in that message. Draft it, hand it over, stop.
   They post it themselves. This was stated as a standing rule, not a one-off.
2. **A new test must be observed to fail against the unfixed code before its passing run
   means anything.** Recorded as F19 in SECURITY_AUDIT.md after a fix shipped with a test
   that passed against the broken version. It is also in the CONTRIBUTING.md PR checklist.
3. **A claim about *why* something works must name the code path that makes it work**, and
   say what would have to be true for a competing explanation to be the real one. Recorded
   as F20 after the same error produced three wrong public claims.
4. When comparing this project to another system, **read and quote that system's spec**.
   Characterising it from memory is how F20 instance 3 survived into a released README and
   into a standards-body thread.

## What v0.2.0 changed

Five phases of an audit response. In commit order:

- `489b175` — F14 (HIGH): delegation depth was bypassable *downward*. `dl` was bounded above
  but not below, so a credential at `dl=0` could mint a working child at `dl=-1` and keep
  going. Fixed at parser and verifier.
- `782031c` — F15 (MEDIUM): SD-6 unimplemented for RESTRICT blocks; one credential admitted
  unboundedly many CIDs.
- `d06b0b7` — F16/F17/F18: seven control-plane defects (http JWKS, RSA key size, JWKS lock
  held across fetch, JCS surrogates, chain-array truncation, wildcard resource, self-minted
  proof of possession), plus two more issuance-only invariants found by sweeping every
  `Create*`/`Parse*` pair.
- `fae8d25` — **breaking**: added `action_restrict`, removed RESTATE (770 lines deleted).
- `b69ff0f` — repositioned the docs on transitive revocation; added Prior art; cut
  PROTOCOL.md into Part I (implemented) and Appendix A (roadmap).
- `a616e0e` — CLA replaced with a DCO sign-off.
- `d588f59` — Go 1.26.6 for five stdlib advisories.
- `1cbe8bf` — corrected the transitive-revocation claim; recorded F20.
- `954c22e` — CI now runs weekly so `vulncheck` fires without a push.

## Automation, all self-running

| What | Trigger |
|---|---|
| CI (test, e2e, lint, vulncheck, postgres-integration) | push to `main`, any PR, **weekly Tue 04:00 UTC**, manual dispatch |
| CodeQL | push/PR to `main`, weekly Mon 03:00 UTC |
| Dependabot (gomod + actions) | weekly Monday, grouped, max 5 PRs |
| Release (goreleaser) | any `v*` tag push |

The weekly CI schedule exists because stdlib advisories appear against a pinned Go version
without anything in the repo changing. Expect Dependabot PRs on Mondays; they need review and
merge, which is the one recurring manual task.

## Open, deliberately

- **F17 — the control plane has authentication but no authorization.** Any valid API key can
  revoke as platform authority, verify as any agent whose key the daemon holds, and walk the
  whole store. Documented unsoftened in README Status. **Tracked for v0.3 and it is the
  largest single gap.**
- F2–F9 remain open and are listed in SECURITY_AUDIT.md with reasons.
- Three "benign asymmetries" in F16 are **recorded rather than fixed**, on purpose: they are
  claims about the current call graph, not about the code, and they expire silently if the
  verification steps change. Written down, they get re-checked.
- Metering is unimplemented; `budget`, `max_calls` and `parameter_schema` always deny.
- Cross-org trust is unreachable from configuration; step 9 is a no-op.

## The UCAN thread

`ucan-wg/spec` issue #199. The user posted a correction of their own earlier claims there on
2026-08-15. Editor is Brooklyn Zelenka (`expede`) — sole editor of both the UCAN spec and the
Revocation spec, ex-Ethereum core dev, deep PLT background, patient and precise. She corrects
imprecision immediately and generously.

Two things established while researching it, both load-bearing:

- The [UCAN Revocation spec](https://ucan.xyz/revocation/) deliberately does **not** guarantee
  that revoking a proof stops an agent from using a capability, because the agent may hold a
  second unrevoked chain. This project has the same limitation. Do not claim otherwise.
- Closing it requires confinement, which needs every process online. It is a known
  impossibility, not an open problem. Do not propose a fix for it.

If the user ever wants to contribute there, `ucan-wg/revocation` issue **#3** ("How can an
issuer revoke someone else's delegation?", filed by Peeja 2026-05-18) has had no reply in
three months and is adjacent to real work here — but ADTP's own authority model is
authenticated and not authorized (F9), so bring the reasoning, not the implementation. And
per rule 1, draft only.

## Environment

- Go is at `C:\Program Files\Go\bin`, **not on the tool shell PATH** — export it first.
  `-race` needs cgo, which is unavailable here.
- Working copy is CRLF, repo is LF. Python scripts that read with `newline=''` will fail to
  match `\n` patterns; read in text mode and write with `newline='\n'`.
- `golangci-lint` v2.12.2 is at `~/go/bin`.
- Full local gate:
  `go build ./... && go test ./... && go test -tags e2e ./test/e2e/... && golangci-lint run ./...`
