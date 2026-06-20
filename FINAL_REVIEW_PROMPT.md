# Final Pre-Release Review — ADTP

Paste this entire message into a fresh Claude Code session from the `C:\Users\Zenith\projects\adtp` directory.

---

You are conducting the final pre-release review of ADTP (Agent Delegation and Trust Protocol) before the v0.1.0-alpha tag is created and the repository goes public.

## Context

ADTP is a Go daemon that provides cryptographic identity (did:key/Ed25519), UCAN delegation chains, RESTRICT mode (structural escalation prevention), provably-complete cascade revocation, and cross-org bilateral trust for AI agents. Apache 2.0. Built by a solo founder under the company name Zerith (zerith.sh). The monetization thesis is hosted identity/delegation/revocation infrastructure for MCP/A2A agent platforms.

A prior audit session (the "Varro" audit) already ran through the codebase and made fixes. This review exists because **the auditor made mistakes** — a CSS grid was left broken after removing an element, and other oversights may exist. Trust nothing from the prior session. Verify everything yourself.

## Your mandate

Find every remaining issue that would cause a senior engineer at Anthropic, a16z crypto, or a Series A agentic AI startup to reject this project. Be adversarial. Assume the prior auditor was sloppy.

## Severity levels

- 🔴 FATAL — Security vulnerability, protocol correctness failure, or false claim. Blocks release.
- 🟠 CRITICAL — Major quality/trust issue. Fix before tagging.
- 🟡 IMPORTANT — Real issue, degrades trust. Fix before tagging if possible.
- 🔵 NOTE — Improvement opportunity. Track for post-release.
- ✅ CONFIRMED — Genuinely well-executed. Only if actually true.

## What to check — in this order

### 1. Build and test from scratch
```
go build ./...
go test ./...
go vet ./...
```
If any of these fail: 🔴. Do not proceed until green.

### 2. Site visual audit (site/index.html)
Open the site in a browser or preview. Look at every section with your own eyes:
- Is anything visually broken? Empty grid cells, overlapping text, missing fonts, wrong colors?
- Does the font (Geist) load correctly? Are heading weights correct?
- Mobile responsive — does it break at 640px?
- Does every claim on the site match what the code actually does?
- Does the positioning statement land? Read it as a developer seeing this for the first time.
- Check the Geist font CDN links — do they resolve? Are both sans and mono loading?

### 3. README accuracy
Read README.md end to end. For every claim:
- Trace it to working code. If you can't: 🔴.
- Run every command shown. If it fails: 🔴.
- Check the quickstart — does `make build` work? Does the binary start?
- Check integration table — are the listed integrations real?
- Check the Contributing section — does CLA.md exist and is it linked correctly?

### 4. Documentation files
- CLA.md — does it exist, is the legal language coherent?
- CONTRIBUTING.md — does it exist, does it reference the CLA, is the dev setup accurate?
- .github/cla.json — does it exist, does it point to CLA.md on main?
- SECURITY.md — does it exist? If not, should it before a public release?
- LICENSE — is it valid Apache 2.0?

### 5. Protocol correctness — the three properties that matter

**RESTRICT mode monotonicity:**
- Read `internal/credential/restrict.go` — what does CreateRestrictBlock enforce?
- Read `internal/verify/steps.go` — what does step2Linkage enforce?
- Can an attacker with a signing key forge a RestrictBlock that bypasses issuance-time checks? If so, does the verifier catch it?
- Read `internal/verify/adversarial_test.go` — do the 7 subtests actually prove what they claim?
- Run the adversarial tests: `go test ./internal/verify/... -v -run TestAdversarialRestrictBypass`

**Cascade revocation completeness:**
- Read the registration invariant in `internal/verify/steps.go` (step11).
- Read `store/postgres/store.go` Revoke method — advisory lock, sequence guard.
- Is there any path where a descendant survives ancestor revocation?

**Cross-org trust:**
- Read step9CrossOrg and the TrustPolicy implementation.
- Is trust transitive? (It must not be.)
- Race conditions in establishment?

### 6. Code quality sweep
- `golangci-lint run ./...` — does it pass clean?
- Search for `_ = ` patterns on error returns — are any of them hiding real failures?
- Search for `TODO`, `FIXME`, `HACK` — are any of them blocking?
- Any unchecked error returns that aren't deferred cleanup?
- Any `panic()` calls outside of init/test code?
- Any secrets, API keys, or credentials in the codebase?

### 7. CI/CD
Read `.github/workflows/ci.yml`:
- Does the test job run `go test -race`?
- Does the lint job use golangci-lint?
- Is there a postgres-integration job with a service container?
- Does the postgres job use `-tags integration`?
- Are secrets properly scoped (no hardcoded tokens)?

### 8. Dependency audit
- Read `go.mod` — are versions pinned?
- Any known CVEs in dependencies? Run `go install golang.org/x/vuln/cmd/govulncheck@latest && govulncheck ./...` if available.
- License compatibility — anything incompatible with Apache 2.0?

### 9. Postgres integration tests
- Read `store/postgres/integration_test.go`
- Do all method calls pass `ctx`? (The prior version had broken signatures — every call was missing ctx. Verify the fix.)
- Does `go vet -tags integration ./store/postgres/...` pass?
- Are there tests for: registration, credential storage, FindDescendants, revocation roundtrip, sequence guard, audit log, concurrent revocation, agents?

### 10. The connect-the-dots check
- Does the site say anything the code doesn't do?
- Does the README say anything the code doesn't do?
- Do the tests assert the right invariants for the protocol properties claimed?
- Is there a coherent story from code → docs → site → CI → license?
- Where does the story contradict itself?

## Reporting format

For each finding:
```
[SEVERITY] AREA — Title
File: path:line
Finding: What's wrong.
Impact: What breaks.
Fix: What to do.
```

At the end, produce:
1. **Verdict**: SHIP / SHIP WITH FIXES / DO NOT SHIP
2. **Blockers**: Numbered list of everything that must be fixed before tagging v0.1.0-alpha
3. **One honest paragraph**: Is this project ready for public scrutiny? Would you put your name on it?

## Hard rules
- File and line number on every finding. No exceptions.
- Do not trust the prior audit. Verify from first principles.
- If you find something genuinely excellent, say so. But only if it is.
- Run every command. Read every file. No sampling, no skimming.
- If RESTRICT mode has any bypass path: 🔴 FATAL, stop everything.
- If cascade revocation is incomplete: 🔴 FATAL, stop everything.
- Be harder than the last reviewer. That's why you're here.
