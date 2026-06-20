# GitHub Discoverability — Complete Execution Brief

You are working on the GitHub repository `Zahanturel/adtp`. Your job is to make this repository maximally discoverable and convertible on GitHub. Every task below must be completed. Do not skip any.

## Project Context

**ADTP** (Agent Delegation and Trust Protocol) is a Go daemon that provides cryptographic identity, delegation chains, and provably-complete revocation for AI agents. Built by Zahan Turel, solo founder of Zerith. Apache 2.0. v0.1.0-alpha shipped.

**What it does:**
- `did:key` / Ed25519 identity per AI agent (no shared credentials, no service accounts)
- UCAN delegation chains with RESTRICT mode (structural escalation prevention — not a policy check, a mathematical invariant)
- Provably-complete cascade revocation (a registration invariant guarantees every descendant is revoked — not best-effort, not eventually consistent)
- Cross-org bilateral trust (non-transitive, depth-bounded agreements between organizations)
- 13-step credential chain verification pipeline
- OIDC integration (Entra, Okta, Auth0), SIEM webhook export (Datadog, Splunk, Elastic)

**What makes it defensible:**
- RESTRICT mode was audited with 7 adversarial attack vectors. Zero bypasses. Escalation requires forging an Ed25519 signature or a SHA-256 collision. No semantic comparison in the trusted computing base.
- Cascade revocation completeness derives from a registration invariant proven through the implementation.
- The protocol specification (docs/PROTOCOL.md) is 512+ lines covering 23 sections, 13 adversary classes, and 10 security properties. This is RFC-grade documentation for a v0.1.0-alpha.

**Codebase stats:**
- Go daemon: 12,600+ lines across 78 .go files
- Test files: 40+ test files including adversarial tests, integration tests, e2e tests
- Dependencies: minimal (pgx for Postgres, yaml.v3 for config — that's it)
- CI: tests pass, lint passes, Postgres integration tests pass
- 22-finding security audit: all findings resolved

**Current state:**
- Landing page live at https://zahanturel.github.io/adtp/ (dark theme, interactive delegation chain demo, 13-step pipeline visualization)
- v0.1.0-alpha tag exists
- No external users yet
- No Python/TypeScript SDKs yet
- No MCP adapter yet (the claim "Compatible with MCP via REST API" is HTTP compatibility, not a real MCP integration)

**Branding:**
- Company: Zerith
- Colors: background #09090B, accent green #6BCB8B, text #FAFAFA, muted #A1A1AA, dim #71717A, card bg #18181B, border #27272A
- Fonts: Geist (sans) and Geist Mono
- Design language: dark, minimal, infrastructure-grade. Same visual tier as Linear, Vercel, Tailscale, Resend.
- Logo: stylized "Z" mark (two horizontal bars with a diagonal slash)

---

## Task 1: Repository Description

Set the GitHub repo description (the "About" one-liner) to exactly:

```
Cryptographic identity, delegation chains, and provably-complete revocation for AI agents. Go daemon. Apache 2.0.
```

This is 103 characters. It hits the three key capabilities, the runtime, and the license in one line. It's what appears in GitHub search results and when the repo is shared.

Set this via `gh repo edit Zahanturel/adtp --description "Cryptographic identity, delegation chains, and provably-complete revocation for AI agents. Go daemon. Apache 2.0."`

---

## Task 2: Homepage URL

Set the homepage URL to: `https://zahanturel.github.io/adtp/`

`gh repo edit Zahanturel/adtp --homepage "https://zahanturel.github.io/adtp/"`

---

## Task 3: Repository Topics

Set these topics (order matters for display):

```
ai-agents, agent-security, delegation, ucan, did, identity, trust, cryptography, revocation, golang, mcp, a2a, zero-trust, ed25519, cross-org
```

Why these specific topics:
- `ai-agents` — primary discovery term for anyone searching for agent tooling
- `agent-security` — the security-specific search term
- `delegation` — the core operation
- `ucan` — the credential standard ADTP is built on (anyone searching UCAN finds this)
- `did` — decentralized identifiers (W3C standard community searches this)
- `identity` — broad but high-traffic
- `trust` — core concept
- `cryptography` — signals technical seriousness
- `revocation` — unique differentiator (almost no repos have this topic)
- `golang` — language discovery
- `mcp` — Model Context Protocol (Anthropic ecosystem — high-value discovery)
- `a2a` — Agent-to-Agent protocol (Google ecosystem)
- `zero-trust` — enterprise security keyword
- `ed25519` — specific crypto primitive (niche but high-intent searchers)
- `cross-org` — unique to ADTP's cross-organizational trust feature

Set via: `gh repo edit Zahanturel/adtp --add-topic ai-agents --add-topic agent-security --add-topic delegation --add-topic ucan --add-topic did --add-topic identity --add-topic trust --add-topic cryptography --add-topic revocation --add-topic golang --add-topic mcp --add-topic a2a --add-topic zero-trust --add-topic ed25519 --add-topic cross-org`

---

## Task 4: Social Preview Image

Create a social preview image (1280x640px) that matches the dark branding. This image appears when the repo is shared on Twitter/X, Slack, HN, Discord, LinkedIn — anywhere an Open Graph image is rendered.

**Design spec:**
- Background: #09090B (the site's bg color)
- A subtle radial gradient at center: rgba(107, 203, 139, 0.06) fading to transparent (matching the hero's glow)
- The Zerith "Z" mark centered-left or top-center, rendered in #6BCB8B, roughly 80x80px
  - The Z mark SVG paths: `<rect x="0" y="0" width="100" height="5" rx="0.5"/>` + `<polygon points="78,5 100,5 22,91 0,91"/>` + `<rect x="0" y="91" width="100" height="9" rx="0.5"/>`
- Below the mark: "Zerith" in Geist sans, 500 weight, #FAFAFA, ~36px
- Main text: "Identity infrastructure for AI agents" in Geist sans, 600 weight, #FAFAFA, ~56px, centered, with line-height 1.15
- Subtitle: "Cryptographic delegation chains. Provably-complete revocation. Open protocol." in Geist sans, 400 weight, #A1A1AA, ~20px
- Bottom-left corner: "github.com/Zahanturel/adtp" in Geist Mono, #71717A, ~14px
- Bottom-right corner: "Apache 2.0" in Geist Mono, #71717A, ~14px
- Optional: very faint border line at top and bottom (1px, #27272A)

**Important:** The image must render well at small sizes (it often appears as a thumbnail). The main text "Identity infrastructure for AI agents" must be readable even at 400px wide.

Create this as an HTML file that can be screenshotted at 1280x640, or as an SVG that can be exported. Save it as `site/social-preview.png` (or provide the source file and instructions to export).

After creating the image, it must be uploaded via GitHub UI: Repository Settings > Social preview > Edit > Upload. This cannot be done via CLI — it requires browser interaction. If you can do this via browser automation, do it. If not, create the image file and instruct the user to upload it manually at https://github.com/Zahanturel/adtp/settings.

---

## Task 5: Release Notes for v0.1.0-alpha

The v0.1.0-alpha tag exists but may not have GitHub Release notes. Check with:

```
gh release view v0.1.0-alpha 2>/dev/null || echo "No release exists"
```

If no release exists, create one:

```
gh release create v0.1.0-alpha --title "v0.1.0-alpha" --notes "$(cat <<'NOTES'
## ADTP v0.1.0-alpha — First public release

The Agent Delegation and Trust Protocol. Cryptographic identity, delegation chains, and provably-complete revocation for AI agents.

### What's included

**Core protocol**
- `did:key` / Ed25519 agent identity (no shared credentials)
- UCAN credential issuance with full delegation chains
- RESTRICT mode: structural escalation prevention (monotone caveats, no semantic comparison in the TCB)
- 13-step credential chain verification pipeline
- Provably-complete cascade revocation via registration invariant
- Cross-organizational bilateral trust (non-transitive, depth-bounded)

**Infrastructure**
- Go daemon, single static binary
- Memory backend (zero dependencies) or PostgreSQL
- HTTP API with bearer token authentication
- OIDC integration (Entra, Okta, Auth0)
- SIEM webhook export (Datadog, Splunk, Elastic)
- 64 KB request body limit

**Security**
- 22-finding security audit: all findings resolved
- 7 adversarial attack vectors tested against RESTRICT mode: zero bypasses
- Adversarial test suite included (`internal/verify/adversarial_test.go`)

**Protocol specification**
- [PROTOCOL.md](docs/PROTOCOL.md): 512+ lines, 23 sections, 13 adversary classes, 10 security properties
- Canonical signing discipline (SD-1 through SD-7)
- Explicit threat model with named attacks and controls

### What's not included (yet)
- Python client SDK
- TypeScript client SDK
- Native MCP adapter
- Hosted option (Zerith Cloud)

### Get started
```bash
git clone https://github.com/Zahanturel/adtp.git
cd adtp && make build
./adtpd --config config.yaml
```

Full documentation: https://zahanturel.github.io/adtp/
NOTES
)"
```

If a release already exists but has minimal notes, delete and recreate it, or edit it with `gh release edit`.

---

## Task 6: README Restructure

This is the most important task. The README is what converts a GitHub visitor into someone who clones the repo.

Read the current README.md, then **rewrite it completely** with this structure. Every section below is mandatory. The tone is: confident, specific, honest, technical. No marketing fluff. No buzzwords. Write like you're explaining the project to a senior distributed systems engineer who has 60 seconds before they close the tab.

### README Structure

```markdown
# ADTP — Agent Delegation and Trust Protocol

> Cryptographic identity, delegation chains, and provably-complete revocation
> for AI agents. Single binary. Apache 2.0.

---

## The problem

AI agents are accumulating authority without accountability.

They inherit human credentials. When Agent A delegates to Agent B, no existing
system records that delegation cryptographically or enforces what B is allowed
to do. When you revoke A's access, B keeps working — silently, indefinitely.

Enterprise agent governance today means vendor-scoped controls: Microsoft
governs Microsoft agents, Google governs Google agents. The cross-platform,
cross-organization case — where the hardest security problems live — has
no solution.

## What ADTP does

ADTP is a Go daemon that gives every AI agent its own cryptographic identity
and manages delegation, verification, and revocation as a protocol — not a
policy layer.

| Capability | How it works |
|---|---|
| **Agent identity** | Every agent gets a `did:key` derived from an Ed25519 keypair. No shared credentials. No service accounts. Each agent signs its own operations. |
| **Delegation chains** | When Agent A delegates to Agent B, ADTP issues a UCAN credential encoding who delegated, to whom, what capabilities, under what constraints. The chain is cryptographically linked and independently verifiable. |
| **RESTRICT mode** | Structural escalation prevention. A child credential can only narrow its parent's permissions — never widen them. This is not a policy check. It is an invariant enforced at issuance. Escalation requires forging an Ed25519 signature or a SHA-256 collision. |
| **Cascade revocation** | Revoke one credential and a registration invariant guarantees every descendant is also revoked. Not a background job. Not eventual consistency. Provably complete. |
| **Cross-org trust** | Bilateral agreements between organizations. Non-transitive, depth-bounded. Org A's agents interact with Org B's agents under auditable policy — without exposing either side's internal IAM. |
| **13-step verification** | Every credential chain passes through 13 verification steps before a single action is authorized — from structural validation to proof-of-possession to audit trail. |

## What makes ADTP different

| | ADTP | SPIFFE/SPIRE | Raw UCAN library | Platform IAM (Entra/Okta) |
|---|---|---|---|---|
| Agent-specific identity | did:key per agent | Workload identity (not agent-scoped) | Manual | Human-centric |
| Delegation chains | Full UCAN chains with RESTRICT | Not a delegation protocol | Chains, no escalation prevention | Scoped to single vendor |
| Escalation prevention | Structural (RESTRICT mode) | N/A | Application-level | Policy-based |
| Cascade revocation | Provably complete | CRL/OCSP | Not included | Vendor-scoped |
| Cross-org trust | Bilateral, non-transitive | Federation (transitive) | Not included | Vendor federation |
| Protocol specification | 512+ lines, 23 sections | SPIFFE spec | UCAN spec | Proprietary |

## Quickstart

```bash
# Clone and build
git clone https://github.com/Zahanturel/adtp.git
cd adtp && make build

# Run the daemon
./adtpd --config config.yaml
# → adtpd listening on 127.0.0.1:8080
# → generated API key: abc123...  ← copy this

# Register an agent
curl -H "Authorization: Bearer <api-key>" \
  -X POST localhost:8080/v1/agents \
  -d '{"sponsor_did":"did:key:z6Mk..."}'
```

> **Building on Windows?** Use Git Bash, WSL, or MSYS2. Or run directly:
> `go build -o adtpd.exe ./cmd/adtpd`

## Integration

| Layer | Supported |
|---|---|
| Identity provider | Entra, Okta, Auth0 via OIDC |
| Audit / SIEM | Datadog, Splunk, Elastic via webhook |
| Storage | Memory (zero dependencies) or PostgreSQL |
| API | REST over HTTP. Compatible with any agent framework. |

## Proof

This is not a weekend project.

- **Codebase:** 12,600+ lines of Go across 78 files
- **Protocol spec:** [PROTOCOL.md](docs/PROTOCOL.md) — 512+ lines, 23 sections,
  13 adversary classes, 10 security properties
- **Security audit:** 22 findings identified and resolved
  ([commit](https://github.com/Zahanturel/adtp/commit/7f45b0a))
- **Adversarial tests:** 7 attack vectors against RESTRICT mode — zero bypasses
  ([adversarial_test.go](internal/verify/adversarial_test.go))
- **CI:** Unit tests, integration tests, Postgres integration, lint — all passing

## Technical details

- Go daemon, single static binary (~15 MB). No runtime dependencies with
  the memory backend.
- Ed25519 signatures. Post-quantum migration path planned (ML-DSA-65).
- RESTRICT mode: monotone caveat blocks. No semantic capability comparison
  in the trusted computing base.
- CIDv1 content addressing (raw codec, SHA-256) for chain linkage.
- Apache 2.0 open source.

## Status

**Shipped (v0.1.0-alpha):**
- [x] Go daemon with full protocol implementation
- [x] Memory and PostgreSQL storage backends
- [x] OIDC integration
- [x] SIEM webhook export
- [x] 13-step verification pipeline
- [x] Cascade revocation
- [x] Cross-org bilateral trust
- [x] Adversarial test suite

**Roadmap:**
- [ ] Python client SDK
- [ ] TypeScript client SDK
- [ ] Native MCP adapter
- [ ] Zerith Cloud (hosted infrastructure)

## Links

- [Landing page](https://zahanturel.github.io/adtp/) — project home and
  interactive protocol demo
- [Protocol specification](docs/PROTOCOL.md) — full v0.3 spec
- [Security policy](SECURITY.md) — vulnerability reporting

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All contributors sign the
[CLA](CLA.md) — CLA Assistant prompts on first PR.

## License

[Apache 2.0](LICENSE)
```

### README Guidelines:
- Do NOT include the "Compatible with MCP, A2A, LangGraph, and CrewAI via REST API" claim. MCP/A2A adapters don't exist yet. Say "REST over HTTP. Compatible with any agent framework." — this is honest.
- The comparison table against SPIFFE/SPIRE, raw UCAN, and platform IAM is critical. It answers the "why not just use X?" question that every experienced developer will have.
- The "Proof" section is new and essential. It surfaces the technical credibility that's hidden in the codebase. Link to the actual adversarial test file and the audit fix commit.
- Keep the Windows build note but make it a blockquote, not a full section.
- The "Status" section with checkboxes shows what's done and what's coming. The checked boxes list is social proof — it shows volume of work completed.

---

## Task 7: Clean Up Stale Files

There is an old `index.html` at the repository root (the parchment-themed version of the landing page). The real site lives at `site/index.html`. The root-level file is untracked and confusing.

Check if it exists: `test -f index.html && echo "exists"`

If it does: it should be added to `.gitignore` or deleted. Since it's untracked, deleting it is safe. But ask the user before deleting any file.

Also check for other stale untracked files:
- `claude.md` at the repo root (this is the audit prompt — should not be committed)
- `FINAL_REVIEW_PROMPT.md` at the repo root (same)
- `.claude/` directory

These are working files, not project files. They should be in `.gitignore` if they aren't already.

---

## Task 8: .gitignore Update

Check if `.gitignore` exists and whether it covers:
```
# Working files
claude.md
FINAL_REVIEW_PROMPT.md
GITHUB_DISCOVERABILITY_PROMPT.md
.claude/

# Build artifacts
adtpd
adtpd.exe
*.out
```

If `.gitignore` doesn't exist or is missing these entries, create or update it.

---

## Task 9: GitHub Issue Templates (Optional but High-Value)

Create `.github/ISSUE_TEMPLATE/` with two templates:

**Bug report** (`.github/ISSUE_TEMPLATE/bug_report.md`):
```markdown
---
name: Bug report
about: Report a bug in the ADTP daemon or protocol implementation
title: ''
labels: bug
assignees: ''
---

**Describe the bug**
A clear description of what the bug is.

**To reproduce**
Steps to reproduce the behavior.

**Expected behavior**
What you expected to happen.

**Environment**
- OS:
- Go version:
- ADTP version/commit:
- Storage backend: memory / postgres
```

**Feature request** (`.github/ISSUE_TEMPLATE/feature_request.md`):
```markdown
---
name: Feature request
about: Suggest a feature or improvement
title: ''
labels: enhancement
assignees: ''
---

**Problem**
What problem does this solve?

**Proposed solution**
How should it work?

**Alternatives considered**
What else did you consider?
```

---

## Execution Order

1. Set repo description and homepage (Tasks 1-2) — 1 minute
2. Set topics (Task 3) — 1 minute
3. Create social preview image (Task 4) — 15-30 minutes
4. Create/update release notes (Task 5) — 5 minutes
5. Restructure README (Task 6) — 30-45 minutes
6. Clean up stale files and .gitignore (Tasks 7-8) — 5 minutes
7. Issue templates (Task 9) — 5 minutes
8. Commit all file changes with message: `feat: GitHub discoverability — README restructure, social preview, issue templates`

Total estimated time: ~1-1.5 hours.

---

## Quality Check

After completing all tasks, verify:

1. Visit https://github.com/Zahanturel/adtp — does the description show? Are topics visible? Is the homepage linked?
2. Share the repo URL in a test message — does the social preview image render correctly?
3. Read the README cold, as a senior engineer who has never heard of ADTP. Does the problem land in the first 10 seconds? Do you understand what it does by the 30 second mark? Can you find the quickstart in under 5 seconds? Does the comparison table answer "why not SPIFFE?"
4. Click every link in the README — do they all resolve?
5. Check the release page — are the notes complete and well-formatted?

If any of these fail, fix before committing.
