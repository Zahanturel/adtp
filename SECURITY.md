# Security Policy

ADTP implements cryptographic authorization primitives. Vulnerabilities in this codebase can result in privilege escalation or authorization bypass in systems that depend on it. Reports are taken seriously and handled promptly.

## Supported versions

| Version | Supported |
|---|---|
| `0.1.x-alpha` | Yes |
| `< 0.1.0` | No |

ADTP is pre-1.0 alpha software. The wire format and delegation semantics may change between minor versions. It is not yet recommended for production use where a compromise would be materially damaging.

## Reporting a vulnerability

**Do not open a public issue for security vulnerabilities.**

Use GitHub's private vulnerability reporting:
[Report a vulnerability](https://github.com/Zahanturel/adtp/security/advisories/new)

Or email **turelzahan10@gmail.com** with subject line `ADTP SECURITY`.

Please include:

- Affected version or commit SHA
- A description of the vulnerability and its impact
- Reproduction steps or a proof-of-concept
- Any suggested remediation

## Response targets

| Stage | Target |
|---|---|
| Acknowledgement of report | 48 hours |
| Initial assessment and severity triage | 7 days |
| Fix or documented mitigation | 30 days for high/critical |
| Public disclosure | After a fix ships, or 90 days, whichever is sooner |

Coordinated disclosure timelines are negotiable where a fix requires longer. Reporters are credited in the advisory and release notes unless they request otherwise.

## Scope

**In scope**
- The ADTP daemon (`adtpd`)
- Delegation chain validation, including chain-of-custody verification
- Ed25519 signature verification and key handling, including key generation
- RESTRICT mode enforcement — any path permitting attenuation to be bypassed or authority to be amplified
- Cascade revocation completeness — any descendant capability surviving revocation of an ancestor
- Credential issuance, delegation, and revocation logic
- Token parsing, canonicalization, and deserialization
- HTTP API authentication and authorization
- The protocol specification (`docs/PROTOCOL.md`)
- Replay, confused-deputy, and time-of-check/time-of-use conditions in the daemon

**Out of scope**
- Vulnerabilities in dependencies without a demonstrated exploit path through ADTP (report upstream; mention here if ADTP's usage is affected)
- Denial of service via resource exhaustion on unauthenticated endpoints where rate limiting is the deployer's responsibility
- Misconfiguration of a deploying system that ADTP does not control
- Attacks requiring prior compromise of the host or private key material

## Threat model

ADTP assumes:

- Private keys are held securely by their owners and are not exfiltrated
- The transport layer provides confidentiality where required (ADTP tokens are integrity-protected, not confidential)
- Clock skew between participants is bounded and roughly synchronized

ADTP does not assume that delegates are honest. Attenuation and revocation guarantees are intended to hold against a malicious delegate attempting to expand or retain authority.
