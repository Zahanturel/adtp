# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in ADTP, please report it responsibly.

**Email:** turelzahan10@gmail.com

**Do not** open a public GitHub issue for security vulnerabilities.

## What to include

- Description of the vulnerability
- Steps to reproduce
- Affected version(s) or commit hash
- Impact assessment (if known)

## Response timeline

- **Acknowledgement:** within 48 hours
- **Initial assessment:** within 7 days
- **Fix or mitigation:** depends on severity, targeting 30 days for critical issues

## Scope

In scope:
- The ADTP daemon (`adtpd`)
- Cryptographic operations (signing, verification, key generation)
- Credential issuance, delegation, and revocation logic
- HTTP API authentication and authorization
- The protocol specification (`docs/PROTOCOL.md`)

Out of scope:
- The landing page (`site/`)
- Third-party dependencies (report upstream; mention here if ADTP's usage is affected)

## Disclosure

We will coordinate disclosure with the reporter. Credit will be given unless anonymity is requested.
