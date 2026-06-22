# Contributing to ADTP

Contributions are welcome. Before submitting a pull request, please review the following.

## Contributor License Agreement

All contributors must sign the [Contributor License Agreement](CLA.md) before their contributions can be merged. CLA signing is automated: CLA Assistant will prompt you with a comment on your first pull request. Simply reply with the requested confirmation to sign.

## Setup

```bash
git clone https://github.com/Zahanturel/adtp.git
cd adtp
make build        # builds ./adtpd
make test         # runs unit tests (in-memory backend)
make vet          # static analysis
```

Requires Go 1.22+ (for method+path routing in `net/http`).

## Running the daemon locally

```bash
./adtpd --config config.yaml
# Generates a platform key and API key on first run
```

## Test suites

| Command | What it runs |
|---|---|
| `make test` | Unit tests (in-memory backend, fast) |
| `go test -tags e2e ./test/e2e/...` | End-to-end scenarios (starts httptest server) |
| `go test -tags integration ./store/postgres/...` | PostgreSQL integration (needs `ADTP_TEST_POSTGRES_DSN`) |
| `go test -fuzz=FuzzParseUCAN ./internal/credential/...` | Fuzz testing (parsers, JCS) |

## Pull requests

- One logical change per PR.
- Include tests for new functionality.
- Run `go test ./...` and `go vet ./...` before submitting.
- CI must pass: unit tests, lint (`golangci-lint`), and E2E.
- For protocol changes, update [PROTOCOL.md](docs/PROTOCOL.md) and [CAPABILITIES.md](CAPABILITIES.md).

## Good first issues

If you're looking for a place to start:

- Add fuzz test corpus entries for edge cases you discover
- Improve error messages in the verification pipeline
- Add integration examples for MCP or A2A frameworks
- Expand the E2E test suite with new adversarial scenarios

## Architecture overview

```
cmd/adtpd/          CLI entrypoint, flag parsing, server lifecycle
api/v1/             HTTP handlers, routing, middleware
config/             YAML + env config loading and validation
internal/
  identity/         did:key generation and Ed25519 key management
  credential/       UCAN parsing, capability model, RESTRICT blocks
  delegation/       Delegation chain construction
  verify/           13-step verification pipeline
  revocation/       Cascade revocation, registration index, reconciliation
  signing/          JCS canonicalization, canonical signing discipline
  audit/            Audit log interface
  siem/             SIEM webhook export (Datadog, Splunk, Elastic)
  lifecycle/        Agent state machine
store/              Storage interface
  memory/           In-memory backend (dev/test)
  postgres/         PostgreSQL backend (production)
pkg/adtp/           Public API types (request/response structs)
test/e2e/           End-to-end test scenarios
site/               Landing page (zerith.sh)
```

## Security

If you discover a security vulnerability, please report it privately via GitHub Security Advisories rather than opening a public issue.
