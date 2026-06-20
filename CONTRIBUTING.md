# Contributing to ADTP

Contributions are welcome. Before submitting a pull request, please review the following.

## Contributor License Agreement

All contributors must sign the [Contributor License Agreement](CLA.md) before their
contributions can be merged. CLA signing is automated: CLA Assistant will prompt you
with a comment on your first pull request. Simply reply with the requested confirmation
to sign.

## Development

```bash
go build ./...
go test ./...
go vet ./...
```

## Pull requests

- One logical change per PR.
- Include tests for new functionality.
- Run `go test ./...` and `go vet ./...` before submitting.
- CI must pass (unit tests, lint, postgres integration).
