# Contributing to PolicyBridge

Thank you for your interest in contributing.

## Development setup

1. Install Go 1.24+
2. Clone the repository
3. Run `make mod` to download dependencies
4. Run `make dev` to start the development server
5. Open http://127.0.0.1:8080

## Testing

```bash
make test          # All Go tests
make test-integration  # API integration tests
```

Tests must not require access to a live NSX Manager. Use fixtures from
`testdata/nsx/` or the mocked NSX server in `internal/fixtures/`.

## Code style

- Run `make fmt` before committing
- Run `make lint` to check for issues
- Follow existing patterns in the codebase
- Do not reimplement NP-Guard analysis algorithms

## Pull requests

1. Create a feature branch from `main`
2. Make your changes with tests
3. Ensure `make test` passes
4. Submit a pull request with a clear description

## Reporting issues

Please include:
- PolicyBridge version
- Steps to reproduce
- Expected vs actual behaviour
- Relevant log output (redact credentials)

Do not include NSX credentials or raw configuration dumps in issue reports.
