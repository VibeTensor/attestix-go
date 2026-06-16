# Contributing to the Attestix Go verifier

Thanks for your interest. This is the Go port of the Attestix offline
verifier, part of the [Attestix](https://github.com/VibeTensor/attestix) project.

## Getting started

1. Fork and clone the repository.
2. Build and run the tests:

   ```
   go test ./...
   ```

## Conformance (required)

Every verifier port MUST reproduce the shared cross-language conformance vectors
from the core repo at
[`spec/verify/v1`](https://github.com/VibeTensor/attestix/tree/main/spec/verify/v1).
Run the conformance suite before opening a pull request: a change that diverges
from the shared `vectors.json` will not be accepted.

## Pull requests

- Branch from `main` and keep each PR focused.
- Use conventional commit messages (`fix:`, `feat:`, `docs:`, `test:`, `chore:`).
- Make sure the full test suite passes and add tests for new behaviour.
- Avoid unrelated formatting churn.

## Reporting issues

Open an issue with a minimal reproduction. For security issues, follow
[SECURITY.md](SECURITY.md) instead of filing a public issue.

## License

By contributing you agree that your contributions are licensed under the
Apache License 2.0, the same license as this repository.
