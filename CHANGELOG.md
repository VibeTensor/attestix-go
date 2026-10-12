# Changelog

## [0.4.2] - 2026-10-12

Includes the verification fixes merged after v0.4.1.

### Verification

- Resolve document keys from the signed issuer; reject conflicting or malformed
  verification-method metadata in document-resolution mode.
- Reject malformed present expiry values, invalid pinned key lengths, trailing
  JSON content, normalized-key collisions, and unsupported float magnitudes.
- Update golang.org/x/text to 0.41.0 and require Go 1.25 or later.

### Documentation

- Explain pinned-key trust, offline revocation limits, canonical number limits,
  and the different guarantees of token, pair, and recursive delegation APIs.
- Replace an old-tag installation example with explicit reviewed-version
  selection and document the current development checks.
