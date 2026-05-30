// Package attestix is an offline verifier for credentials and delegations
// issued by the Attestix Python core (https://github.com/VibeTensor/attestix).
//
// It verifies, with no Python runtime and no network, the three artefact types
// Attestix produces:
//
//   - W3C Verifiable Credentials with Ed25519 proofs (VerifyCredential)
//   - did:key Ed25519 identities (DecodeDidKey)
//   - UCAN delegation chains as EdDSA JWTs (VerifyDelegationChain)
//
// The crux is the canonical form. Attestix signs over a JCS-STYLE
// canonicalization that is deliberately NOT strict RFC 8785: it applies Unicode
// NFC normalization to every string value and object key, sorts keys by code
// point, emits raw UTF-8 (no \uXXXX escapes), collapses whole-number floats to
// integers, and preserves integers at arbitrary precision. Canonicalize
// reproduces that form byte-for-byte; the package is validated against the
// shared cross-language conformance vectors (testdata/vectors.json).
package attestix
