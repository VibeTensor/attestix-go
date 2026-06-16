# attestix-go

[![test](https://github.com/VibeTensor/attestix-go/actions/workflows/test.yml/badge.svg)](https://github.com/VibeTensor/attestix-go/actions/workflows/test.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/VibeTensor/attestix-go.svg)](https://pkg.go.dev/github.com/VibeTensor/attestix-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/VibeTensor/attestix-go)](https://goreportcard.com/report/github.com/VibeTensor/attestix-go)

Offline verifier (pure Go, no Python runtime, no network) for credentials
and delegations issued by the [Attestix](https://github.com/VibeTensor/attestix)
Python core. Verify Ed25519 W3C Verifiable Credentials, `did:key` identities, and
UCAN delegation chains anywhere Go runs: agent runtimes, MCP servers, Kubernetes
admission controllers, CLIs.

This port is validated, byte-for-byte, against the shared cross-language
conformance vectors (`spec/verify/v1/vectors.json` in the core repo, vendored
here as [`testdata/vectors.json`](testdata/vectors.json)). All vectors pass.

## Install

```sh
go get github.com/VibeTensor/attestix-go@v0.4.0
```

```go
import attestix "github.com/VibeTensor/attestix-go"
```

## Verify a credential (10 lines)

```go
package main

import (
	"fmt"
	"os"

	attestix "github.com/VibeTensor/attestix-go"
)

func main() {
	vc, _ := os.ReadFile("credential.json")        // a VC issued by Attestix
	res, err := attestix.VerifyCredential(vc)        // resolves the issuer did:key, checks Ed25519 + expiry + revocation
	if err != nil {
		panic(err)
	}
	fmt.Printf("valid=%v  signature=%v  expired=%v  revoked=%v\n",
		res.Verify(), res.SignatureValid, !res.NotExpired, !res.NotRevoked)
}
```

`Verify()` is the AND of `SignatureValid`, `NotExpired`, and `NotRevoked`
(plus a structural check), exactly the reference verdict.

## API

| Function | Purpose |
|---|---|
| `VerifyCredential(raw []byte) (CredentialResult, error)` | Verify a W3C VC; issuer key resolved from the document's `did:key`. |
| `VerifyCredentialAt(raw, now)` / `VerifyCredentialWithKey(raw, pub, now)` | Explicit verification time / pinned issuer key. |
| `Canonicalize(raw []byte) ([]byte, error)` | The Attestix JCS-style canonical UTF-8 bytes (the signed form). |
| `DecodeDidKey(did string) (ed25519.PublicKey, error)` | Decode an Ed25519 `did:key` to its raw 32-byte public key. |
| `EncodeDidKey` / `VerificationMethod` / `DidKeyMultibase` | did:key helpers. |
| `VerifyDelegationChain(child, parent string, childAtt, parentAtt []string, pub) (DelegationResult, error)` | Verify a UCAN parent→child delegation: EdDSA signatures + capability attenuation. |
| `VerifyChainFull(token, pub, now)` | Recursive `prf` chain verification (signature + expiry + cycle detection + attenuation). |
| `VerifyToken(token, pub)` | Verify a single UCAN EdDSA JWT (rejects `alg:none`). |

## The canonical form is JCS-*style*, not strict RFC 8785

This is the single most error-prone part of any Attestix port, so it is worth
stating loudly: **Attestix does not sign over strict RFC 8785.** It signs over a
practical JCS subset that differs from RFC 8785 in two load-bearing ways:

1. **Unicode NFC normalization is applied** to every string value and every
   object key. RFC 8785 explicitly does *not* normalize. (This port uses
   `golang.org/x/text/unicode/norm`.)
2. **Number formatting follows Python `json.dumps`**: whole-number floats
   collapse to integers (`1.0` → `1`), integers are preserved at arbitrary
   precision (e.g. `9007199254740993`, beyond 2^53, is emitted verbatim), and
   non-whole floats keep their literal form. Signed payloads should avoid
   non-trivial floats; the vectors only use integers and `1.5`.

Otherwise: keys sorted by Unicode code point, separators `","` / `":"` with no
whitespace, raw UTF-8 output (no `\uXXXX` escapes). `Canonicalize` reproduces
this exactly: see [`canonical.go`](canonical.go) and the `canon-001` vector.

Other contract details mirrored here: VC signatures cover every top-level field
**except** `proof` and `credentialStatus`; `proofValue` is base64url **with**
padding; `did:key` is `did:key:z` + base58btc(`0xed01` ‖ 32-byte key); UCAN
tokens are EdDSA JWTs whose signed message is the compact
`base64url(header).base64url(payload)` (base64url **without** padding), with
`alg:none` rejected and child capabilities required to be a subset of the
parent's.

## Spec & references

- Core (issuer) implementation: <https://github.com/VibeTensor/attestix>
- Conformance contract: `spec/verify/v1/vectors.json` + `README.md` in the core repo
- Bundle wire-format spec: <https://attestix.io/spec/bundle/v1>

## Run the tests

```sh
go test ./...
```

The suite loads `testdata/vectors.json` and asserts every conformance vector
(canonicalization byte-match, did:key decode, VC verify: valid / tampered /
expired, and UCAN chain: valid attenuation / escalation).

## License

[Apache-2.0](LICENSE) © 2026 VibeTensor
