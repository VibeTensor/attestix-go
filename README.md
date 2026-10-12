# attestix-go

Offline Go verifier for Attestix Ed25519 credentials, `did:key` public keys,
and UCAN-style delegation tokens. The verifier does not issue credentials or
contact a server. Issuance belongs to the [Attestix core](https://github.com/VibeTensor/attestix).

## Use the current source

Requires Go 1.25 or later, as declared in [go.mod](go.mod). This checkout uses
`golang.org/x/text` 0.41.0. The source version and a published module tag are
separate: do not assume an older tag includes the current verification fixes.

From a checkout of the reviewed main commit:

```sh
go test ./...
go build ./...
```

For an application, select a reviewed module tag or commit explicitly:

```sh
go get github.com/VibeTensor/attestix-go@<reviewed-tag-or-commit>
```

## Verify a credential

```go
package main

import (
	"fmt"
	"log"
	"os"

	attestix "github.com/VibeTensor/attestix-go"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: verifier credential.json")
	}
	vc, err := os.ReadFile(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	result, err := attestix.VerifyCredential(vc)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("valid=%v signature=%v expired=%v revoked=%v\n",
		result.Verify(), result.SignatureValid, !result.NotExpired, !result.NotRevoked)
}
```

Always handle the returned error before using the result. `Verify()` requires
`StructureValid`, `SignatureValid`, `NotExpired`, and `NotRevoked`.

## Credential boundaries

- `VerifyCredential` and `VerifyCredentialAt` resolve the key from the signed
  `issuer` string or `issuer.id`. Present `proof.verificationMethod` metadata
  must be a nonempty string whose DID before `#` matches that issuer.
- `VerifyCredentialWithKey` uses the caller's pinned key instead of document
  key resolution. The caller must associate the trusted key with the expected
  issuer; this path does not independently validate the method/issuer binding.
  A supplied non-nil key must contain 32 Ed25519 public-key bytes. A nil key
  selects normal document resolution.
- The signature covers every top-level field except `proof` and
  `credentialStatus`. These mutable fields do not authorize a different issuer.
- Absent `expirationDate` means no expiry. A present empty, non-string, or
  unparseable date returns an error and does not pass the expiry check.
  A valid date requires `now < expirationDate`.
- Offline revocation reads the embedded boolean `credentialStatus.revoked`.
  Missing status does not establish current revocation state. Consult the
  issuer's trusted status source when current revocation matters.
- Parsing rejects trailing JSON content. Structural checks concern the proof
  shape; this is not a general W3C schema validator or JSON-LD processor.

## Choose the delegation API deliberately

| API | Checks performed |
|---|---|
| `VerifyToken(token, pub)` | Compact JWT parsing, `alg=EdDSA`, and signature against the caller's key; returns claims. No expiry or ancestry check. |
| `VerifyDelegationChain(child, parent, childAtt, parentAtt, pub)` | Both signatures and child-capability subset. Non-nil capability arguments override token claims. No expiry or recursive ancestry check. |
| `VerifyChainFull(token, pub, now)` | Signatures through `prf`, nonzero `exp` expiry, repeated-`jti` cycle detection, and attenuation at each ancestor. |

Delegation APIs require a trusted 32-byte Ed25519 key supplied by the caller.
`VerifyChainFull` does not enforce `nbf`, `iat`, audience policy, or live
revocation. Apply those application policies separately; a valid signature is
not a complete authorization decision.

## Canonicalization and public API

Attestix uses a JCS-style form, not strict RFC 8785. It NFC-normalizes string
values and object keys, sorts normalized keys by Unicode code point, emits
compact UTF-8 JSON, and preserves integer literals without float conversion.
Distinct keys that collide after NFC normalization return an error. Non-finite
float values and overflowing float magnitudes are rejected.

Whole-valued floats collapse to integers. Non-whole float literals retain their
input form; general Python float-format equivalence is not guaranteed. Prefer
integer or string fields for signed data. The shared vectors cover integers
and the simple decimal `1.5`, not every numeric edge case.

| API | Purpose |
|---|---|
| `Canonicalize(raw)` | Parse one raw JSON value and produce canonical bytes. |
| `CanonicalizeValue(value)` | Canonicalize a decoded value; use `json.Decoder.UseNumber()` to preserve number tokens. |
| `VerifyCredentialAt(raw, now)` | Verify with an explicit reference time. |
| `VerifyCredentialWithKey(raw, pub, now)` | Verify with a caller-pinned issuer key. |
| `DecodeDidKey(did)` | Decode an Ed25519 `did:key` to a 32-byte key. |
| `EncodeDidKey`, `VerificationMethod`, `DidKeyMultibase` | Encode key identifiers and method IDs. |

## Development and compatibility

```sh
go test ./...
go vet ./...
go build ./...
```

Linux CI runs `go test -race ./...` on Go 1.25, 1.26, and 1.27. Shared vectors
are vendored in [testdata/vectors.json](testdata/vectors.json); security boundary
regressions are in [security_boundaries_test.go](security_boundaries_test.go).
Vector compatibility is evidence for the represented cases, not a blanket
claim for every JSON value or every verifier implementation.

## License

[Apache-2.0](LICENSE).
