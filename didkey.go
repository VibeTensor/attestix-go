package attestix

import (
	"crypto/ed25519"
	"fmt"
	"strings"

	"github.com/mr-tron/base58"
)

// ed25519MulticodecPrefix is the unsigned-varint multicodec code for
// ed25519-pub (0xed 0x01). Ed25519 did:keys always render with a z6Mk... prefix.
var ed25519MulticodecPrefix = []byte{0xED, 0x01}

// DecodeDidKey decodes an Ed25519 did:key into its raw 32-byte public key.
//
// did:key form: "did:key:z" + base58btc(0xed 0x01 || raw32). The leading "z"
// is the multibase code for base58btc.
func DecodeDidKey(did string) (ed25519.PublicKey, error) {
	mb, err := DidKeyMultibase(did)
	if err != nil {
		return nil, err
	}
	return DecodeMultibaseKey(mb)
}

// DidKeyMultibase returns the multibase portion (the "z..." string) of a
// did:key, i.e. everything after the "did:key:" prefix. The verificationMethod
// fragment for a did:key is "#" + this value.
func DidKeyMultibase(did string) (string, error) {
	const prefix = "did:key:"
	if !strings.HasPrefix(did, prefix) {
		return "", fmt.Errorf("attestix: not a did:key: %q", did)
	}
	mb := strings.TrimPrefix(did, prefix)
	if !strings.HasPrefix(mb, "z") {
		return "", fmt.Errorf("attestix: did:key multibase must start with 'z' (base58btc): %q", mb)
	}
	return mb, nil
}

// DecodeMultibaseKey decodes a "z..." base58btc multibase string carrying the
// 0xed01 multicodec prefix into the raw 32-byte Ed25519 public key.
func DecodeMultibaseKey(mb string) (ed25519.PublicKey, error) {
	if !strings.HasPrefix(mb, "z") {
		return nil, fmt.Errorf("attestix: multibase must start with 'z': %q", mb)
	}
	decoded, err := base58.Decode(mb[1:])
	if err != nil {
		return nil, fmt.Errorf("attestix: base58 decode: %w", err)
	}
	if len(decoded) != len(ed25519MulticodecPrefix)+ed25519.PublicKeySize {
		return nil, fmt.Errorf("attestix: unexpected decoded length %d", len(decoded))
	}
	if decoded[0] != ed25519MulticodecPrefix[0] || decoded[1] != ed25519MulticodecPrefix[1] {
		return nil, fmt.Errorf("attestix: bad multicodec prefix %02x%02x, want ed01", decoded[0], decoded[1])
	}
	return ed25519.PublicKey(decoded[len(ed25519MulticodecPrefix):]), nil
}

// EncodeDidKey is the inverse of DecodeDidKey: it renders a raw Ed25519 public
// key as a did:key string. Provided for round-trip testing and issuance tools.
func EncodeDidKey(pub ed25519.PublicKey) (string, error) {
	if len(pub) != ed25519.PublicKeySize {
		return "", fmt.Errorf("attestix: public key must be %d bytes", ed25519.PublicKeySize)
	}
	payload := append(append([]byte{}, ed25519MulticodecPrefix...), pub...)
	return "did:key:z" + base58.Encode(payload), nil
}

// VerificationMethod returns the canonical verificationMethod identifier for a
// did:key, "<did>#<multibase>".
func VerificationMethod(did string) (string, error) {
	mb, err := DidKeyMultibase(did)
	if err != nil {
		return "", err
	}
	return did + "#" + mb, nil
}
