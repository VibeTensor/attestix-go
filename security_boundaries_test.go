package attestix

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"math"
	"testing"
	"time"
)

func signedTestCredential(t *testing.T, impersonate bool, expiry interface{}, includeExpiry bool) []byte {
	t.Helper()
	pub, private, _ := ed25519.GenerateKey(nil)
	victim, _, _ := ed25519.GenerateKey(nil)
	did, _ := EncodeDidKey(pub)
	claimed := did
	if impersonate {
		claimed, _ = EncodeDidKey(victim)
	}
	payload := map[string]interface{}{"type": []interface{}{"VerifiableCredential"}, "issuer": map[string]interface{}{"id": claimed}, "credentialSubject": map[string]interface{}{"id": "synthetic"}}
	if includeExpiry {
		payload["expirationDate"] = expiry
	}
	canon, err := CanonicalizeValue(payload)
	if err != nil {
		t.Fatal(err)
	}
	payload["proof"] = map[string]interface{}{"verificationMethod": did + "#" + did[8:], "proofValue": base64.URLEncoding.EncodeToString(ed25519.Sign(private, canon))}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestIssuerSubstitutionRejected(t *testing.T) {
	for _, impersonate := range []bool{false, true} {
		result, err := VerifyCredentialAt(signedTestCredential(t, impersonate, nil, false), time.Now())
		if !impersonate && (err != nil || !result.Verify()) {
			t.Fatalf("valid issuer rejected: %v", err)
		}
		if impersonate && err == nil && result.Verify() {
			t.Fatal("attacker signature accepted for victim issuer")
		}
	}
}

func TestMalformedExpiryRejected(t *testing.T) {
	for _, expiry := range []interface{}{nil, false, "", "invalid-date", json.Number("123")} {
		result, err := VerifyCredentialAt(signedTestCredential(t, false, expiry, true), time.Now())
		if err == nil && result.Verify() {
			t.Fatalf("malformed expiry accepted: %v", expiry)
		}
	}
}

func TestMalformedPinnedKeyRejected(t *testing.T) {
	raw := signedTestCredential(t, false, nil, false)
	_, err := VerifyCredentialWithKey(raw, ed25519.PublicKey{1}, time.Now())
	if err == nil {
		t.Fatal("malformed pinned key accepted")
	}
}

func TestCanonicalSecurityBoundaries(t *testing.T) {
	for _, raw := range []string{`{"\u00e9":1,"e\u0301":2}`, `{} {}`, `{"n":1e309}`} {
		if _, err := Canonicalize([]byte(raw)); err == nil {
			t.Fatalf("ambiguous JSON accepted: %s", raw)
		}
	}
	if _, err := CanonicalizeValue(math.Inf(1)); err == nil {
		t.Fatal("infinity accepted")
	}
	if _, err := VerifyCredentialAt([]byte(`{} {}`), time.Now()); err == nil {
		t.Fatal("trailing JSON accepted")
	}
}
