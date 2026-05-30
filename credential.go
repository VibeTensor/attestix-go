package attestix

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// mutableFields are the top-level VC fields excluded from the signed payload,
// matching attestix/services/credential_service.py::MUTABLE_FIELDS.
var mutableFields = map[string]struct{}{
	"proof":            {},
	"credentialStatus": {},
}

// CredentialResult is the structured outcome of verifying a W3C VC.
type CredentialResult struct {
	// SignatureValid is true when proof.proofValue is a valid Ed25519 signature
	// over the JCS-canonical bytes of the VC with proof + credentialStatus
	// removed.
	SignatureValid bool
	// NotExpired is true when there is no expirationDate, or the verification
	// time precedes it.
	NotExpired bool
	// NotRevoked is true unless credentialStatus.revoked is truthy.
	NotRevoked bool
	// StructureValid is true when the VC has the required shape (proof with a
	// proofValue, etc.).
	StructureValid bool
}

// Verify reports the overall verdict: signature valid AND not expired AND not
// revoked (structure must also be valid).
func (r CredentialResult) Verify() bool {
	return r.StructureValid && r.SignatureValid && r.NotExpired && r.NotRevoked
}

// VerifyCredential verifies a W3C Verifiable Credential supplied as raw JSON
// bytes. The issuer public key is resolved from the credential's
// issuer.id / verificationMethod did:key. Verification time is time.Now().
func VerifyCredential(raw []byte) (CredentialResult, error) {
	return VerifyCredentialAt(raw, time.Now())
}

// VerifyCredentialAt is VerifyCredential with an explicit verification time,
// used for deterministic testing of the expiry check.
func VerifyCredentialAt(raw []byte, now time.Time) (CredentialResult, error) {
	doc, err := decodeOrdered(raw)
	if err != nil {
		return CredentialResult{}, err
	}
	return verifyCredentialDoc(doc, now, nil)
}

// VerifyCredentialWithKey verifies a VC against a caller-supplied issuer public
// key, bypassing did:key resolution from the document. Use when the trusted key
// is pinned out of band.
func VerifyCredentialWithKey(raw []byte, pub ed25519.PublicKey, now time.Time) (CredentialResult, error) {
	doc, err := decodeOrdered(raw)
	if err != nil {
		return CredentialResult{}, err
	}
	return verifyCredentialDoc(doc, now, pub)
}

func decodeOrdered(raw []byte) (map[string]interface{}, error) {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	var v interface{}
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	m, ok := v.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("attestix: credential must be a JSON object")
	}
	return m, nil
}

func verifyCredentialDoc(doc map[string]interface{}, now time.Time, pinned ed25519.PublicKey) (CredentialResult, error) {
	res := CredentialResult{NotExpired: true, NotRevoked: true}

	proof, ok := doc["proof"].(map[string]interface{})
	if !ok {
		return res, fmt.Errorf("attestix: credential has no proof object")
	}
	proofValue, ok := proof["proofValue"].(string)
	if !ok || proofValue == "" {
		return res, fmt.Errorf("attestix: proof has no proofValue")
	}
	res.StructureValid = true

	// Resolve issuer key.
	pub := pinned
	if pub == nil {
		var err error
		pub, err = resolveIssuerKey(doc, proof)
		if err != nil {
			return res, err
		}
	}

	// Build the signed payload: drop mutable fields, canonicalize.
	payload := make(map[string]interface{}, len(doc))
	for k, v := range doc {
		if _, mut := mutableFields[k]; mut {
			continue
		}
		payload[k] = v
	}
	canon, err := CanonicalizeValue(payload)
	if err != nil {
		return res, err
	}

	// base64url WITH padding (urlsafe_b64encode). Accept unpadded too for
	// robustness.
	sig, err := decodeBase64urlPadded(proofValue)
	if err != nil {
		return res, fmt.Errorf("attestix: decode proofValue: %w", err)
	}
	res.SignatureValid = ed25519.Verify(pub, canon, sig)

	// Expiry: now < expirationDate.
	if expStr, ok := doc["expirationDate"].(string); ok && expStr != "" {
		exp, err := parseTime(expStr)
		if err != nil {
			return res, fmt.Errorf("attestix: parse expirationDate: %w", err)
		}
		res.NotExpired = now.Before(exp)
	}

	// Revocation: credentialStatus.revoked truthy => revoked.
	if cs, ok := doc["credentialStatus"].(map[string]interface{}); ok {
		if revoked, ok := cs["revoked"].(bool); ok && revoked {
			res.NotRevoked = false
		}
	}

	return res, nil
}

func resolveIssuerKey(doc, proof map[string]interface{}) (ed25519.PublicKey, error) {
	// Prefer proof.verificationMethod, fall back to issuer.id.
	if vm, ok := proof["verificationMethod"].(string); ok && vm != "" {
		did := vm
		if i := strings.IndexByte(vm, '#'); i >= 0 {
			did = vm[:i]
		}
		if strings.HasPrefix(did, "did:key:") {
			return DecodeDidKey(did)
		}
	}
	switch iss := doc["issuer"].(type) {
	case string:
		if strings.HasPrefix(iss, "did:key:") {
			return DecodeDidKey(iss)
		}
	case map[string]interface{}:
		if id, ok := iss["id"].(string); ok && strings.HasPrefix(id, "did:key:") {
			return DecodeDidKey(id)
		}
	}
	return nil, fmt.Errorf("attestix: could not resolve issuer did:key")
}

// decodeBase64urlPadded decodes base64url that may or may not carry padding.
func decodeBase64urlPadded(s string) ([]byte, error) {
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

// parseTime parses an ISO-8601 / RFC3339 timestamp. The Attestix reference
// emits offsets like "+00:00"; RFC3339 handles those directly.
func parseTime(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	// Some emitters use a space separator or no offset; try a couple fallbacks.
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05Z07:00", "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("attestix: unrecognised time %q", s)
}
