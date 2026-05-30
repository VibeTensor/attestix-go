package attestix

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// vectorsFile is the shared cross-language conformance contract, vendored
// verbatim from VibeTensor/attestix:spec/verify/v1/vectors.json.
const vectorsFile = "testdata/vectors.json"

type vectorSet struct {
	AttestixVersion string   `json:"attestix_version"`
	IssuerDID       string   `json:"issuer_did"`
	IssuerPubkeyHex string   `json:"issuer_pubkey_raw_hex"`
	IssuerSeedHex   string   `json:"issuer_seed_hex"`
	Spec            string   `json:"spec"`
	Version         string   `json:"version"`
	VectorCount     int      `json:"vector_count"`
	Vectors         []vector `json:"vectors"`
}

type vector struct {
	ID                string          `json:"id"`
	Kind              string          `json:"kind"`
	Description       string          `json:"description"`
	Input             json.RawMessage `json:"input"`
	Expected          map[string]any  `json:"expected"`
	CanonicalBytesHex string          `json:"canonical_bytes_hex"`
}

func loadVectors(t *testing.T) vectorSet {
	t.Helper()
	raw, err := os.ReadFile(vectorsFile)
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var vs vectorSet
	if err := json.Unmarshal(raw, &vs); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(vs.Vectors) != vs.VectorCount {
		t.Fatalf("vector_count %d != len(vectors) %d", vs.VectorCount, len(vs.Vectors))
	}
	return vs
}

// fixedNow is a verification time after the expired vector's 2021 expiry and
// before the valid vector's 2027 expiry, so the deterministic expiry checks
// resolve as the vectors expect.
var fixedNow = time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)

func TestConformanceVectors(t *testing.T) {
	vs := loadVectors(t)
	if len(vs.Vectors) == 0 {
		t.Fatal("no vectors loaded")
	}

	issuerPub, err := hex.DecodeString(vs.IssuerPubkeyHex)
	if err != nil {
		t.Fatalf("decode issuer pubkey: %v", err)
	}

	passed := 0
	for _, v := range vs.Vectors {
		v := v
		t.Run(v.ID, func(t *testing.T) {
			switch v.Kind {
			case "canonicalize":
				runCanonicalize(t, v)
			case "did_key_decode":
				runDidKeyDecode(t, v)
			case "verify_credential":
				runVerifyCredential(t, v, issuerPub)
			case "verify_delegation_chain":
				runVerifyDelegationChain(t, v, issuerPub)
			default:
				t.Fatalf("unknown vector kind %q", v.Kind)
			}
		})
		if !t.Failed() {
			passed++
		}
	}
	t.Logf("conformance: %d/%d vectors passed", passed, len(vs.Vectors))
}

func runCanonicalize(t *testing.T, v vector) {
	got, err := Canonicalize(v.Input)
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	wantHex := v.CanonicalBytesHex
	gotHex := hex.EncodeToString(got)
	if gotHex != wantHex {
		t.Fatalf("canonical bytes mismatch\n got: %s\nwant: %s\n got str: %s",
			gotHex, wantHex, string(got))
	}
	// Cross-check the readable expected form when present.
	if exp, ok := v.Expected["canonical_utf8"].(string); ok {
		if string(got) != exp {
			t.Fatalf("canonical_utf8 mismatch\n got: %s\nwant: %s", string(got), exp)
		}
	}
}

func runDidKeyDecode(t *testing.T, v vector) {
	var in struct {
		DID string `json:"did"`
	}
	if err := json.Unmarshal(v.Input, &in); err != nil {
		t.Fatalf("parse input: %v", err)
	}
	pub, err := DecodeDidKey(in.DID)
	if err != nil {
		t.Fatalf("DecodeDidKey: %v", err)
	}
	gotHex := hex.EncodeToString(pub)
	if want, _ := v.Expected["pubkey_raw_hex"].(string); gotHex != want {
		t.Fatalf("pubkey mismatch\n got: %s\nwant: %s", gotHex, want)
	}
	mb, err := DidKeyMultibase(in.DID)
	if err != nil {
		t.Fatalf("DidKeyMultibase: %v", err)
	}
	if want, _ := v.Expected["fragment"].(string); "#"+mb != want {
		t.Fatalf("fragment mismatch got #%s want %s", mb, want)
	}
	vm, err := VerificationMethod(in.DID)
	if err != nil {
		t.Fatalf("VerificationMethod: %v", err)
	}
	if want, _ := v.Expected["verification_method"].(string); vm != want {
		t.Fatalf("verification_method mismatch\n got: %s\nwant: %s", vm, want)
	}
}

func runVerifyCredential(t *testing.T, v vector, issuerPub []byte) {
	// First validate the canonical bytes the verifier signs over.
	if v.CanonicalBytesHex != "" {
		doc := mustDecodeOrdered(t, v.Input)
		payload := map[string]any{}
		for k, val := range doc {
			if k == "proof" || k == "credentialStatus" {
				continue
			}
			payload[k] = val
		}
		canon, err := CanonicalizeValue(payload)
		if err != nil {
			t.Fatalf("CanonicalizeValue: %v", err)
		}
		if hex.EncodeToString(canon) != v.CanonicalBytesHex {
			t.Fatalf("VC canonical mismatch\n got: %s\nwant: %s\n str: %s",
				hex.EncodeToString(canon), v.CanonicalBytesHex, string(canon))
		}
	}

	res, err := VerifyCredentialWithKey(v.Input, issuerPub, fixedNow)
	if err != nil {
		t.Fatalf("VerifyCredentialWithKey: %v", err)
	}
	wantBool(t, "signature_valid", res.SignatureValid, v.Expected)
	wantBool(t, "not_expired", res.NotExpired, v.Expected)
	wantBool(t, "not_revoked", res.NotRevoked, v.Expected)
	wantBool(t, "verify", res.Verify(), v.Expected)

	// did:key resolution path must agree with the pinned-key path.
	res2, err := VerifyCredentialAt(v.Input, fixedNow)
	if err != nil {
		t.Fatalf("VerifyCredentialAt: %v", err)
	}
	if res2.Verify() != res.Verify() {
		t.Fatalf("did:key-resolved verdict %v != pinned-key verdict %v", res2.Verify(), res.Verify())
	}
}

func runVerifyDelegationChain(t *testing.T, v vector, issuerPub []byte) {
	var in struct {
		ChildAtt    []string `json:"child_att"`
		ParentAtt   []string `json:"parent_att"`
		ParentToken string   `json:"parent_token"`
		Token       string   `json:"token"`
	}
	if err := json.Unmarshal(v.Input, &in); err != nil {
		t.Fatalf("parse input: %v", err)
	}
	res, err := verifyDelegationChainAt(in.Token, in.ParentToken, in.ChildAtt, in.ParentAtt, issuerPub, fixedNow)
	if err != nil {
		t.Fatalf("VerifyDelegationChain: %v", err)
	}
	wantBool(t, "child_signature_valid", res.ChildSignatureValid, v.Expected)
	wantBool(t, "parent_signature_valid", res.ParentSignatureValid, v.Expected)
	wantBool(t, "attenuation_is_subset", res.AttenuationIsSubset, v.Expected)
	wantBool(t, "verify", res.Verify(), v.Expected)
}

func mustDecodeOrdered(t *testing.T, raw []byte) map[string]interface{} {
	t.Helper()
	doc, err := decodeOrdered(raw)
	if err != nil {
		t.Fatalf("decodeOrdered: %v", err)
	}
	return doc
}

func wantBool(t *testing.T, key string, got bool, expected map[string]any) {
	t.Helper()
	want, ok := expected[key].(bool)
	if !ok {
		t.Fatalf("expected[%q] missing or not bool", key)
	}
	if got != want {
		t.Fatalf("%s: got %v want %v", key, got, want)
	}
}
