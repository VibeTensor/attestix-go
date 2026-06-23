package attestix_test

import (
	"fmt"
	"os"
	"testing"

	attestix "github.com/VibeTensor/attestix-go"
)

// TestVerifyCredentialExample exercises the 10-line offline verification of a
// W3C VC issued by the Attestix Python core. No network, no Python runtime.
//
// It asserts only that parsing/verification returns without error and yields a
// usable result. It does NOT assert Verify()==true: the sample VC may carry an
// expirationDate in the past under wall-clock, which is a valid verification
// outcome (NotExpired=false), not a parse failure.
func TestVerifyCredentialExample(t *testing.T) {
	vc, err := os.ReadFile("testdata/sample-vc.json")
	if err != nil {
		t.Fatalf("read sample-vc.json: %v", err)
	}
	res, err := attestix.VerifyCredential(vc)
	if err != nil {
		t.Fatalf("VerifyCredential: %v", err)
	}
	// Verify() must be callable on the returned result without panicking.
	_ = res.Verify()
}

// ExampleDecodeDidKey resolves an Ed25519 public key from a did:key.
func ExampleDecodeDidKey() {
	pub, err := attestix.DecodeDidKey("did:key:z6Mko5TBPGKHkCxSgmf3aC6p6SGj2auwCfRmBydXJFEwL4ev")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("%x\n", pub)
	// Output: 8022fe847be6106443a4030d74d390c8d9a91319b9f51526bc7c3d88a27c9b7b
}
