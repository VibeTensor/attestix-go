package attestix_test

import (
	"fmt"
	"os"

	attestix "github.com/VibeTensor/attestix-go"
)

// ExampleVerifyCredential shows the 10-line offline verification of a W3C VC
// issued by the Attestix Python core. No network, no Python runtime.
func ExampleVerifyCredential() {
	vc, err := os.ReadFile("testdata/sample-vc.json")
	if err != nil {
		fmt.Println("read:", err)
		return
	}
	res, err := attestix.VerifyCredential(vc)
	if err != nil {
		fmt.Println("verify:", err)
		return
	}
	fmt.Printf("signature=%v expired=%v revoked=%v verify=%v\n",
		res.SignatureValid, !res.NotExpired, !res.NotRevoked, res.Verify())
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
