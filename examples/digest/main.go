package main

import (
	"fmt"
	"log"
	"os"

	digestsigning "github.com/shiftleftcyber/securesbom-verifier/services/digest"
	"github.com/shiftleftcyber/securesbom-verifier/verificationkey"
)

func main() {
	if len(os.Args) != 4 {
		log.Fatalf("usage: %s <digest-base64> <signature-base64> <public-key-path>", os.Args[0])
	}

	if err := verifyDigestExample(os.Args[1], os.Args[2], os.Args[3]); err != nil {
		log.Fatal(err)
	}

	fmt.Println("verification result: signature is valid")
}

func verifyDigestExample(digestB64, signatureB64, publicKeyPath string) error {
	pub, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return fmt.Errorf("read public key: %w", err)
	}

	validated, err := digestsigning.NewValidator().ValidateVerifyDigestRequest(digestsigning.VerifyDigestInput{
		KeyID:         "offline",
		HashAlgorithm: "sha256",
		Digest:        digestB64,
		Signature:     signatureB64,
	})
	if err != nil {
		return fmt.Errorf("validate digest request: %w", err)
	}

	err = digestsigning.NewCryptoVerifier().Verify(
		&verificationkey.KeyInfo{
			KeyID:     "offline",
			Algorithm: "ES256",
			PublicKey: string(pub),
		},
		validated.Digest,
		validated.Signature,
	)
	if err != nil {
		return fmt.Errorf("verify digest: %w", err)
	}

	return nil
}
