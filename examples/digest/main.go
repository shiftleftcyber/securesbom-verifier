package main

import (
	"fmt"
	"log"
	"os"

	securesbomverifier "github.com/shiftleftcyber/securesbom-verifier"
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

	_, err = securesbomverifier.NewVerifier().VerifyDigest(
		securesbomverifier.VerifyDigestInput{
			KeyID:         "offline",
			HashAlgorithm: "sha256",
			Digest:        digestB64,
			Signature:     signatureB64,
		},
		securesbomverifier.VerificationKey{
			KeyID:     "offline",
			Algorithm: "ES256",
			PublicKey: string(pub),
		},
	)
	if err != nil {
		return fmt.Errorf("verify digest: %w", err)
	}

	return nil
}
