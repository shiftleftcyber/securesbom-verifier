package main

import (
	"fmt"
	"log"
	"os"

	securesbomverifier "github.com/shiftleftcyber/securesbom-verifier"
)

func main() {
	if len(os.Args) != 4 {
		log.Fatalf("usage: %s <spdx-sbom-path> <signature> <public-key-path>", os.Args[0])
	}

	result, err := verifySPDXExample(os.Args[1], os.Args[2], os.Args[3])
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("verification result: %+v\n", result)
}

func verifySPDXExample(sbomPath, signatureB64, publicKeyPath string) (*securesbomverifier.VerificationResult, error) {
	sbom, err := os.ReadFile(sbomPath)
	if err != nil {
		return nil, fmt.Errorf("read SBOM: %w", err)
	}

	pub, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read public key: %w", err)
	}

	verifier := securesbomverifier.NewVerifier()
	result, err := verifier.VerifySPDXDetachedVersioned(sbom, signatureB64, string(pub), securesbomverifier.VerificationV2)
	if err != nil {
		return nil, fmt.Errorf("verify SPDX: %w", err)
	}

	return result, nil
}
