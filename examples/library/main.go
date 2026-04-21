package main

import (
	"fmt"
	"log"
	"os"

	"github.com/shiftleftcyber/secure-sbom-verifier/application"
)

func main() {
	if len(os.Args) != 3 {
		log.Fatalf("usage: %s <signed-sbom-path> <public-key-path>", os.Args[0])
	}

	result, err := verifyExample(os.Args[1], os.Args[2])
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("verification result: %+v\n", result)
}

func verifyExample(sbomPath, publicKeyPath string) (*application.VerificationResult, error) {
	sbom, err := os.ReadFile(sbomPath)
	if err != nil {
		return nil, fmt.Errorf("read sbom: %w", err)
	}

	pub, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read public key: %w", err)
	}

	app := application.NewVerifierApp()
	result, err := app.VerifyCycloneDXEmbeddedVersioned(sbom, string(pub), application.VerificationV2)
	if err != nil {
		return nil, fmt.Errorf("verify: %w", err)
	}

	return result, nil
}
