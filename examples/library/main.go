package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	securesbomverifier "github.com/shiftleftcyber/securesbom-verifier"
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

func verifyExample(sbomPath, publicKeyPath string) (*securesbomverifier.VerificationResult, error) {
	sbom, err := os.ReadFile(sbomPath)
	if err != nil {
		return nil, fmt.Errorf("read sbom: %w", err)
	}

	pub, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read public key: %w", err)
	}

	verifier := securesbomverifier.NewVerifier()
	if isAIBOM(sbom) {
		result, err := verifier.VerifyAIBOMEmbeddedVersioned(sbom, string(pub), securesbomverifier.VerificationV2)
		if err != nil {
			return nil, fmt.Errorf("verify AI-BOM: %w", err)
		}
		return result, nil
	}

	result, err := verifier.VerifyCycloneDXEmbeddedVersioned(sbom, string(pub), securesbomverifier.VerificationV2)
	if err != nil {
		return nil, fmt.Errorf("verify CycloneDX: %w", err)
	}
	return result, nil
}

func isAIBOM(sbom []byte) bool {
	var doc struct {
		Metadata struct {
			BOMFormat string `json:"bomFormat"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(sbom, &doc); err != nil {
		return false
	}
	return doc.Metadata.BOMFormat == "AI-SBOM"
}
