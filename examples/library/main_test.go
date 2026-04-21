package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/shiftleftcyber/securesbom-verifier/testsupport"
)

func TestVerifyExample(t *testing.T) {
	signed, publicKey := testsupport.SignedCycloneDXV2(t, "ES256")
	tempDir := t.TempDir()
	sbomPath := filepath.Join(tempDir, "signed.cdx.json")
	pubPath := filepath.Join(tempDir, "public.pem")

	if err := os.WriteFile(sbomPath, signed, 0o600); err != nil {
		t.Fatalf("write SBOM: %v", err)
	}
	if err := os.WriteFile(pubPath, []byte(publicKey), 0o600); err != nil {
		t.Fatalf("write public key: %v", err)
	}

	result, err := verifyExample(sbomPath, pubPath)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Message != "signature is valid" {
		t.Fatalf("unexpected message: %s", result.Message)
	}
}

func TestVerifyExample_ReadErrors(t *testing.T) {
	if _, err := verifyExample("missing-sbom.json", "missing-key.pem"); err == nil {
		t.Fatal("expected error")
	}
}
