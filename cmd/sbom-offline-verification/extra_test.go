package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shiftleftcyber/securesbom-verifier/testsupport"
)

func TestCommandRun_SPDXSuccess(t *testing.T) {
	sbom, publicKey, signature := testsupport.SignedSPDXDetachedV1(t)
	tempDir := t.TempDir()
	sbomPath := filepath.Join(tempDir, "sample.spdx.json")
	pubPath := filepath.Join(tempDir, "public.pem")

	if err := os.WriteFile(sbomPath, sbom, 0o600); err != nil {
		t.Fatalf("write SBOM: %v", err)
	}
	if err := os.WriteFile(pubPath, []byte(publicKey), 0o600); err != nil {
		t.Fatalf("write public key: %v", err)
	}

	var stdout, stderr bytes.Buffer
	exitCode := newCommand(&stdout, &stderr).run([]string{
		"--sbom", sbomPath,
		"--signature", signature,
		"--pubkey", pubPath,
		"--verification-version", "v1",
	})
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d stderr=%s", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "SPDX") {
		t.Fatalf("expected SPDX output, got %s", stdout.String())
	}
}

func TestCommandRun_MissingSBOMFile(t *testing.T) {
	tempDir := t.TempDir()
	pubPath := filepath.Join(tempDir, "public.pem")
	if err := os.WriteFile(pubPath, []byte("pem"), 0o600); err != nil {
		t.Fatalf("write public key: %v", err)
	}

	var stdout, stderr bytes.Buffer
	exitCode := newCommand(&stdout, &stderr).run([]string{"--sbom", filepath.Join(tempDir, "missing.json"), "--pubkey", pubPath})
	if exitCode == 0 {
		t.Fatal("expected non-zero exit code")
	}
	if !strings.Contains(stderr.String(), "Failed to read SBOM") {
		t.Fatalf("expected read failure output, got %s", stderr.String())
	}
}

func TestCommandRun_SPDXMissingSignature(t *testing.T) {
	sbom := testsupport.FixtureBytes(t, "spdx.json")
	_, publicKey := testsupport.GenerateKeyPair(t)
	tempDir := t.TempDir()
	sbomPath := filepath.Join(tempDir, "sample.spdx.json")
	pubPath := filepath.Join(tempDir, "public.pem")

	if err := os.WriteFile(sbomPath, sbom, 0o600); err != nil {
		t.Fatalf("write SBOM: %v", err)
	}
	if err := os.WriteFile(pubPath, []byte(publicKey), 0o600); err != nil {
		t.Fatalf("write public key: %v", err)
	}

	var stdout, stderr bytes.Buffer
	exitCode := newCommand(&stdout, &stderr).run([]string{"--sbom", sbomPath, "--pubkey", pubPath})
	if exitCode == 0 {
		t.Fatal("expected non-zero exit code")
	}
	if !strings.Contains(stderr.String(), "Unsupported SBOM type") && !strings.Contains(stderr.String(), "SPDX verification requires --signature") && !strings.Contains(stdout.String(), "VERIFICATION FAILED") {
		t.Fatalf("expected failure output, got stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
}

func TestCommandRun_InvalidSBOMContent(t *testing.T) {
	_, publicKey := testsupport.GenerateKeyPair(t)
	tempDir := t.TempDir()
	sbomPath := filepath.Join(tempDir, "invalid.json")
	pubPath := filepath.Join(tempDir, "public.pem")

	if err := os.WriteFile(sbomPath, []byte("{"), 0o600); err != nil {
		t.Fatalf("write SBOM: %v", err)
	}
	if err := os.WriteFile(pubPath, []byte(publicKey), 0o600); err != nil {
		t.Fatalf("write public key: %v", err)
	}

	var stdout, stderr bytes.Buffer
	exitCode := newCommand(&stdout, &stderr).run([]string{"--sbom", sbomPath, "--pubkey", pubPath})
	if exitCode == 0 {
		t.Fatal("expected non-zero exit code")
	}
	if !strings.Contains(stderr.String(), "SBOM validation failed") {
		t.Fatalf("expected validation failure output, got %s", stderr.String())
	}
}

func TestCommandRun_DigestMissingSignature(t *testing.T) {
	_, publicKey := testsupport.GenerateKeyPair(t)
	tempDir := t.TempDir()
	pubPath := filepath.Join(tempDir, "public.pem")
	if err := os.WriteFile(pubPath, []byte(publicKey), 0o600); err != nil {
		t.Fatalf("write public key: %v", err)
	}

	var stdout, stderr bytes.Buffer
	exitCode := newCommand(&stdout, &stderr).run([]string{
		"--digest", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
		"--pubkey", pubPath,
	})
	if exitCode == 0 {
		t.Fatal("expected non-zero exit code")
	}
	if !strings.Contains(stderr.String(), "digest verification requires -signature") {
		t.Fatalf("expected missing signature output, got %s", stderr.String())
	}
}

func TestCommandRun_CycloneDXFailure(t *testing.T) {
	signed, _ := testsupport.SignedCycloneDXV2(t, "ES256")
	_, wrongPublicKey := testsupport.GenerateKeyPair(t)
	tempDir := t.TempDir()
	sbomPath := filepath.Join(tempDir, "signed.cdx.json")
	pubPath := filepath.Join(tempDir, "public.pem")

	if err := os.WriteFile(sbomPath, signed, 0o600); err != nil {
		t.Fatalf("write SBOM: %v", err)
	}
	if err := os.WriteFile(pubPath, []byte(wrongPublicKey), 0o600); err != nil {
		t.Fatalf("write public key: %v", err)
	}

	var stdout, stderr bytes.Buffer
	exitCode := newCommand(&stdout, &stderr).run([]string{"--sbom", sbomPath, "--pubkey", pubPath})
	if exitCode == 0 {
		t.Fatal("expected non-zero exit code")
	}
	if !strings.Contains(stdout.String(), "VERIFICATION FAILED") {
		t.Fatalf("expected failure output, got %s", stdout.String())
	}
}

func TestPrintResultFailure(t *testing.T) {
	var out bytes.Buffer
	printResult(&out, false, "SBOM", "SBOM Type", "CycloneDX", "ES256", "", errExample)
	if !strings.Contains(out.String(), "VERIFICATION FAILED") {
		t.Fatalf("expected failure output, got %s", out.String())
	}
}

var errExample = errors.New("boom")
