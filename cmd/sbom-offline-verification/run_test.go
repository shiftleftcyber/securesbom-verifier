package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shiftleftcyber/secure-sbom-verifier/testsupport"
)

func TestCommandRun_CycloneDXSuccess(t *testing.T) {
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

	var stdout, stderr bytes.Buffer
	exitCode := newCommand(&stdout, &stderr).run([]string{"--sbom", sbomPath, "--pubkey", pubPath, "--verification-version", "v2"})
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d stderr=%s", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "VERIFICATION SUCCESSFUL") {
		t.Fatalf("expected success output, got %s", stdout.String())
	}
}

func TestCommandRun_DigestSuccess(t *testing.T) {
	privKey, publicKey := testsupport.GenerateKeyPair(t)
	digest := sha256.Sum256([]byte("hello world"))
	signature := testsupport.SignDigestASN1(t, privKey, digest[:])

	tempDir := t.TempDir()
	pubPath := filepath.Join(tempDir, "public.pem")
	if err := os.WriteFile(pubPath, []byte(publicKey), 0o600); err != nil {
		t.Fatalf("write public key: %v", err)
	}

	var stdout, stderr bytes.Buffer
	exitCode := newCommand(&stdout, &stderr).run([]string{
		"--digest", base64.StdEncoding.EncodeToString(digest[:]),
		"--signature", base64.StdEncoding.EncodeToString(signature),
		"--pubkey", pubPath,
	})
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d stderr=%s", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "VERIFICATION SUCCESSFUL") {
		t.Fatalf("expected success output, got %s", stdout.String())
	}
}

func TestCommandRun_MissingPubKey(t *testing.T) {
	var stdout, stderr bytes.Buffer
	exitCode := newCommand(&stdout, &stderr).run([]string{"--digest", "abc"})
	if exitCode == 0 {
		t.Fatal("expected non-zero exit code")
	}
	if !strings.Contains(stderr.String(), "-pubkey is required") {
		t.Fatalf("expected missing pubkey output, got %s", stderr.String())
	}
}

func TestCommandRun_InvalidVerificationVersion(t *testing.T) {
	tempDir := t.TempDir()
	pubPath := filepath.Join(tempDir, "public.pem")
	if err := os.WriteFile(pubPath, []byte("pem"), 0o600); err != nil {
		t.Fatalf("write public key: %v", err)
	}

	var stdout, stderr bytes.Buffer
	exitCode := newCommand(&stdout, &stderr).run([]string{"--digest", "abc", "--pubkey", pubPath, "--verification-version", "v3"})
	if exitCode == 0 {
		t.Fatal("expected non-zero exit code")
	}
	if !strings.Contains(stderr.String(), "Invalid -verification-version") {
		t.Fatalf("expected invalid version output, got %s", stderr.String())
	}
}
