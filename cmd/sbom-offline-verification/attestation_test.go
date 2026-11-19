package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shiftleftcyber/securesbom-verifier/attestation"
	"github.com/shiftleftcyber/securesbom-verifier/testsupport"
)

func writeAttestationFixture(t *testing.T) (string, string) {
	t.Helper()

	privKey, publicKey := testsupport.GenerateKeyPair(t)
	envelope := testsupport.SignedAttestation(t, privKey, "cli-key", testsupport.TestSubjects(), attestation.PredicateTypeCycloneDX, testsupport.SignedCycloneDXV2WithKey(t, privKey, "ES256"))

	tempDir := t.TempDir()
	envelopePath := filepath.Join(tempDir, "sbom.intoto.json")
	pubPath := filepath.Join(tempDir, "public.pem")
	if err := os.WriteFile(envelopePath, envelope, 0o600); err != nil {
		t.Fatalf("write attestation: %v", err)
	}
	if err := os.WriteFile(pubPath, []byte(publicKey), 0o600); err != nil {
		t.Fatalf("write public key: %v", err)
	}
	return envelopePath, pubPath
}

func TestCommandRun_AttestationSuccess(t *testing.T) {
	envelopePath, pubPath := writeAttestationFixture(t)

	var stdout, stderr bytes.Buffer
	exitCode := newCommand(&stdout, &stderr).run([]string{"--attestation", envelopePath, "--expected-digest", "sha256:" + testsupport.TestSubjectDigest, "--pubkey", pubPath})
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d stderr=%s stdout=%s", exitCode, stderr.String(), stdout.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "VERIFICATION SUCCESSFUL") || !strings.Contains(out, "predicate signature valid") {
		t.Fatalf("unexpected output: %s", out)
	}
}

func TestCommandRun_AttestationSubjectMismatch(t *testing.T) {
	envelopePath, pubPath := writeAttestationFixture(t)

	var stdout, stderr bytes.Buffer
	exitCode := newCommand(&stdout, &stderr).run([]string{"--attestation", envelopePath, "--expected-digest", strings.Repeat("ab", 32), "--pubkey", pubPath})
	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", exitCode)
	}
	if !strings.Contains(stdout.String(), "VERIFICATION FAILED") {
		t.Fatalf("unexpected output: %s", stdout.String())
	}
}

func TestCommandRun_AttestationRequiresExpectedDigest(t *testing.T) {
	envelopePath, pubPath := writeAttestationFixture(t)

	var stdout, stderr bytes.Buffer
	exitCode := newCommand(&stdout, &stderr).run([]string{"--attestation", envelopePath, "--pubkey", pubPath})
	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "-expected-digest is required") {
		t.Fatalf("unexpected stderr: %s", stderr.String())
	}
}

func TestCommandRun_AttestationMissingFile(t *testing.T) {
	_, pubPath := writeAttestationFixture(t)

	var stdout, stderr bytes.Buffer
	exitCode := newCommand(&stdout, &stderr).run([]string{"--attestation", filepath.Join(t.TempDir(), "missing.json"), "--expected-digest", testsupport.TestSubjectDigest, "--pubkey", pubPath})
	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "Failed to read attestation") {
		t.Fatalf("unexpected stderr: %s", stderr.String())
	}
}
