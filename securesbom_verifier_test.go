package securesbomverifier

import (
	"testing"

	"github.com/shiftleftcyber/securesbom-verifier/testsupport"
)

func TestNewVerifier_RootPackageAPI(t *testing.T) {
	signed, publicKey := testsupport.SignedCycloneDXV2(t, "ES256")

	result, err := NewVerifier().VerifyCycloneDXEmbeddedVersioned(signed, publicKey, VerificationV2)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Message != "signature is valid" {
		t.Fatalf("unexpected message: %s", result.Message)
	}
}
