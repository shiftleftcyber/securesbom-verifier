package application

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/shiftleftcyber/securesbom-verifier/services"
	"github.com/shiftleftcyber/securesbom-verifier/testsupport"
)

func TestNewVerifierApp(t *testing.T) {
	app := NewVerifierApp()
	if app == nil {
		t.Fatal("expected app")
	}
}

func TestVerifyCycloneDXEmbeddedVersioned_V1(t *testing.T) {
	signed, publicKey := testsupport.SignedCycloneDXV1(t, "ES256")

	result, err := NewVerifierApp().VerifyCycloneDXEmbeddedVersioned(signed, publicKey, VerificationV1)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Message != "signature is valid" {
		t.Fatalf("unexpected message: %s", result.Message)
	}
}

func TestVerifyCycloneDXEmbeddedVersioned_V2(t *testing.T) {
	signed, publicKey := testsupport.SignedCycloneDXV2(t, "ES256")

	result, err := NewVerifierApp().VerifyCycloneDXEmbeddedVersioned(signed, publicKey, VerificationV2)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Algorithm != "ecdsa" {
		t.Fatalf("unexpected algorithm: %s", result.Algorithm)
	}
}

func TestVerifyCycloneDXEmbeddedVersioned_MissingPublicKey(t *testing.T) {
	signed, _ := testsupport.SignedCycloneDXV1(t, "ES256")

	_, err := NewVerifierApp().VerifyCycloneDXEmbeddedVersioned(signed, "", VerificationV1)
	if err == nil || !strings.Contains(err.Error(), "public key is required") {
		t.Fatalf("expected public key error, got %v", err)
	}
}

func TestVerifyCycloneDXEmbeddedVersioned_InvalidSignature(t *testing.T) {
	signed, publicKey := testsupport.SignedCycloneDXV1(t, "ES256")
	signed[len(signed)-2] = 'x'

	_, err := NewVerifierApp().VerifyCycloneDXEmbeddedVersioned(signed, publicKey, VerificationV1)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestVerifyCycloneDXEmbeddedVersioned_UnsupportedAlgorithm(t *testing.T) {
	signed, publicKey := testsupport.SignedCycloneDXV1(t, "RS256")

	_, err := NewVerifierApp().VerifyCycloneDXEmbeddedVersioned(signed, publicKey, VerificationV1)
	if err == nil || !strings.Contains(err.Error(), "failed to create verifier") {
		t.Fatalf("expected verifier creation error, got %v", err)
	}
}

func TestVerifyCycloneDXEmbeddedVersioned_FactoryError(t *testing.T) {
	signed, publicKey := testsupport.SignedCycloneDXV1(t, "ES256")
	app := NewVerifierAppWithFactory(func(string) (services.PublicKeyVerifier, error) {
		return nil, errors.New("boom")
	})

	_, err := app.VerifyCycloneDXEmbeddedVersioned(signed, publicKey, VerificationV1)
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("expected factory error, got %v", err)
	}
}

func TestVerifySPDXDetachedVersioned_V1(t *testing.T) {
	sbom, publicKey, signature := testsupport.SignedSPDXDetachedV1(t)

	result, err := NewVerifierApp().VerifySPDXDetachedVersioned(sbom, signature, publicKey, VerificationV1)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Message != "SPDX detached signature is valid" {
		t.Fatalf("unexpected message: %s", result.Message)
	}
}

func TestVerifySPDXDetachedVersioned_V2(t *testing.T) {
	sbom, publicKey, signature := testsupport.SignedSPDXDetachedV2(t)

	result, err := NewVerifierApp().VerifySPDXDetachedVersioned(sbom, signature, publicKey, VerificationV2)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Algorithm != "ES256" {
		t.Fatalf("unexpected algorithm: %s", result.Algorithm)
	}
}

func TestVerifySPDXDetachedVersioned_MissingPublicKey(t *testing.T) {
	sbom, _, signature := testsupport.SignedSPDXDetachedV1(t)

	_, err := NewVerifierApp().VerifySPDXDetachedVersioned(sbom, signature, "", VerificationV1)
	if err == nil || !strings.Contains(err.Error(), "public key is required") {
		t.Fatalf("expected public key error, got %v", err)
	}
}

func TestVerifySPDXDetachedVersioned_InvalidSignature(t *testing.T) {
	sbom, publicKey, signature := testsupport.SignedSPDXDetachedV1(t)

	_, err := NewVerifierApp().VerifySPDXDetachedVersioned(sbom, signature+"A", publicKey, VerificationV1)
	if !errors.Is(err, ErrSignatureFail) && (err == nil || !strings.Contains(err.Error(), "signature verification failed")) {
		t.Fatalf("expected signature failure, got %v", err)
	}
}

func TestDecodeEmbeddedSignature_InvalidJSON(t *testing.T) {
	_, _, err := decodeEmbeddedSignature([]byte("{"))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestDecodeEmbeddedSignature_MissingValue(t *testing.T) {
	_, _, err := decodeEmbeddedSignature([]byte(`{"alg":"ES256"}`))
	if err == nil || !strings.Contains(err.Error(), "signature value missing") {
		t.Fatalf("expected missing value error, got %v", err)
	}
}

func TestCanonicalizeEmbeddedCycloneDXForV2_InvalidCases(t *testing.T) {
	_, _, _, err := canonicalizeEmbeddedCycloneDXForV2([]byte(`{`))
	if err == nil {
		t.Fatal("expected invalid JSON error")
	}

	_, _, _, err = canonicalizeEmbeddedCycloneDXForV2([]byte(`{"name":"demo"}`))
	if err == nil || !strings.Contains(err.Error(), "signature object is missing") {
		t.Fatalf("expected missing signature error, got %v", err)
	}

	_, _, _, err = canonicalizeEmbeddedCycloneDXForV2([]byte(`{"signature":"bad"}`))
	if err == nil || !strings.Contains(err.Error(), "signature must be an object") {
		t.Fatalf("expected invalid signature type error, got %v", err)
	}
}

func TestCanonicalizeEmbeddedCycloneDXForV2_MissingValue(t *testing.T) {
	doc := map[string]any{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.6",
		"version":     1,
		"metadata": map[string]any{
			"component": map[string]any{
				"type": "application",
				"name": "example",
			},
		},
		"signature": map[string]any{
			"alg": "ES256",
		},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal doc: %v", err)
	}

	_, _, _, err = canonicalizeEmbeddedCycloneDXForV2(raw)
	if err == nil || !strings.Contains(err.Error(), "signature value missing") {
		t.Fatalf("expected missing value error, got %v", err)
	}
}
