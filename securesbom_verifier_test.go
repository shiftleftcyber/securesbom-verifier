package securesbomverifier

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/shiftleftcyber/securesbom-verifier/testsupport"
)

func TestNewVerifier_RootPackageAPI(t *testing.T) {
	signed, publicKey := testsupport.SignedCycloneDXV2(t, "ES256")

	result, err := NewVerifier().VerifyCycloneDXEmbeddedWithKeyVersioned(
		signed,
		VerificationKey{
			KeyID:     "test-key",
			Algorithm: "ES256",
			PublicKey: publicKey,
		},
		VerificationV2,
	)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Message != "signature is valid" {
		t.Fatalf("unexpected message: %s", result.Message)
	}
	if result.KeyID != "test-key" {
		t.Fatalf("unexpected key id: %s", result.KeyID)
	}
}

func TestVerifier_VerifyDigest_RootPackageAPI(t *testing.T) {
	privKey, publicKey := testsupport.GenerateKeyPair(t)
	digest := sha256.Sum256([]byte("hello root digest api"))
	signature := testsupport.SignDigestASN1(t, privKey, digest[:])

	result, err := NewVerifier().VerifyDigest(
		VerifyDigestInput{
			KeyID:         "test-key",
			HashAlgorithm: "sha256",
			Digest:        base64.StdEncoding.EncodeToString(digest[:]),
			Signature:     base64.StdEncoding.EncodeToString(signature),
		},
		VerificationKey{
			KeyID:     "test-key",
			Algorithm: "ES256",
			PublicKey: publicKey,
		},
	)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !result.Verified {
		t.Fatal("expected digest to verify")
	}
}

func TestVerifier_VerifyDigest_StableErrors(t *testing.T) {
	_, err := NewVerifier().VerifyDigest(
		VerifyDigestInput{
			KeyID:         "test-key",
			HashAlgorithm: "sha512",
			Digest:        "bad",
			Signature:     "bad",
		},
		VerificationKey{},
	)
	if !errors.Is(err, ErrInvalidHashAlgorithm) {
		t.Fatalf("expected ErrInvalidHashAlgorithm, got %v", err)
	}

	_, err = NewVerifier().VerifyDigest(
		VerifyDigestInput{
			KeyID:         "test-key",
			HashAlgorithm: "sha256",
			Digest:        base64.StdEncoding.EncodeToString(make([]byte, 32)),
			Signature:     base64.StdEncoding.EncodeToString([]byte("signature")),
		},
		VerificationKey{KeyID: "other-key", Algorithm: "ES256"},
	)
	if !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("expected ErrInvalidKey, got %v", err)
	}
}

func TestVerifier_VerifyDigest_VerificationFailedError(t *testing.T) {
	privKey, publicKey := testsupport.GenerateKeyPair(t)
	digest := sha256.Sum256([]byte("hello root digest api"))
	signature := testsupport.SignDigestASN1(t, privKey, digest[:])
	digest[0] ^= 0xff

	_, err := NewVerifier().VerifyDigest(
		VerifyDigestInput{
			KeyID:         "test-key",
			HashAlgorithm: "sha256",
			Digest:        base64.StdEncoding.EncodeToString(digest[:]),
			Signature:     base64.StdEncoding.EncodeToString(signature),
		},
		VerificationKey{
			KeyID:     "test-key",
			Algorithm: "ES256",
			PublicKey: publicKey,
		},
	)
	if !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("expected ErrVerificationFailed, got %v", err)
	}
}

func TestContractFixtures(t *testing.T) {
	fixtures := testsupport.NewContractFixtures(t)
	verifier := NewVerifier()

	if _, err := verifier.VerifyCycloneDXEmbeddedVersioned(
		fixtures.CycloneDXEmbeddedValid.SBOM,
		fixtures.CycloneDXEmbeddedValid.PublicKeyPEM,
		VerificationV2,
	); err != nil {
		t.Fatalf("valid CycloneDX contract fixture failed: %v", err)
	}

	if _, err := verifier.VerifyCycloneDXEmbeddedVersioned(
		fixtures.CycloneDXEmbeddedInvalid.SBOM,
		fixtures.CycloneDXEmbeddedInvalid.PublicKeyPEM,
		VerificationV2,
	); !errors.Is(err, ErrSignatureFail) {
		t.Fatalf("expected invalid CycloneDX fixture to fail signature verification, got %v", err)
	}

	if _, err := verifier.VerifySPDXDetachedVersioned(
		fixtures.SPDXDetachedValid.SBOM,
		fixtures.SPDXDetachedValid.SignatureB64,
		fixtures.SPDXDetachedValid.PublicKeyPEM,
		VerificationV2,
	); err != nil {
		t.Fatalf("valid SPDX contract fixture failed: %v", err)
	}

	if _, err := verifier.VerifySPDXDetachedVersioned(
		fixtures.SPDXDetachedInvalid.SBOM,
		fixtures.SPDXDetachedInvalid.SignatureB64,
		fixtures.SPDXDetachedInvalid.PublicKeyPEM,
		VerificationV2,
	); !errors.Is(err, ErrSignatureFail) {
		t.Fatalf("expected invalid SPDX fixture to fail signature verification, got %v", err)
	}

	if _, err := verifier.VerifyDigest(
		VerifyDigestInput{
			KeyID:         fixtures.DigestValid.KeyID,
			HashAlgorithm: fixtures.DigestValid.HashAlgorithm,
			Digest:        fixtures.DigestValid.DigestB64,
			Signature:     fixtures.DigestValid.SignatureB64,
		},
		VerificationKey{
			KeyID:     fixtures.DigestValid.KeyID,
			Algorithm: fixtures.DigestValid.Algorithm,
			PublicKey: fixtures.DigestValid.PublicKeyPEM,
		},
	); err != nil {
		t.Fatalf("valid digest contract fixture failed: %v", err)
	}

	if _, err := verifier.VerifyDigest(
		VerifyDigestInput{
			KeyID:         fixtures.DigestInvalid.KeyID,
			HashAlgorithm: fixtures.DigestInvalid.HashAlgorithm,
			Digest:        fixtures.DigestInvalid.DigestB64,
			Signature:     fixtures.DigestInvalid.SignatureB64,
		},
		VerificationKey{
			KeyID:     fixtures.DigestInvalid.KeyID,
			Algorithm: fixtures.DigestInvalid.Algorithm,
			PublicKey: fixtures.DigestInvalid.PublicKeyPEM,
		},
	); !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("expected invalid digest fixture to fail verification, got %v", err)
	}
}
