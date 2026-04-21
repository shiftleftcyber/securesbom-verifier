package application

import (
	"errors"
	"fmt"

	digestsbom "github.com/shiftleftcyber/securesbom-verifier/services/sbom"
	"github.com/shiftleftcyber/securesbom-verifier/utils"
)

func (v *VerifierApp) VerifySPDXDetachedV1(sbom []byte, signatureB64 string, publicKeyPEM string) (*VerificationResult, error) {
	return v.verifySPDXDetached(sbom, signatureB64, publicKeyPEM, digestsbom.CanonicalizeUnsignedSBOM)
}

func (v *VerifierApp) VerifySPDXDetachedV2(sbom []byte, signatureB64 string, publicKeyPEM string) (*VerificationResult, error) {
	return v.verifySPDXDetached(sbom, signatureB64, publicKeyPEM, digestsbom.CanonicalizeUnsignedSBOMV2)
}

func (v *VerifierApp) verifySPDXDetached(
	sbom []byte,
	signatureB64 string,
	publicKeyPEM string,
	canonicalize func([]byte) ([]byte, error),
) (*VerificationResult, error) {
	if publicKeyPEM == "" {
		return nil, errors.New("public key is required for verification")
	}

	if err := validateSBOM(sbom, "SPDX SBOM"); err != nil {
		return nil, err
	}

	verifier, err := v.verifierForAlgorithm("ES256")
	if err != nil {
		return nil, err
	}

	canonicalSBOM, err := canonicalize(sbom)
	if err != nil {
		return nil, fmt.Errorf("canonicalization failed: %w", err)
	}

	valid, err := verifier.VerifyWithPublicKey(string(canonicalSBOM), signatureB64, utils.NormalizePublicKeyPEM(publicKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}
	if !valid {
		return nil, ErrSignatureFail
	}

	return &VerificationResult{
		Message:   "SPDX detached signature is valid",
		Algorithm: "ES256",
	}, nil
}
