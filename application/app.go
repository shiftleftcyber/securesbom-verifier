package application

import (
	"fmt"

	"github.com/shiftleftcyber/securesbom-verifier/services"

	sbomValidator "github.com/shiftleftcyber/sbom-validator/v2"
)

type verifierFactory func(string) (services.PublicKeyVerifier, error)

type VerifierApp struct {
	newVerifier verifierFactory
}

func NewVerifierApp() *VerifierApp {
	return &VerifierApp{
		newVerifier: services.NewVerifier,
	}
}

func NewVerifierAppWithFactory(factory func(string) (services.PublicKeyVerifier, error)) *VerifierApp {
	return &VerifierApp{
		newVerifier: factory,
	}
}

func (v *VerifierApp) VerifyCycloneDXEmbeddedVersioned(
	signedSBOM []byte,
	publicKeyPEM string,
	version VerificationVersion,
) (*VerificationResult, error) {
	switch version {
	case VerificationV2:
		return v.VerifyCycloneDXEmbeddedV2(signedSBOM, publicKeyPEM)
	default:
		return v.VerifyCycloneDXEmbeddedV1(signedSBOM, publicKeyPEM)
	}
}

func (v *VerifierApp) VerifySPDXDetachedVersioned(
	sbom []byte,
	signatureB64 string,
	publicKeyPEM string,
	version VerificationVersion,
) (*VerificationResult, error) {
	switch version {
	case VerificationV2:
		return v.VerifySPDXDetachedV2(sbom, signatureB64, publicKeyPEM)
	default:
		return v.VerifySPDXDetachedV1(sbom, signatureB64, publicKeyPEM)
	}
}

func validateSBOM(data []byte, label string) error {
	result, err := sbomValidator.ValidateSBOMData(data)
	if err != nil {
		return fmt.Errorf("failed to validate %s: %w", label, err)
	}
	if !result.IsValid {
		return fmt.Errorf("invalid %s: %v", label, result.ValidationErrors)
	}
	return nil
}

func (v *VerifierApp) verifierForAlgorithm(algorithm string) (services.PublicKeyVerifier, error) {
	verifier, err := v.newVerifier(algorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to create verifier: %w", err)
	}
	return verifier, nil
}
