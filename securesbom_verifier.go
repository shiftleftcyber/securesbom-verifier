package securesbomverifier

import (
	"fmt"

	"github.com/shiftleftcyber/securesbom-verifier/application"
	digestsigning "github.com/shiftleftcyber/securesbom-verifier/services/digest"
	"github.com/shiftleftcyber/securesbom-verifier/verificationkey"
)

type VerificationResult = application.VerificationResult
type VerifyDigestInput = digestsigning.VerifyDigestInput
type VerifyDigestResult = digestsigning.VerifyDigestResult
type VerificationKey = verificationkey.KeyInfo
type KeyInfo = verificationkey.KeyInfo

type VerificationVersion = application.VerificationVersion

const (
	VerificationV1 = application.VerificationV1
	VerificationV2 = application.VerificationV2
)

var (
	ErrInvalidSBOM          = application.ErrInvalidSBOM
	ErrMissingSignature     = application.ErrMissingSig
	ErrSignatureFail        = application.ErrSignatureFail
	ErrKeyNotFound          = application.ErrKeyNotFound
	ErrInvalidHashAlgorithm = digestsigning.ErrInvalidHashAlgorithm
	ErrInvalidDigest        = digestsigning.ErrInvalidDigest
	ErrInvalidKeyID         = digestsigning.ErrInvalidKeyID
	ErrInvalidSignature     = digestsigning.ErrInvalidSignature
	ErrInvalidKey           = digestsigning.ErrInvalidKey
	ErrVerificationFailed   = digestsigning.ErrVerificationFailed
)

type Verifier struct {
	app *application.VerifierApp
}

func NewVerifier() *Verifier {
	return &Verifier{
		app: application.NewVerifierApp(),
	}
}

func (v *Verifier) VerifyCycloneDXEmbeddedVersioned(
	signedSBOM []byte,
	publicKeyPEM string,
	version VerificationVersion,
) (*VerificationResult, error) {
	return v.app.VerifyCycloneDXEmbeddedVersioned(signedSBOM, publicKeyPEM, version)
}

func (v *Verifier) VerifyCycloneDXEmbeddedWithKeyVersioned(
	signedSBOM []byte,
	key VerificationKey,
	version VerificationVersion,
) (*VerificationResult, error) {
	result, err := v.app.VerifyCycloneDXEmbeddedVersioned(signedSBOM, key.PublicKey, version)
	if err != nil {
		return nil, err
	}
	result.KeyID = key.KeyID
	if key.Algorithm != "" {
		result.Algorithm = key.Algorithm
	}
	return result, nil
}

func (v *Verifier) VerifySPDXDetachedVersioned(
	sbom []byte,
	signatureB64 string,
	publicKeyPEM string,
	version VerificationVersion,
) (*VerificationResult, error) {
	return v.app.VerifySPDXDetachedVersioned(sbom, signatureB64, publicKeyPEM, version)
}

func (v *Verifier) VerifySPDXDetachedWithKeyVersioned(
	sbom []byte,
	signatureB64 string,
	key VerificationKey,
	version VerificationVersion,
) (*VerificationResult, error) {
	result, err := v.app.VerifySPDXDetachedVersioned(sbom, signatureB64, key.PublicKey, version)
	if err != nil {
		return nil, err
	}
	result.KeyID = key.KeyID
	if key.Algorithm != "" {
		result.Algorithm = key.Algorithm
	}
	return result, nil
}

func (v *Verifier) VerifyDigest(
	input VerifyDigestInput,
	key VerificationKey,
) (*VerifyDigestResult, error) {
	validated, err := digestsigning.NewValidator().ValidateVerifyDigestRequest(input)
	if err != nil {
		return nil, err
	}

	if key.KeyID != "" && input.KeyID != key.KeyID {
		return nil, fmt.Errorf("%w: request key_id does not match verification key", ErrInvalidKey)
	}

	if err := digestsigning.NewCryptoVerifier().Verify(&key, validated.Digest, validated.Signature); err != nil {
		return nil, fmt.Errorf("failed to verify digest: %w", err)
	}

	return &VerifyDigestResult{
		KeyID:            input.KeyID,
		HashAlgorithm:    validated.HashAlgorithm,
		SigningAlgorithm: key.Algorithm,
		Verified:         true,
		Message:          "signature is valid",
	}, nil
}
