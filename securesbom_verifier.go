package securesbomverifier

import "github.com/shiftleftcyber/securesbom-verifier/application"

type VerificationResult = application.VerificationResult

type VerificationVersion = application.VerificationVersion

const (
	VerificationV1 = application.VerificationV1
	VerificationV2 = application.VerificationV2
)

var (
	ErrSignatureFail = application.ErrSignatureFail
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

func (v *Verifier) VerifySPDXDetachedVersioned(
	sbom []byte,
	signatureB64 string,
	publicKeyPEM string,
	version VerificationVersion,
) (*VerificationResult, error) {
	return v.app.VerifySPDXDetachedVersioned(sbom, signatureB64, publicKeyPEM, version)
}
