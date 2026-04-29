package digestsigning

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/shiftleftcyber/securesbom-verifier/verificationkey"
)

type cryptoVerifier struct{}

func NewCryptoVerifier() Verifier {
	return &cryptoVerifier{}
}

func (v *cryptoVerifier) Verify(keyMeta *verificationkey.KeyInfo, digest []byte, signature []byte) error {
	if keyMeta == nil {
		return fmt.Errorf("%w: key metadata is required", ErrInvalidKey)
	}

	publicKeyPEM := strings.TrimSpace(keyMeta.PublicKey)
	if publicKeyPEM == "" {
		return fmt.Errorf("%w: public key not found for key", ErrInvalidKey)
	}

	switch strings.ToUpper(strings.TrimSpace(keyMeta.Algorithm)) {
	case "ES256", "ES384", "ES512":
		return verifyECDSADigest(publicKeyPEM, digest, signature)
	default:
		return fmt.Errorf("%w: unsupported signature algorithm: %s", ErrInvalidKey, keyMeta.Algorithm)
	}
}

func verifyECDSADigest(publicKeyPEM string, digest []byte, signature []byte) error {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return fmt.Errorf("%w: failed to decode PEM block", ErrInvalidKey)
	}

	pubKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("%w: failed to parse public key: %v", ErrInvalidKey, err)
	}

	pubKey, ok := pubKeyInterface.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("%w: not an ECDSA public key", ErrInvalidKey)
	}

	if !ecdsa.VerifyASN1(pubKey, digest, signature) {
		return fmt.Errorf("%w: signature is invalid", ErrVerificationFailed)
	}

	return nil
}
