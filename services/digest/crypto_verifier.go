package digestsigning

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/shiftleftcyber/secure-sbom-verifier/verificationkey"
)

type cryptoVerifier struct{}

func NewCryptoVerifier() Verifier {
	return &cryptoVerifier{}
}

func (v *cryptoVerifier) Verify(keyMeta *verificationkey.KeyInfo, digest []byte, signature []byte) error {
	if keyMeta == nil {
		return errors.New("key metadata is required")
	}

	publicKeyPEM := strings.TrimSpace(keyMeta.PublicKey)
	if publicKeyPEM == "" {
		return errors.New("public key not found for key")
	}

	switch strings.ToUpper(strings.TrimSpace(keyMeta.Algorithm)) {
	case "ES256", "ES384", "ES512":
		return verifyECDSADigest(publicKeyPEM, digest, signature)
	default:
		return fmt.Errorf("unsupported signature algorithm: %s", keyMeta.Algorithm)
	}
}

func verifyECDSADigest(publicKeyPEM string, digest []byte, signature []byte) error {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return errors.New("failed to decode PEM block")
	}

	pubKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	pubKey, ok := pubKeyInterface.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("not an ECDSA public key")
	}

	if !ecdsa.VerifyASN1(pubKey, digest, signature) {
		return errors.New("signature is invalid")
	}

	return nil
}
