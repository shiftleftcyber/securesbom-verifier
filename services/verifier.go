package services

import "errors"

type PublicKeyVerifier interface {
	VerifyWithPublicKey(data string, signature string, publicKeyPEM string) (bool, error)
}

func NewVerifier(alg string) (PublicKeyVerifier, error) {
	switch alg {
	case "ES256", "ES384", "ES512":
		return &ECDSAVerifier{alg: alg}, nil
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "Ed25519":
		return nil, errors.New("unsupported signature algorithm")
	default:
		return nil, errors.New("unsupported signature algorithm")
	}
}
