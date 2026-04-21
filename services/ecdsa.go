package services

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
)

type ECDSAVerifier struct {
	alg string
}

func (s *ECDSAVerifier) VerifyWithPublicKey(data string, signature string, publicKeyPEM string) (bool, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return false, errors.New("failed to decode PEM block")
	}

	pubKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false, fmt.Errorf("failed to parse public key: %w", err)
	}

	pubKey, ok := pubKeyInterface.(*ecdsa.PublicKey)
	if !ok {
		return false, errors.New("not an ECDSA public key")
	}

	sigBytes, err := decodeSigB64Any(signature)
	if err != nil {
		return false, fmt.Errorf("failed to decode signature: %w", err)
	}

	hash := sha256.Sum256([]byte(data))
	valid := ecdsa.VerifyASN1(pubKey, hash[:], sigBytes)
	return valid, nil
}

func decodeSigB64Any(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return nil, fmt.Errorf("failed to decode signature: unsupported base64 encoding")
}
