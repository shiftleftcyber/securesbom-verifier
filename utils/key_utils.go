package utils

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

func PEMToBase64(pemKey string) (string, error) {
	block, _ := pem.Decode([]byte(pemKey))
	if block == nil {
		return "", errors.New("failed to decode PEM block")
	}

	return encodeToBase64(block.Bytes), nil
}

func Base64ToPEM(b64 string) (string, error) {
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", err
	}

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}

	pemBytes := pem.EncodeToMemory(block)
	if pemBytes == nil {
		return "", errors.New("failed to encode PEM")
	}

	return string(pemBytes), nil
}

func encodeToBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func DerivePublicKeyFromPrivatePEM(privateKeyPEM []byte) ([]byte, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, errors.New("invalid PEM: could not decode")
	}

	if block.Type != "EC PRIVATE KEY" {
		return nil, fmt.Errorf("unsupported key type: %s", block.Type)
	}

	privKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse EC private key: %w", err)
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})
	return pubPEM, nil
}

func NormalizePublicKeyPEM(pemValue string) string {
	pemValue = strings.TrimPrefix(pemValue, "\uFEFF")
	pemValue = strings.ReplaceAll(pemValue, "\r\n", "\n")
	pemValue = strings.ReplaceAll(pemValue, "\r", "\n")
	pemValue = strings.TrimSpace(pemValue)

	if !strings.HasSuffix(pemValue, "\n") {
		pemValue += "\n"
	}

	return pemValue
}
