package digestsigning

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/shiftleftcyber/secure-sbom-verifier/verificationkey"
)

func generateECDSAPublicKeyPEM(t *testing.T, pubKey *ecdsa.PublicKey) string {
	t.Helper()

	publicKeyDER, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}

	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDER,
	}))
}

func TestCryptoVerifier_Verify(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	digest := []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
	}

	signature, err := ecdsa.SignASN1(rand.Reader, privKey, digest)
	if err != nil {
		t.Fatalf("failed to sign digest: %v", err)
	}

	verifier := NewCryptoVerifier()
	keyMeta := &verificationkey.KeyInfo{
		KeyID:     "key-123",
		Algorithm: "ES256",
		PublicKey: generateECDSAPublicKeyPEM(t, &privKey.PublicKey),
	}

	if err := verifier.Verify(keyMeta, digest, signature); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestCryptoVerifier_Verify_InvalidSignature(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	digest := make([]byte, 32)
	signature, err := ecdsa.SignASN1(rand.Reader, privKey, digest)
	if err != nil {
		t.Fatalf("failed to sign digest: %v", err)
	}

	digest[0] = 0xff

	verifier := NewCryptoVerifier()
	err = verifier.Verify(&verificationkey.KeyInfo{
		KeyID:     "key-123",
		Algorithm: "ES256",
		PublicKey: generateECDSAPublicKeyPEM(t, &privKey.PublicKey),
	}, digest, signature)
	if err == nil || !strings.Contains(err.Error(), "signature is invalid") {
		t.Fatalf("expected invalid signature error, got %v", err)
	}
}

func TestCryptoVerifier_Verify_UnsupportedAlgorithm(t *testing.T) {
	verifier := NewCryptoVerifier()
	err := verifier.Verify(&verificationkey.KeyInfo{
		KeyID:     "key-123",
		Algorithm: "RS256",
		PublicKey: "pem",
	}, make([]byte, 32), []byte{0x01})
	if err == nil || !strings.Contains(err.Error(), "unsupported signature algorithm") {
		t.Fatalf("expected unsupported algorithm error, got %v", err)
	}
}

func TestCryptoVerifier_Verify_NilKeyMetadata(t *testing.T) {
	verifier := NewCryptoVerifier()
	err := verifier.Verify(nil, make([]byte, 32), []byte{0x01})
	if err == nil || !strings.Contains(err.Error(), "key metadata is required") {
		t.Fatalf("expected key metadata error, got %v", err)
	}
}

func TestCryptoVerifier_Verify_MissingPublicKey(t *testing.T) {
	verifier := NewCryptoVerifier()
	err := verifier.Verify(&verificationkey.KeyInfo{Algorithm: "ES256"}, make([]byte, 32), []byte{0x01})
	if err == nil || !strings.Contains(err.Error(), "public key not found") {
		t.Fatalf("expected public key error, got %v", err)
	}
}

func TestVerifyECDSADigest_InvalidPEM(t *testing.T) {
	err := verifyECDSADigest("not-a-pem", make([]byte, 32), []byte{0x01})
	if err == nil || !strings.Contains(err.Error(), "failed to decode PEM block") {
		t.Fatalf("expected PEM decode error, got %v", err)
	}
}
