package services

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"
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

func TestNewVerifier(t *testing.T) {
	verifier, err := NewVerifier("ES256")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if verifier == nil {
		t.Fatal("expected verifier")
	}
}

func TestECDSAVerifier_VerifyWithPublicKey(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	data := `{"hello":"world"}`
	hash := sha256Sum([]byte(data))
	signature, err := ecdsa.SignASN1(rand.Reader, privKey, hash[:])
	if err != nil {
		t.Fatalf("failed to sign data: %v", err)
	}

	verifier := &ECDSAVerifier{alg: "ES256"}
	ok, err := verifier.VerifyWithPublicKey(data, base64.StdEncoding.EncodeToString(signature), generateECDSAPublicKeyPEM(t, &privKey.PublicKey))
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !ok {
		t.Fatal("expected signature to verify")
	}
}

func TestECDSAVerifier_VerifyWithPublicKey_InvalidSignature(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	data := `{"hello":"world"}`
	hash := sha256Sum([]byte(data))
	signature, err := ecdsa.SignASN1(rand.Reader, privKey, hash[:])
	if err != nil {
		t.Fatalf("failed to sign data: %v", err)
	}

	verifier := &ECDSAVerifier{alg: "ES256"}
	ok, err := verifier.VerifyWithPublicKey(data+"!", base64.StdEncoding.EncodeToString(signature), generateECDSAPublicKeyPEM(t, &privKey.PublicKey))
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if ok {
		t.Fatal("expected signature verification failure")
	}
}

func TestNewVerifier_UnsupportedAlgorithm(t *testing.T) {
	verifier, err := NewVerifier("RS256")
	if err == nil || !strings.Contains(err.Error(), "unsupported signature algorithm") {
		t.Fatalf("expected unsupported algorithm error, got verifier=%T err=%v", verifier, err)
	}
}

func TestECDSAVerifier_VerifyWithPublicKey_InvalidPEM(t *testing.T) {
	verifier := &ECDSAVerifier{alg: "ES256"}
	_, err := verifier.VerifyWithPublicKey("{}", "abc", "not-a-pem")
	if err == nil || !strings.Contains(err.Error(), "failed to decode PEM block") {
		t.Fatalf("expected PEM decode error, got %v", err)
	}
}

func TestECDSAVerifier_VerifyWithPublicKey_NotECDSA(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	publicKeyDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal RSA public key: %v", err)
	}
	publicKeyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyDER}))

	verifier := &ECDSAVerifier{alg: "ES256"}
	_, err = verifier.VerifyWithPublicKey("{}", "abc", publicKeyPEM)
	if err == nil || !strings.Contains(err.Error(), "not an ECDSA public key") {
		t.Fatalf("expected non-ECDSA key error, got %v", err)
	}
}

func TestDecodeSigB64Any(t *testing.T) {
	payload := []byte{0x30, 0x45, 0x02}

	encodings := []string{
		base64.StdEncoding.EncodeToString(payload),
		base64.RawStdEncoding.EncodeToString(payload),
		base64.URLEncoding.EncodeToString(payload),
		base64.RawURLEncoding.EncodeToString(payload),
	}

	for _, encoded := range encodings {
		decoded, err := decodeSigB64Any(encoded)
		if err != nil {
			t.Fatalf("expected no error for %q, got %v", encoded, err)
		}
		if string(decoded) != string(payload) {
			t.Fatalf("unexpected decoded payload: %v", decoded)
		}
	}

	if _, err := decodeSigB64Any("%%%"); err == nil {
		t.Fatal("expected decode error")
	}
}

func sha256Sum(data []byte) [32]byte {
	return sha256.Sum256(data)
}
