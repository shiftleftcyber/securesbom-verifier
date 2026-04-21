package utils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

const testPEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC8QySyHcKH0+4LtgXI0tnH0mvPru
g2IV/atfWbB4EFlb0Hstqsth2hadfy5yz4VdIkhCyseUE9p0QkJfomz6cA==
-----END PUBLIC KEY-----`

func TestPEMToBase64AndBack(t *testing.T) {
	b64, err := PEMToBase64(testPEM)
	if err != nil {
		t.Fatalf("PEMToBase64 failed: %v", err)
	}
	if b64 == "" {
		t.Fatal("expected non-empty base64 output")
	}

	pemOut, err := Base64ToPEM(b64)
	if err != nil {
		t.Fatalf("Base64ToPEM failed: %v", err)
	}

	if !strings.Contains(pemOut, "-----BEGIN PUBLIC KEY-----") {
		t.Error("missing BEGIN marker in PEM output")
	}
	if !strings.Contains(pemOut, "-----END PUBLIC KEY-----") {
		t.Error("missing END marker in PEM output")
	}
}

func TestNormalizePublicKeyPEM(t *testing.T) {
	input := "\uFEFF \r\n-----BEGIN PUBLIC KEY-----\rABC\r\nDEF\r\n-----END PUBLIC KEY-----\r  "
	expected := "-----BEGIN PUBLIC KEY-----\nABC\nDEF\n-----END PUBLIC KEY-----\n"

	output := NormalizePublicKeyPEM(input)
	if output != expected {
		t.Errorf("NormalizePublicKeyPEM() = [%q], expected [%q]", output, expected)
	}
}

func TestPEMToBase64_InvalidInput(t *testing.T) {
	if _, err := PEMToBase64("not-a-pem"); err == nil {
		t.Fatal("expected error")
	}
}

func TestBase64ToPEM_InvalidInput(t *testing.T) {
	if _, err := Base64ToPEM("%%%"); err == nil {
		t.Fatal("expected error")
	}
}

func TestDerivePublicKeyFromPrivatePEM(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	privateKeyDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}

	publicKeyPEM, err := DerivePublicKeyFromPrivatePEM(pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyDER,
	}))
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !strings.Contains(string(publicKeyPEM), "BEGIN PUBLIC KEY") {
		t.Fatalf("unexpected public key output: %s", string(publicKeyPEM))
	}
}

func TestDerivePublicKeyFromPrivatePEM_InvalidPEM(t *testing.T) {
	if _, err := DerivePublicKeyFromPrivatePEM([]byte("nope")); err == nil {
		t.Fatal("expected error")
	}
}

func TestDerivePublicKeyFromPrivatePEM_UnsupportedType(t *testing.T) {
	if _, err := DerivePublicKeyFromPrivatePEM(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: []byte("abc"),
	})); err == nil {
		t.Fatal("expected error")
	}
}
