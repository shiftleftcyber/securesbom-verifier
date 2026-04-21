package testsupport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	sbomsvc "github.com/shiftleftcyber/securesbom-verifier/services/sbom"
)

func FixtureBytes(t *testing.T, name string) []byte {
	t.Helper()

	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to resolve testsupport file path")
	}

	path := filepath.Join(filepath.Dir(currentFile), "..", "testdata", "fixtures", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

func GenerateKeyPair(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}

	publicKeyDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDER,
	})

	return privKey, string(publicKeyPEM)
}

func PrivateKeyPEM(t *testing.T, privKey *ecdsa.PrivateKey) []byte {
	t.Helper()

	privateKeyDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyDER,
	})
}

func SignMessageB64(t *testing.T, privKey *ecdsa.PrivateKey, data []byte) string {
	t.Helper()

	hash := sha256.Sum256(data)
	signature, err := ecdsa.SignASN1(rand.Reader, privKey, hash[:])
	if err != nil {
		t.Fatalf("sign message: %v", err)
	}

	return base64.StdEncoding.EncodeToString(signature)
}

func SignDigestASN1(t *testing.T, privKey *ecdsa.PrivateKey, digest []byte) []byte {
	t.Helper()

	signature, err := ecdsa.SignASN1(rand.Reader, privKey, digest)
	if err != nil {
		t.Fatalf("sign digest: %v", err)
	}

	return signature
}

func SignedCycloneDXV1(t *testing.T, algorithm string) ([]byte, string) {
	t.Helper()

	sbom := FixtureBytes(t, "cyclonedx.json")
	privKey, publicKeyPEM := GenerateKeyPair(t)
	canonical, err := sbomsvc.CanonicalizeUnsignedSBOM(sbom)
	if err != nil {
		t.Fatalf("canonicalize CycloneDX v1: %v", err)
	}

	signature := SignMessageB64(t, privKey, canonical)

	var obj map[string]any
	if err := json.Unmarshal(sbom, &obj); err != nil {
		t.Fatalf("unmarshal CycloneDX fixture: %v", err)
	}

	obj["signature"] = map[string]any{
		"alg":   algorithm,
		"value": signature,
	}

	signed, err := json.Marshal(obj)
	if err != nil {
		t.Fatalf("marshal signed CycloneDX v1: %v", err)
	}

	return signed, publicKeyPEM
}

func SignedCycloneDXV2(t *testing.T, algorithm string) ([]byte, string) {
	t.Helper()

	sbom := FixtureBytes(t, "cyclonedx.json")
	privKey, publicKeyPEM := GenerateKeyPair(t)

	var obj map[string]any
	if err := json.Unmarshal(sbom, &obj); err != nil {
		t.Fatalf("unmarshal CycloneDX fixture: %v", err)
	}

	obj["signature"] = map[string]any{
		"alg": algorithm,
	}

	withoutValue, err := json.Marshal(obj)
	if err != nil {
		t.Fatalf("marshal CycloneDX v2 without value: %v", err)
	}

	canonical, err := sbomsvc.CanonicalizeForJSF(withoutValue)
	if err != nil {
		t.Fatalf("canonicalize CycloneDX v2: %v", err)
	}

	signature := SignMessageB64(t, privKey, canonical)
	obj["signature"] = map[string]any{
		"alg":   algorithm,
		"value": signature,
	}

	signed, err := json.Marshal(obj)
	if err != nil {
		t.Fatalf("marshal signed CycloneDX v2: %v", err)
	}

	return signed, publicKeyPEM
}

func SignedSPDXDetachedV1(t *testing.T) ([]byte, string, string) {
	t.Helper()

	sbom := FixtureBytes(t, "spdx.json")
	privKey, publicKeyPEM := GenerateKeyPair(t)
	canonical, err := sbomsvc.CanonicalizeUnsignedSBOM(sbom)
	if err != nil {
		t.Fatalf("canonicalize SPDX v1: %v", err)
	}

	return sbom, publicKeyPEM, SignMessageB64(t, privKey, canonical)
}

func SignedSPDXDetachedV2(t *testing.T) ([]byte, string, string) {
	t.Helper()

	sbom := FixtureBytes(t, "spdx.json")
	privKey, publicKeyPEM := GenerateKeyPair(t)
	canonical, err := sbomsvc.CanonicalizeUnsignedSBOMV2(sbom)
	if err != nil {
		t.Fatalf("canonicalize SPDX v2: %v", err)
	}

	return sbom, publicKeyPEM, SignMessageB64(t, privKey, canonical)
}
