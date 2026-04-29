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

type ContractFixtures struct {
	CycloneDXEmbeddedValid   SignedSBOMFixture
	CycloneDXEmbeddedInvalid SignedSBOMFixture
	SPDXDetachedValid        DetachedSBOMFixture
	SPDXDetachedInvalid      DetachedSBOMFixture
	DigestValid              DigestFixture
	DigestInvalid            DigestFixture
}

type SignedSBOMFixture struct {
	SBOM         []byte
	PublicKeyPEM string
	Version      int
	WantVerified bool
}

type DetachedSBOMFixture struct {
	SBOM         []byte
	SignatureB64 string
	PublicKeyPEM string
	Version      int
	WantVerified bool
}

type DigestFixture struct {
	KeyID         string
	HashAlgorithm string
	DigestB64     string
	SignatureB64  string
	PublicKeyPEM  string
	Algorithm     string
	WantVerified  bool
}

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

func NewContractFixtures(t *testing.T) ContractFixtures {
	t.Helper()

	cdxValid, cdxPublicKey := SignedCycloneDXV2(t, "ES256")
	cdxInvalid := corruptCycloneDXEmbeddedSignature(t, cdxValid)

	spdxSBOM, spdxPublicKey, spdxSignature := SignedSPDXDetachedV2(t)
	spdxInvalidSignature := corruptBase64Signature(spdxSignature)

	digestPrivKey, digestPublicKey := GenerateKeyPair(t)
	digest := sha256.Sum256([]byte("securesbom-verifier contract digest fixture"))
	digestSignature := SignDigestASN1(t, digestPrivKey, digest[:])
	invalidDigest := digest
	invalidDigest[0] ^= 0xff

	return ContractFixtures{
		CycloneDXEmbeddedValid: SignedSBOMFixture{
			SBOM:         cdxValid,
			PublicKeyPEM: cdxPublicKey,
			Version:      2,
			WantVerified: true,
		},
		CycloneDXEmbeddedInvalid: SignedSBOMFixture{
			SBOM:         cdxInvalid,
			PublicKeyPEM: cdxPublicKey,
			Version:      2,
			WantVerified: false,
		},
		SPDXDetachedValid: DetachedSBOMFixture{
			SBOM:         spdxSBOM,
			SignatureB64: spdxSignature,
			PublicKeyPEM: spdxPublicKey,
			Version:      2,
			WantVerified: true,
		},
		SPDXDetachedInvalid: DetachedSBOMFixture{
			SBOM:         spdxSBOM,
			SignatureB64: spdxInvalidSignature,
			PublicKeyPEM: spdxPublicKey,
			Version:      2,
			WantVerified: false,
		},
		DigestValid: DigestFixture{
			KeyID:         "contract-digest-key",
			HashAlgorithm: "sha256",
			DigestB64:     base64.StdEncoding.EncodeToString(digest[:]),
			SignatureB64:  base64.StdEncoding.EncodeToString(digestSignature),
			PublicKeyPEM:  digestPublicKey,
			Algorithm:     "ES256",
			WantVerified:  true,
		},
		DigestInvalid: DigestFixture{
			KeyID:         "contract-digest-key",
			HashAlgorithm: "sha256",
			DigestB64:     base64.StdEncoding.EncodeToString(invalidDigest[:]),
			SignatureB64:  base64.StdEncoding.EncodeToString(digestSignature),
			PublicKeyPEM:  digestPublicKey,
			Algorithm:     "ES256",
			WantVerified:  false,
		},
	}
}

func corruptBase64Signature(signature string) string {
	decoded, err := base64.StdEncoding.DecodeString(signature)
	if err != nil || len(decoded) == 0 {
		return signature
	}
	decoded[len(decoded)-1] ^= 0xff
	return base64.StdEncoding.EncodeToString(decoded)
}

func corruptCycloneDXEmbeddedSignature(t *testing.T, signed []byte) []byte {
	t.Helper()

	var obj map[string]any
	if err := json.Unmarshal(signed, &obj); err != nil {
		t.Fatalf("unmarshal signed CycloneDX fixture: %v", err)
	}

	sigObj, ok := obj["signature"].(map[string]any)
	if !ok {
		t.Fatal("signed CycloneDX fixture missing signature object")
	}

	signature, ok := sigObj["value"].(string)
	if !ok {
		t.Fatal("signed CycloneDX fixture missing signature value")
	}
	sigObj["value"] = corruptBase64Signature(signature)

	corrupted, err := json.Marshal(obj)
	if err != nil {
		t.Fatalf("marshal corrupted CycloneDX fixture: %v", err)
	}
	return corrupted
}
