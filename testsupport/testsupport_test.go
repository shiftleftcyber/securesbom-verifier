package testsupport

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

func TestFixtureBytes(t *testing.T) {
	data := FixtureBytes(t, "cyclonedx.json")
	if !strings.Contains(string(data), `"bomFormat": "CycloneDX"`) {
		t.Fatalf("unexpected fixture contents: %s", string(data))
	}
}

func TestGenerateKeyPairAndPrivateKeyPEM(t *testing.T) {
	privKey, publicKeyPEM := GenerateKeyPair(t)
	if publicKeyPEM == "" {
		t.Fatal("expected public key PEM")
	}

	privateKeyPEM := PrivateKeyPEM(t, privKey)
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		t.Fatal("expected PEM block")
	}
	if _, err := x509.ParseECPrivateKey(block.Bytes); err != nil {
		t.Fatalf("expected valid EC private key, got %v", err)
	}
}

func TestSignHelpers(t *testing.T) {
	privKey, _ := GenerateKeyPair(t)
	message := []byte(`{"hello":"world"}`)
	signature := SignMessageB64(t, privKey, message)
	if signature == "" {
		t.Fatal("expected signature")
	}

	digest := sha256Sum(message)
	digestSignature := SignDigestASN1(t, privKey, digest[:])
	if len(digestSignature) == 0 {
		t.Fatal("expected digest signature")
	}
}

func TestSignedFixtures(t *testing.T) {
	signedV1, pub1 := SignedCycloneDXV1(t, "ES256")
	if len(signedV1) == 0 || pub1 == "" {
		t.Fatal("expected signed CycloneDX v1 fixture")
	}

	signedV2, pub2 := SignedCycloneDXV2(t, "ES256")
	if len(signedV2) == 0 || pub2 == "" {
		t.Fatal("expected signed CycloneDX v2 fixture")
	}

	sbomV1, pub3, sig1 := SignedSPDXDetachedV1(t)
	if len(sbomV1) == 0 || pub3 == "" || sig1 == "" {
		t.Fatal("expected signed SPDX v1 fixture")
	}

	sbomV2, pub4, sig2 := SignedSPDXDetachedV2(t)
	if len(sbomV2) == 0 || pub4 == "" || sig2 == "" {
		t.Fatal("expected signed SPDX v2 fixture")
	}
}

func sha256Sum(data []byte) [32]byte {
	return sha256.Sum256(data)
}
