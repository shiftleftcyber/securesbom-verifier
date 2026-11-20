package application

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/shiftleftcyber/securesbom-verifier/attestation"
	sbomsvc "github.com/shiftleftcyber/securesbom-verifier/services/sbom"
	"github.com/shiftleftcyber/securesbom-verifier/testsupport"
	"github.com/shiftleftcyber/securesbom-verifier/verificationkey"
)

const attestationKeyID = "attestation-key"

func detachedCycloneDXSignature(t *testing.T, signed []byte) string {
	t.Helper()

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(signed, &obj); err != nil {
		t.Fatalf("unmarshal signed CycloneDX: %v", err)
	}
	return string(obj["signature"])
}

func TestVerifyAttestationPredicateSignatures(t *testing.T) {
	privKey, publicKeyPEM := testsupport.GenerateKeyPair(t)
	otherKey, _ := testsupport.GenerateKeyPair(t)
	key := verificationkey.KeyInfo{KeyID: attestationKeyID, Algorithm: "ES256", PublicKey: publicKeyPEM}

	cdx := testsupport.FixtureBytes(t, "cyclonedx.json")
	spdx := testsupport.FixtureBytes(t, "spdx.json")
	aiBOM := testsupport.UnsignedAIBOM(t)
	cdxSigned := testsupport.SignedCycloneDXV2WithKey(t, privKey, "ES256")
	cdxSignedByOther := testsupport.SignedCycloneDXV2WithKey(t, otherKey, "ES256")
	aiBOMSigned := testsupport.SignedAIBOMV2WithKey(t, privKey, "ES256")
	aiBOMSignedByOther := testsupport.SignedAIBOMV2WithKey(t, otherKey, "ES256")

	spdxCanonical, err := sbomsvc.CanonicalizeUnsignedSBOMV2(spdx)
	if err != nil {
		t.Fatalf("canonicalize SPDX: %v", err)
	}
	spdxSignature := testsupport.SignMessageB64(t, privKey, spdxCanonical)
	spdxSignatureByOther := testsupport.SignMessageB64(t, otherKey, spdxCanonical)

	cases := []struct {
		name          string
		predicateType string
		predicate     []byte
		detached      string
		wantState     string
		wantErr       error
	}{
		{"cyclonedx unsigned", attestation.PredicateTypeCycloneDX, cdx, "", PredicateSignatureNotPresent, nil},
		{"cyclonedx embedded", attestation.PredicateTypeCycloneDX, cdxSigned, "", PredicateSignatureValid, nil},
		{"cyclonedx embedded by other key", attestation.PredicateTypeCycloneDX, cdxSignedByOther, "", "", attestation.ErrPredicateSignatureInvalid},
		{"cyclonedx embedded and detached", attestation.PredicateTypeCycloneDX, cdxSigned, detachedCycloneDXSignature(t, cdxSigned), "", attestation.ErrPredicateSignatureInvalid},
		{"cyclonedx detached", attestation.PredicateTypeCycloneDX, cdx, detachedCycloneDXSignature(t, cdxSigned), PredicateSignatureValid, nil},
		{"cyclonedx detached by other key", attestation.PredicateTypeCycloneDX, cdx, detachedCycloneDXSignature(t, cdxSignedByOther), "", attestation.ErrPredicateSignatureInvalid},
		{"cyclonedx detached not json", attestation.PredicateTypeCycloneDX, cdx, "not-json", "", attestation.ErrPredicateSignatureInvalid},
		{"spdx unsigned", attestation.PredicateTypeSPDX, spdx, "", PredicateSignatureNotPresent, nil},
		{"spdx detached", attestation.PredicateTypeSPDX, spdx, spdxSignature, PredicateSignatureValid, nil},
		{"spdx detached by other key", attestation.PredicateTypeSPDX, spdx, spdxSignatureByOther, "", attestation.ErrPredicateSignatureInvalid},
		{"ai-sbom unsigned", attestation.PredicateTypeAISBOM, aiBOM, "", PredicateSignatureNotPresent, nil},
		{"ai-sbom embedded", attestation.PredicateTypeAISBOM, aiBOMSigned, "", PredicateSignatureValid, nil},
		{"ai-sbom embedded by other key", attestation.PredicateTypeAISBOM, aiBOMSignedByOther, "", "", attestation.ErrPredicateSignatureInvalid},
		{"ai-sbom detached", attestation.PredicateTypeAISBOM, aiBOM, spdxSignature, "", attestation.ErrPredicateSignatureInvalid},
	}

	app := NewVerifierApp()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			envelope := testsupport.SignedAttestation(t, privKey, attestationKeyID, testsupport.TestSubjects(), tc.predicateType, tc.predicate)
			result, err := app.VerifyAttestation(AttestationInput{
				Envelope:                   envelope,
				ExpectedSHA256:             testsupport.TestSubjectDigest,
				DetachedPredicateSignature: tc.detached,
			}, key)

			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				if result != nil {
					t.Fatalf("result must be nil on failure, got %+v", result)
				}
				return
			}
			if err != nil {
				t.Fatalf("VerifyAttestation: %v", err)
			}
			if result.PredicateSignature != tc.wantState {
				t.Fatalf("PredicateSignature = %q, want %q", result.PredicateSignature, tc.wantState)
			}
			if result.PredicateType != tc.predicateType || result.KeyID != attestationKeyID || result.Message == "" {
				t.Fatalf("unexpected result: %+v", result)
			}
			if result.MatchedSubject.SHA256() != testsupport.TestSubjectDigest || len(result.Predicate) == 0 {
				t.Fatalf("unexpected subject or predicate: %+v", result)
			}
		})
	}
}

func TestVerifyAttestationPropagatesOuterFailures(t *testing.T) {
	privKey, publicKeyPEM := testsupport.GenerateKeyPair(t)
	key := verificationkey.KeyInfo{KeyID: attestationKeyID, PublicKey: publicKeyPEM}
	envelope := testsupport.SignedAttestation(t, privKey, attestationKeyID, testsupport.TestSubjects(), attestation.PredicateTypeCycloneDX, testsupport.FixtureBytes(t, "cyclonedx.json"))

	_, err := NewVerifierApp().VerifyAttestation(AttestationInput{Envelope: envelope}, key)
	if !errors.Is(err, attestation.ErrExpectedDigestRequired) {
		t.Fatalf("err = %v, want ErrExpectedDigestRequired", err)
	}
}

func TestHasTopLevelMemberRejectsInvalidJSON(t *testing.T) {
	if _, err := hasTopLevelMember([]byte(`[`), "signature"); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestHasAIBOMSignature(t *testing.T) {
	if hasAIBOMSignature([]byte(`{`)) {
		t.Fatal("invalid JSON must not report a signature")
	}
	if hasAIBOMSignature([]byte(`{"metadata":{}}`)) {
		t.Fatal("missing signature reported as present")
	}
	if !hasAIBOMSignature([]byte(`{"metadata":{"sbomAuthorSignature":"x"}}`)) {
		t.Fatal("present but malformed signature must be reported as present")
	}
}

func TestEmbedCycloneDXSignatureRejectsInvalidPredicate(t *testing.T) {
	if _, err := embedCycloneDXSignature([]byte(`{`), `{"alg":"ES256"}`); err == nil {
		t.Fatal("expected error for invalid predicate")
	}
}
