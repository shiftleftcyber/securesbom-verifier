package application

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/shiftleftcyber/securesbom-verifier/attestation"
	"github.com/shiftleftcyber/securesbom-verifier/verificationkey"
)

// Predicate signature states reported in AttestationResult.PredicateSignature.
const (
	PredicateSignatureValid      = "valid"
	PredicateSignatureNotPresent = "not_present"
)

// AttestationInput is a DSSE attestation to verify.
type AttestationInput struct {
	// Envelope is the DSSE envelope JSON.
	Envelope []byte
	// ExpectedSHA256 is the artifact digest the caller resolved independently,
	// as 64 hex characters, optionally prefixed with "sha256:".
	ExpectedSHA256 string
	// DetachedPredicateSignature optionally carries a detached signature over
	// the predicate: base64 for SPDX, the JSF signature object JSON for
	// CycloneDX.
	DetachedPredicateSignature string
}

// AttestationResult describes a verified attestation.
type AttestationResult struct {
	Message            string                `json:"message"`
	KeyID              string                `json:"key_id,omitempty"`
	Algorithm          string                `json:"algorithm,omitempty"`
	PredicateType      string                `json:"predicate_type"`
	MatchedSubject     attestation.Subject   `json:"matched_subject"`
	Subjects           []attestation.Subject `json:"subjects"`
	PredicateSignature string                `json:"predicate_signature"`
	PayloadSHA256      string                `json:"payload_sha256"`
	Predicate          json.RawMessage       `json:"-"`
}

// VerifyAttestation runs the outer profile checks and then verifies the
// predicate's own signature: always when one is embedded, and when the caller
// supplies a detached one.
func (v *VerifierApp) VerifyAttestation(input AttestationInput, key verificationkey.KeyInfo) (*AttestationResult, error) {
	verified, err := attestation.VerifyEnvelope(input.Envelope, key, input.ExpectedSHA256)
	if err != nil {
		return nil, err
	}

	state, err := v.verifyPredicateSignature(verified, strings.TrimSpace(input.DetachedPredicateSignature), key.PublicKey)
	if err != nil {
		return nil, err
	}

	return &AttestationResult{
		Message:            "attestation is valid",
		KeyID:              verified.KeyID,
		Algorithm:          verified.Algorithm,
		PredicateType:      verified.PredicateType,
		MatchedSubject:     verified.MatchedSubject,
		Subjects:           verified.Subjects,
		PredicateSignature: state,
		PayloadSHA256:      verified.PayloadSHA256,
		Predicate:          json.RawMessage(verified.Predicate),
	}, nil
}

func (v *VerifierApp) verifyPredicateSignature(verified *attestation.VerifiedEnvelope, detached, publicKeyPEM string) (string, error) {
	predicate := verified.Predicate

	switch verified.PredicateType {
	case attestation.PredicateTypeCycloneDX:
		embedded, err := hasTopLevelMember(predicate, signatureProperty)
		if err != nil {
			return "", fmt.Errorf("%w: %v", attestation.ErrPredicateSignatureInvalid, err)
		}
		switch {
		case embedded && detached != "":
			return "", fmt.Errorf("%w: predicate has an embedded signature and a detached one was also supplied", attestation.ErrPredicateSignatureInvalid)
		case embedded:
			return predicateResult(v.VerifyCycloneDXEmbeddedV2(predicate, publicKeyPEM))
		case detached != "":
			signed, err := embedCycloneDXSignature(predicate, detached)
			if err != nil {
				return "", fmt.Errorf("%w: %v", attestation.ErrPredicateSignatureInvalid, err)
			}
			return predicateResult(v.VerifyCycloneDXEmbeddedV2(signed, publicKeyPEM))
		}

	case attestation.PredicateTypeAISBOM:
		embedded := hasAIBOMSignature(predicate)
		if detached != "" {
			// Detached AI-SBOM signatures are not part of the profile.
			return "", fmt.Errorf("%w: AI-SBOM predicates do not support detached signatures", attestation.ErrPredicateSignatureInvalid)
		}
		if embedded {
			return predicateResult(v.VerifyAIBOMEmbeddedV2(predicate, publicKeyPEM))
		}

	case attestation.PredicateTypeSPDX:
		if detached != "" {
			return predicateResult(v.VerifySPDXDetachedV2(predicate, detached, publicKeyPEM))
		}
	}

	return PredicateSignatureNotPresent, nil
}

func predicateResult(_ *VerificationResult, err error) (string, error) {
	if err != nil {
		return "", fmt.Errorf("%w: %v", attestation.ErrPredicateSignatureInvalid, err)
	}
	return PredicateSignatureValid, nil
}

func hasTopLevelMember(document []byte, name string) (bool, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(document, &obj); err != nil {
		return false, err
	}
	_, ok := obj[name]
	return ok, nil
}

// hasAIBOMSignature reports whether metadata.sbomAuthorSignature is present at
// all; a present but malformed signature then fails verification instead of
// being reported as absent.
func hasAIBOMSignature(document []byte) bool {
	var obj struct {
		Metadata map[string]json.RawMessage `json:"metadata"`
	}
	if err := json.Unmarshal(document, &obj); err != nil {
		return false
	}
	_, ok := obj.Metadata[aiBOMSignatureProperty]
	return ok
}

// embedCycloneDXSignature places a detached JSF signature object back into an
// unsigned CycloneDX document so the embedded verifier can check it.
func embedCycloneDXSignature(predicate []byte, signatureJSON string) ([]byte, error) {
	var signature map[string]any
	if err := json.Unmarshal([]byte(signatureJSON), &signature); err != nil {
		return nil, errors.New("detached CycloneDX signature must be a JSON signature object")
	}

	var obj map[string]any
	dec := json.NewDecoder(bytes.NewReader(predicate))
	dec.UseNumber()
	if err := dec.Decode(&obj); err != nil {
		return nil, fmt.Errorf("invalid predicate JSON: %w", err)
	}
	obj[signatureProperty] = signature

	return json.Marshal(obj)
}
