package attestation

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/shiftleftcyber/securesbom-verifier/services"
	"github.com/shiftleftcyber/securesbom-verifier/utils"
	"github.com/shiftleftcyber/securesbom-verifier/verificationkey"

	sbomValidator "github.com/shiftleftcyber/sbom-validator/v2"
)

// VerifiedEnvelope is the result of a successful outer verification. The
// predicate is only exposed after every outer check has passed.
type VerifiedEnvelope struct {
	KeyID          string
	Algorithm      string
	PredicateType  string
	SBOMType       string
	Subjects       []Subject
	MatchedSubject Subject
	Predicate      []byte
	PayloadSHA256  string
}

// VerifyEnvelope runs the outer checks of the profile and stops at the first
// failure, returning an error that wraps the sentinel for that check:
//
//  1. expected digest present and well-formed (ErrExpectedDigestRequired)
//  2. envelope shape (ErrInvalidEnvelope)
//  3. signature key ID matches key.KeyID when set (ErrKeyMismatch)
//  4. signature over PAE verifies with key (ErrSignatureInvalid)
//  5. payload is canonical JSON (ErrPayloadNotCanonical)
//  6. Statement shape and subjects (ErrInvalidStatement)
//  7. predicate type supported and matching the predicate (ErrUnsupportedPredicateType)
//  8. some subject's sha256 equals the expected digest (ErrSubjectMismatch)
//
// Verifying a signature embedded in the predicate is left to the caller.
func VerifyEnvelope(envelopeJSON []byte, key verificationkey.KeyInfo, expectedSHA256 string) (*VerifiedEnvelope, error) {
	if strings.TrimSpace(expectedSHA256) == "" {
		return nil, ErrExpectedDigestRequired
	}
	expected, err := NormalizeSHA256(expectedSHA256)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrExpectedDigestRequired, err)
	}

	env, payload, err := ParseEnvelope(envelopeJSON)
	if err != nil {
		return nil, err
	}
	sig := env.Signatures[0]
	if key.KeyID != "" && sig.KeyID != key.KeyID {
		return nil, ErrKeyMismatch
	}

	algorithm := strings.TrimSpace(key.Algorithm)
	if algorithm == "" {
		algorithm = "ES256"
	}
	if err := verifySignature(algorithm, key.PublicKey, PAE(env.PayloadType, payload), sig.Sig); err != nil {
		return nil, err
	}

	if !IsCanonical(payload) {
		return nil, ErrPayloadNotCanonical
	}

	statement, err := ParseStatement(payload)
	if err != nil {
		return nil, err
	}
	if !IsSupportedPredicateType(statement.PredicateType) {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedPredicateType, statement.PredicateType)
	}
	sbomType, err := predicateSBOMType(statement.Predicate, statement.PredicateType)
	if err != nil {
		return nil, err
	}

	matched, ok := matchSubject(statement.Subject, expected)
	if !ok {
		return nil, ErrSubjectMismatch
	}

	sum := sha256.Sum256(payload)
	return &VerifiedEnvelope{
		KeyID:          sig.KeyID,
		Algorithm:      algorithm,
		PredicateType:  statement.PredicateType,
		SBOMType:       sbomType,
		Subjects:       statement.Subject,
		MatchedSubject: matched,
		Predicate:      []byte(statement.Predicate),
		PayloadSHA256:  hex.EncodeToString(sum[:]),
	}, nil
}

func verifySignature(algorithm, publicKeyPEM string, pae []byte, sigB64 string) error {
	if strings.TrimSpace(publicKeyPEM) == "" {
		return fmt.Errorf("%w: public key is required", ErrSignatureInvalid)
	}
	verifier, err := services.NewVerifier(algorithm)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSignatureInvalid, err)
	}
	valid, err := verifier.VerifyWithPublicKey(string(pae), sigB64, utils.NormalizePublicKeyPEM(publicKeyPEM))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSignatureInvalid, err)
	}
	if !valid {
		return ErrSignatureInvalid
	}
	return nil
}

// predicateSBOMType validates the predicate as an SBOM and checks that its
// format matches the declared predicate type.
func predicateSBOMType(predicate []byte, predicateType string) (string, error) {
	result, err := sbomValidator.ValidateSBOMData(predicate)
	if err != nil || result == nil || !result.IsValid {
		return "", fmt.Errorf("%w: predicate is not a valid SBOM", ErrUnsupportedPredicateType)
	}
	want, err := PredicateTypeForSBOMType(result.SBOMType)
	if err != nil {
		return "", err
	}
	if want != predicateType {
		return "", fmt.Errorf("%w: predicateType %s does not match a %s predicate", ErrUnsupportedPredicateType, predicateType, result.SBOMType)
	}
	return result.SBOMType, nil
}

func matchSubject(subjects []Subject, expected string) (Subject, bool) {
	for _, subject := range subjects {
		if subject.SHA256() == expected {
			return subject, true
		}
	}
	return Subject{}, false
}
