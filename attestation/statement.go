package attestation

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Statement is an in-toto Statement v1.
type Statement struct {
	Type          string          `json:"_type"`
	Subject       []Subject       `json:"subject"`
	PredicateType string          `json:"predicateType"`
	Predicate     json.RawMessage `json:"predicate"`
}

// Subject identifies one artifact by name and digest.
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// SHA256 returns the subject's sha256 digest.
func (s Subject) SHA256() string {
	return s.Digest[DigestAlgorithmSHA256]
}

// NormalizeSHA256 validates a sha256 digest given as 64 hex characters,
// optionally prefixed with "sha256:", and returns it as lowercase hex.
func NormalizeSHA256(value string) (string, error) {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, DigestAlgorithmSHA256+":")
	value = strings.ToLower(value)

	if len(value) != 64 {
		return "", fmt.Errorf("%w: expected 64 hex characters", ErrInvalidDigest)
	}
	raw, err := hex.DecodeString(value)
	if err != nil {
		return "", fmt.Errorf("%w: not hexadecimal", ErrInvalidDigest)
	}
	if bytes.Equal(raw, make([]byte, len(raw))) {
		return "", fmt.Errorf("%w: all-zero digest", ErrInvalidDigest)
	}
	return value, nil
}

// ValidateSubjects enforces the profile's subject rules: 1 to MaxSubjects
// entries; each with a printable name of 1 to MaxSubjectNameLength bytes and a
// digest map holding exactly one sha256 value in lowercase hex; no duplicate
// digests.
func ValidateSubjects(subjects []Subject) error {
	if len(subjects) == 0 {
		return fmt.Errorf("%w: at least one subject is required", ErrInvalidSubject)
	}
	if len(subjects) > MaxSubjects {
		return fmt.Errorf("%w: at most %d subjects are allowed", ErrInvalidSubject, MaxSubjects)
	}

	seen := make(map[string]struct{}, len(subjects))
	for i, subject := range subjects {
		if err := validateSubjectName(subject.Name); err != nil {
			return fmt.Errorf("%w: subject %d: %v", ErrInvalidSubject, i, err)
		}
		if len(subject.Digest) != 1 {
			return fmt.Errorf("%w: subject %d: digest must contain exactly one sha256 entry", ErrInvalidSubject, i)
		}
		value, ok := subject.Digest[DigestAlgorithmSHA256]
		if !ok {
			return fmt.Errorf("%w: subject %d: only sha256 digests are supported", ErrInvalidSubject, i)
		}
		normalized, err := NormalizeSHA256(value)
		if err != nil || normalized != value {
			return fmt.Errorf("%w: subject %d: sha256 must be 64 lowercase hex characters", ErrInvalidSubject, i)
		}
		if _, dup := seen[value]; dup {
			return fmt.Errorf("%w: subject %d: duplicate digest", ErrInvalidSubject, i)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validateSubjectName(name string) error {
	if name == "" {
		return fmt.Errorf("name is required")
	}
	if len(name) > MaxSubjectNameLength {
		return fmt.Errorf("name exceeds %d bytes", MaxSubjectNameLength)
	}
	if !utf8.ValidString(name) {
		return fmt.Errorf("name must be valid UTF-8")
	}
	for _, r := range name {
		if !unicode.IsPrint(r) {
			return fmt.Errorf("name must contain printable characters only")
		}
	}
	return nil
}

// BuildStatementPayload validates the inputs and returns the canonical
// payload bytes of a Statement: the exact bytes that go into the DSSE
// envelope and PAE.
func BuildStatementPayload(subjects []Subject, predicateType string, predicate []byte) ([]byte, error) {
	if err := ValidateSubjects(subjects); err != nil {
		return nil, err
	}
	if !IsSupportedPredicateType(predicateType) {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedPredicateType, predicateType)
	}
	if !isJSONObject(predicate) {
		return nil, fmt.Errorf("%w: predicate must be a JSON object", ErrInvalidStatement)
	}

	raw, err := json.Marshal(Statement{
		Type:          StatementType,
		Subject:       subjects,
		PredicateType: predicateType,
		Predicate:     json.RawMessage(predicate),
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidStatement, err)
	}
	return Canonicalize(raw)
}

// ParseStatement decodes a payload into a Statement, rejecting unknown fields,
// a wrong _type, and an empty predicate.
func ParseStatement(payload []byte) (*Statement, error) {
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()

	var statement Statement
	if err := dec.Decode(&statement); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidStatement, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%w: trailing data after statement", ErrInvalidStatement)
	}
	if statement.Type != StatementType {
		return nil, fmt.Errorf("%w: _type must be %s", ErrInvalidStatement, StatementType)
	}
	if statement.PredicateType == "" {
		return nil, fmt.Errorf("%w: predicateType is required", ErrInvalidStatement)
	}
	if !isJSONObject(statement.Predicate) {
		return nil, fmt.Errorf("%w: predicate must be a JSON object", ErrInvalidStatement)
	}
	if err := ValidateSubjects(statement.Subject); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidStatement, err)
	}
	return &statement, nil
}

// IsSupportedPredicateType reports whether the profile accepts predicateType.
func IsSupportedPredicateType(predicateType string) bool {
	switch predicateType {
	case PredicateTypeCycloneDX, PredicateTypeSPDX, PredicateTypeAISBOM:
		return true
	default:
		return false
	}
}

// PredicateTypeForSBOMType maps an sbom-validator SBOM type ("CycloneDX",
// "SPDX", "AI-SBOM") to its predicate type.
func PredicateTypeForSBOMType(sbomType string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(sbomType)) {
	case "cyclonedx":
		return PredicateTypeCycloneDX, nil
	case "spdx":
		return PredicateTypeSPDX, nil
	case "ai-sbom":
		return PredicateTypeAISBOM, nil
	default:
		return "", fmt.Errorf("%w: no predicate type for SBOM type %q", ErrUnsupportedPredicateType, sbomType)
	}
}

func isJSONObject(data []byte) bool {
	trimmed := bytes.TrimSpace(data)
	return len(trimmed) > 1 && trimmed[0] == '{' && json.Valid(trimmed)
}
