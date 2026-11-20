// Package attestation implements the SecureSBOM attestation signing profile,
// securesbom-attestation-v1: an in-toto Statement v1 whose predicate is an
// SBOM, serialized as RFC 8785 (JCS) canonical JSON and signed inside a DSSE
// envelope.
//
// The package holds everything both sides of the profile must agree on: the
// constants, the Statement and envelope types, subject rules, canonical
// encoding, DSSE pre-authentication encoding (PAE), and outer envelope
// verification. Signers (the SecureSBOM API) build payloads with
// BuildStatementPayload and PAE; verifiers call VerifyEnvelope.
package attestation

import "errors"

const (
	// Profile names the signing profile implemented by this package.
	Profile = "securesbom-attestation-v1"

	// PayloadType is the only DSSE payloadType the profile accepts.
	PayloadType = "application/vnd.in-toto+json"

	// EnvelopeMediaType is the media type of a serialized DSSE envelope.
	EnvelopeMediaType = "application/vnd.dsse.envelope.v1+json"

	// StatementType is the in-toto Statement v1 type URI.
	StatementType = "https://in-toto.io/Statement/v1"

	// PredicateTypeCycloneDX is used for CycloneDX SBOM predicates.
	PredicateTypeCycloneDX = "https://cyclonedx.org/bom"

	// PredicateTypeSPDX is used for SPDX SBOM predicates.
	PredicateTypeSPDX = "https://spdx.dev/Document"

	// PredicateTypeAISBOM is used for SecureSBOM AI-SBOM predicates. AI-SBOM
	// is not a CycloneDX document, so it gets its own predicate type.
	PredicateTypeAISBOM = "https://shiftleftcyber.io/attestation/ai-sbom/v1"

	// DigestAlgorithmSHA256 is the only subject digest algorithm accepted.
	DigestAlgorithmSHA256 = "sha256"

	// MaxSubjects caps the number of subjects in one Statement.
	MaxSubjects = 64

	// MaxSubjectNameLength caps a subject name, in bytes.
	MaxSubjectNameLength = 512

	// maxSafeInteger is the largest integer an IEEE 754 double represents
	// exactly. RFC 8785 serializes numbers as doubles, so larger integer
	// literals would change silently; the profile rejects them instead.
	maxSafeInteger = 1 << 53
)

// Sentinel errors. Each maps to one failure code of the profile so callers
// can report a distinct, stable result for every check.
var (
	ErrInvalidEnvelope           = errors.New("invalid attestation envelope")
	ErrKeyMismatch               = errors.New("attestation key does not match")
	ErrSignatureInvalid          = errors.New("attestation signature is invalid")
	ErrPayloadNotCanonical       = errors.New("attestation payload is not canonical JSON")
	ErrInvalidStatement          = errors.New("invalid in-toto statement")
	ErrUnsupportedPredicateType  = errors.New("unsupported predicate type")
	ErrExpectedDigestRequired    = errors.New("expected subject digest is required")
	ErrSubjectMismatch           = errors.New("no attestation subject matches the expected digest")
	ErrInvalidSubject            = errors.New("invalid attestation subject")
	ErrInvalidDigest             = errors.New("invalid sha256 digest")
	ErrNonCanonicalizableJSON    = errors.New("JSON cannot be canonicalized without changing it")
	ErrPredicateSignatureInvalid = errors.New("predicate signature is invalid")
)
