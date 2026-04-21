package application

import "errors"

const signatureProperty = "signature"

var (
	ErrInvalidSBOM   = errors.New("invalid SBOM format")
	ErrMissingSig    = errors.New("missing or invalid signature object")
	ErrSignatureFail = errors.New("signature verification failed")
	ErrKeyNotFound   = errors.New("key not found")
)

type VerificationResult struct {
	Message   string `json:"message"`
	KeyID     string `json:"key_id,omitempty"`
	Algorithm string `json:"algorithm,omitempty"`
}

type VerificationVersion int

const (
	VerificationV1 VerificationVersion = iota
	VerificationV2
)
