package digestsigning

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

type HashSpec struct {
	Name      string
	DigestLen int
}

var supportedHashes = map[string]HashSpec{
	"sha256": {Name: "sha256", DigestLen: 32},
}

var (
	ErrInvalidHashAlgorithm = errors.New("invalid hash algorithm")
	ErrInvalidDigest        = errors.New("invalid digest")
	ErrInvalidKeyID         = errors.New("invalid key_id")
	ErrInvalidSignature     = errors.New("invalid signature")
	ErrInvalidKey           = errors.New("invalid verification key")
	ErrVerificationFailed   = errors.New("verification failed")
)

type ValidatedDigest struct {
	HashAlgorithm string
	Digest        []byte
}

type ValidatedVerifyDigest struct {
	HashAlgorithm string
	Digest        []byte
	Signature     []byte
}

type validator struct{}

func NewValidator() Validator {
	return &validator{}
}

func (v *validator) ValidateVerifyDigestRequest(req VerifyDigestInput) (*ValidatedVerifyDigest, error) {
	if strings.TrimSpace(req.KeyID) == "" {
		return nil, fmt.Errorf("%w: key_id is required", ErrInvalidKeyID)
	}

	spec, decodedDigest, err := validateDigest(req.HashAlgorithm, req.Digest)
	if err != nil {
		return nil, err
	}

	decodedSignature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.Signature))
	if err != nil {
		return nil, fmt.Errorf("%w: signature must be valid base64", ErrInvalidSignature)
	}
	if len(decodedSignature) == 0 {
		return nil, fmt.Errorf("%w: signature is required", ErrInvalidSignature)
	}

	return &ValidatedVerifyDigest{
		HashAlgorithm: spec.Name,
		Digest:        decodedDigest,
		Signature:     decodedSignature,
	}, nil
}

func getHashSpec(name string) (HashSpec, bool) {
	spec, ok := supportedHashes[strings.ToLower(strings.TrimSpace(name))]
	return spec, ok
}

func validateDigest(hashAlgorithm, digest string) (HashSpec, []byte, error) {
	spec, ok := getHashSpec(hashAlgorithm)
	if !ok {
		return HashSpec{}, nil, fmt.Errorf("%w: unsupported hash algorithm", ErrInvalidHashAlgorithm)
	}

	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(digest))
	if err != nil {
		return HashSpec{}, nil, fmt.Errorf("%w: digest must be valid base64", ErrInvalidDigest)
	}

	if len(decoded) != spec.DigestLen {
		return HashSpec{}, nil, fmt.Errorf("%w: %s digest must be %d bytes", ErrInvalidDigest, spec.Name, spec.DigestLen)
	}

	return spec, decoded, nil
}
