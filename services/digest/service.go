package digestsigning

import (
	"context"
	"fmt"

	"github.com/shiftleftcyber/secure-sbom-verifier/verificationkey"
)

type Service interface {
	VerifyDigest(ctx context.Context, input VerifyDigestInput) (*VerifyDigestResult, error)
}

type Validator interface {
	ValidateVerifyDigestRequest(req VerifyDigestInput) (*ValidatedVerifyDigest, error)
}

type KeyMetadataStore interface {
	GetKeyMetadata(ctx context.Context, keyID string) (*verificationkey.KeyInfo, error)
}

type Verifier interface {
	Verify(keyMeta *verificationkey.KeyInfo, digest []byte, signature []byte) error
}

type service struct {
	validator Validator
	keys      KeyMetadataStore
	verifier  Verifier
}

func NewService(validator Validator, keys KeyMetadataStore, verifier Verifier) Service {
	return &service{
		validator: validator,
		keys:      keys,
		verifier:  verifier,
	}
}

type VerifyDigestInput struct {
	KeyID         string
	HashAlgorithm string
	Digest        string
	Signature     string
}

type VerifyDigestResult struct {
	KeyID            string
	HashAlgorithm    string
	SigningAlgorithm string
	Verified         bool
	Message          string
}

func (s *service) VerifyDigest(ctx context.Context, input VerifyDigestInput) (*VerifyDigestResult, error) {
	validated, err := s.validator.ValidateVerifyDigestRequest(input)
	if err != nil {
		return nil, err
	}

	keyMeta, err := s.keys.GetKeyMetadata(ctx, input.KeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get key metadata: %w", err)
	}

	if err := s.verifier.Verify(keyMeta, validated.Digest, validated.Signature); err != nil {
		return nil, fmt.Errorf("failed to verify digest: %w", err)
	}

	return &VerifyDigestResult{
		KeyID:            input.KeyID,
		HashAlgorithm:    validated.HashAlgorithm,
		SigningAlgorithm: keyMeta.Algorithm,
		Verified:         true,
		Message:          "signature is valid",
	}, nil
}
