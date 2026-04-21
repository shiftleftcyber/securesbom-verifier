package digestsigning

import (
	"context"
	"errors"
	"testing"

	"github.com/shiftleftcyber/secure-sbom-verifier/verificationkey"
)

type stubKeyMetadataStore struct {
	key *verificationkey.KeyInfo
	err error
}

func (s *stubKeyMetadataStore) GetKeyMetadata(ctx context.Context, keyID string) (*verificationkey.KeyInfo, error) {
	return s.key, s.err
}

type stubDigestVerifier struct {
	err error
}

func (s *stubDigestVerifier) Verify(keyMeta *verificationkey.KeyInfo, digest []byte, signature []byte) error {
	return s.err
}

func TestServiceVerifyDigest(t *testing.T) {
	service := NewService(
		NewValidator(),
		&stubKeyMetadataStore{
			key: &verificationkey.KeyInfo{
				KeyID:     "key-123",
				Algorithm: "ES256",
				PublicKey: "pem",
			},
		},
		&stubDigestVerifier{},
	)

	result, err := service.VerifyDigest(context.Background(), VerifyDigestInput{
		KeyID:         "key-123",
		HashAlgorithm: "sha256",
		Digest:        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
		Signature:     "MEUCIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAiEA",
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !result.Verified {
		t.Fatal("expected verified result")
	}
}

func TestServiceVerifyDigest_InvalidInput(t *testing.T) {
	service := NewService(NewValidator(), &stubKeyMetadataStore{}, &stubDigestVerifier{})

	_, err := service.VerifyDigest(context.Background(), VerifyDigestInput{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestServiceVerifyDigest_KeyMetadataError(t *testing.T) {
	service := NewService(
		NewValidator(),
		&stubKeyMetadataStore{err: errors.New("lookup failed")},
		&stubDigestVerifier{},
	)

	_, err := service.VerifyDigest(context.Background(), VerifyDigestInput{
		KeyID:         "key-123",
		HashAlgorithm: "sha256",
		Digest:        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
		Signature:     "MEUCIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAiEA",
	})
	if err == nil || err.Error() != "failed to get key metadata: lookup failed" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestServiceVerifyDigest_VerifierError(t *testing.T) {
	service := NewService(
		NewValidator(),
		&stubKeyMetadataStore{
			key: &verificationkey.KeyInfo{
				KeyID:     "key-123",
				Algorithm: "ES256",
				PublicKey: "pem",
			},
		},
		&stubDigestVerifier{err: errors.New("bad signature")},
	)

	_, err := service.VerifyDigest(context.Background(), VerifyDigestInput{
		KeyID:         "key-123",
		HashAlgorithm: "sha256",
		Digest:        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
		Signature:     "MEUCIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAiEA",
	})
	if err == nil || err.Error() != "failed to verify digest: bad signature" {
		t.Fatalf("unexpected error: %v", err)
	}
}
