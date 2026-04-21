package digestsigning

import (
	"encoding/base64"
	"errors"
	"testing"
)

func TestNewValidator(t *testing.T) {
	v := NewValidator()
	if v == nil {
		t.Fatal("expected validator to be non-nil")
	}

	if _, ok := v.(*validator); !ok {
		t.Fatalf("expected type *validator, got %T", v)
	}
}

func TestValidator_ValidateVerifyDigestRequest(t *testing.T) {
	v := NewValidator()

	rawDigest := make([]byte, 32)
	for i := range rawDigest {
		rawDigest[i] = byte(i)
	}

	t.Run("success", func(t *testing.T) {
		req := VerifyDigestInput{
			KeyID:         "key-123",
			HashAlgorithm: "sha256",
			Digest:        base64.StdEncoding.EncodeToString(rawDigest),
			Signature:     base64.StdEncoding.EncodeToString([]byte{0x30, 0x45, 0x02, 0x20}),
		}

		got, err := v.ValidateVerifyDigestRequest(req)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if got == nil {
			t.Fatal("expected validated digest, got nil")
		}
		if len(got.Signature) == 0 {
			t.Fatal("expected signature bytes")
		}
	})

	t.Run("invalid signature base64", func(t *testing.T) {
		req := VerifyDigestInput{
			KeyID:         "key-123",
			HashAlgorithm: "sha256",
			Digest:        base64.StdEncoding.EncodeToString(rawDigest),
			Signature:     "not-valid-base64$$$",
		}

		got, err := v.ValidateVerifyDigestRequest(req)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !errors.Is(err, ErrInvalidSignature) {
			t.Fatalf("expected ErrInvalidSignature, got %v", err)
		}
		if got != nil {
			t.Fatalf("expected nil result, got %+v", got)
		}
	})

	t.Run("missing key id", func(t *testing.T) {
		got, err := v.ValidateVerifyDigestRequest(VerifyDigestInput{
			HashAlgorithm: "sha256",
			Digest:        base64.StdEncoding.EncodeToString(rawDigest),
			Signature:     base64.StdEncoding.EncodeToString([]byte{0x30}),
		})
		if err == nil || !errors.Is(err, ErrInvalidKeyID) {
			t.Fatalf("expected ErrInvalidKeyID, got %v", err)
		}
		if got != nil {
			t.Fatalf("expected nil result, got %+v", got)
		}
	})

	t.Run("invalid digest base64", func(t *testing.T) {
		got, err := v.ValidateVerifyDigestRequest(VerifyDigestInput{
			KeyID:         "key-123",
			HashAlgorithm: "sha256",
			Digest:        "%%%invalid%%%",
			Signature:     base64.StdEncoding.EncodeToString([]byte{0x30}),
		})
		if err == nil || !errors.Is(err, ErrInvalidDigest) {
			t.Fatalf("expected ErrInvalidDigest, got %v", err)
		}
		if got != nil {
			t.Fatalf("expected nil result, got %+v", got)
		}
	})

	t.Run("unsupported hash algorithm", func(t *testing.T) {
		got, err := v.ValidateVerifyDigestRequest(VerifyDigestInput{
			KeyID:         "key-123",
			HashAlgorithm: "sha512",
			Digest:        base64.StdEncoding.EncodeToString(rawDigest),
			Signature:     base64.StdEncoding.EncodeToString([]byte{0x30}),
		})
		if err == nil || !errors.Is(err, ErrInvalidHashAlgorithm) {
			t.Fatalf("expected ErrInvalidHashAlgorithm, got %v", err)
		}
		if got != nil {
			t.Fatalf("expected nil result, got %+v", got)
		}
	})

	t.Run("empty signature", func(t *testing.T) {
		got, err := v.ValidateVerifyDigestRequest(VerifyDigestInput{
			KeyID:         "key-123",
			HashAlgorithm: "sha256",
			Digest:        base64.StdEncoding.EncodeToString(rawDigest),
			Signature:     "",
		})
		if err == nil || !errors.Is(err, ErrInvalidSignature) {
			t.Fatalf("expected ErrInvalidSignature, got %v", err)
		}
		if got != nil {
			t.Fatalf("expected nil result, got %+v", got)
		}
	})
}
