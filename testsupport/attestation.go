package testsupport

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/shiftleftcyber/securesbom-verifier/attestation"
)

// TestSubjectDigest is a fixed, valid sha256 subject digest for tests.
const TestSubjectDigest = "a3f5c1d2e4b6a7980f1e2d3c4b5a69788796a5b4c3d2e1f00112233445566778"

// TestSubjects returns one subject using TestSubjectDigest.
func TestSubjects() []attestation.Subject {
	return []attestation.Subject{{
		Name:   "registry.example.com/app",
		Digest: map[string]string{attestation.DigestAlgorithmSHA256: TestSubjectDigest},
	}}
}

// SignedAttestation builds a canonical Statement around predicate and signs it
// with privKey the way the SecureSBOM API does.
func SignedAttestation(t *testing.T, privKey *ecdsa.PrivateKey, keyID string, subjects []attestation.Subject, predicateType string, predicate []byte) []byte {
	t.Helper()

	payload, err := attestation.BuildStatementPayload(subjects, predicateType, predicate)
	if err != nil {
		t.Fatalf("build statement payload: %v", err)
	}
	return SignedEnvelopeForPayload(t, privKey, keyID, payload)
}

// SignedEnvelopeForPayload signs arbitrary payload bytes into a DSSE envelope,
// so tests can produce envelopes the profile must reject.
func SignedEnvelopeForPayload(t *testing.T, privKey *ecdsa.PrivateKey, keyID string, payload []byte) []byte {
	t.Helper()

	hash := sha256.Sum256(attestation.PAE(attestation.PayloadType, payload))
	sig, err := ecdsa.SignASN1(rand.Reader, privKey, hash[:])
	if err != nil {
		t.Fatalf("sign PAE: %v", err)
	}

	envelope, err := json.Marshal(attestation.NewEnvelope(payload, keyID, sig))
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return envelope
}

// MutateEnvelope decodes an envelope, applies fn and re-encodes it.
func MutateEnvelope(t *testing.T, envelope []byte, fn func(*attestation.Envelope)) []byte {
	t.Helper()

	var env attestation.Envelope
	if err := json.Unmarshal(envelope, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	fn(&env)
	out, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return out
}

// EnvelopePayload returns the decoded payload of an envelope.
func EnvelopePayload(t *testing.T, envelope []byte) []byte {
	t.Helper()

	var env attestation.Envelope
	if err := json.Unmarshal(envelope, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	return payload
}
