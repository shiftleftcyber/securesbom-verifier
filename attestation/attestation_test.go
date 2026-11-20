package attestation_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/shiftleftcyber/securesbom-verifier/attestation"
	"github.com/shiftleftcyber/securesbom-verifier/testsupport"
	"github.com/shiftleftcyber/securesbom-verifier/verificationkey"
)

const testKeyID = "key-123"

func TestPAEMatchesDSSESpecVector(t *testing.T) {
	got := attestation.PAE("http://example.com/HelloWorld", []byte("hello world"))
	want := "DSSEv1 29 http://example.com/HelloWorld 11 hello world"
	if string(got) != want {
		t.Fatalf("PAE = %q, want %q", got, want)
	}
}

func TestPAECountsBytesNotRunes(t *testing.T) {
	got := attestation.PAE("t", []byte("é"))
	if string(got) != "DSSEv1 1 t 2 é" {
		t.Fatalf("PAE = %q", got)
	}
}

func TestNormalizeSHA256(t *testing.T) {
	upper := strings.ToUpper(testsupport.TestSubjectDigest)
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"lowercase", testsupport.TestSubjectDigest, testsupport.TestSubjectDigest, false},
		{"uppercase", upper, testsupport.TestSubjectDigest, false},
		{"prefixed", "sha256:" + testsupport.TestSubjectDigest, testsupport.TestSubjectDigest, false},
		{"padded", "  " + testsupport.TestSubjectDigest + " ", testsupport.TestSubjectDigest, false},
		{"short", "abc", "", true},
		{"not hex", strings.Repeat("z", 64), "", true},
		{"all zeros", strings.Repeat("0", 64), "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := attestation.NormalizeSHA256(tc.in)
			if tc.wantErr {
				if !errors.Is(err, attestation.ErrInvalidDigest) {
					t.Fatalf("err = %v, want ErrInvalidDigest", err)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

func subject(name, digest string) attestation.Subject {
	return attestation.Subject{Name: name, Digest: map[string]string{"sha256": digest}}
}

func TestValidateSubjects(t *testing.T) {
	d := testsupport.TestSubjectDigest
	other := strings.Repeat("ab", 32)
	tooMany := make([]attestation.Subject, attestation.MaxSubjects+1)
	for i := range tooMany {
		tooMany[i] = subject("s", d)
	}

	cases := []struct {
		name     string
		subjects []attestation.Subject
		wantErr  bool
	}{
		{"one subject", []attestation.Subject{subject("app", d)}, false},
		{"two subjects", []attestation.Subject{subject("a", d), subject("b", other)}, false},
		{"none", nil, true},
		{"too many", tooMany, true},
		{"empty name", []attestation.Subject{subject("", d)}, true},
		{"long name", []attestation.Subject{subject(strings.Repeat("n", attestation.MaxSubjectNameLength+1), d)}, true},
		{"control char", []attestation.Subject{subject("a\nb", d)}, true},
		{"invalid utf8", []attestation.Subject{subject(string([]byte{0xff}), d)}, true},
		{"uppercase digest", []attestation.Subject{subject("a", strings.ToUpper(d))}, true},
		{"bad digest", []attestation.Subject{subject("a", "abc")}, true},
		{"sha512 only", []attestation.Subject{{Name: "a", Digest: map[string]string{"sha512": d}}}, true},
		{"two algorithms", []attestation.Subject{{Name: "a", Digest: map[string]string{"sha256": d, "sha512": d}}}, true},
		{"duplicate digest", []attestation.Subject{subject("a", d), subject("b", d)}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := attestation.ValidateSubjects(tc.subjects)
			if tc.wantErr != (err != nil) {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if err != nil && !errors.Is(err, attestation.ErrInvalidSubject) {
				t.Fatalf("err = %v, want ErrInvalidSubject", err)
			}
		})
	}
}

func TestCanonicalize(t *testing.T) {
	got, err := attestation.Canonicalize([]byte(`{ "b": 1, "a": [true, null, 1.50, "x"] }`))
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	if string(got) != `{"a":[true,null,1.5,"x"],"b":1}` {
		t.Fatalf("Canonicalize = %s", got)
	}

	for name, input := range map[string]string{
		"duplicate member": `{"a":1,"a":2}`,
		"large integer":    `{"a":9007199254740993}`,
		"large negative":   `{"a":-9007199254740993}`,
		"invalid json":     `{"a":`,
		"two values":       `{} {}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := attestation.Canonicalize([]byte(input)); !errors.Is(err, attestation.ErrNonCanonicalizableJSON) {
				t.Fatalf("err = %v, want ErrNonCanonicalizableJSON", err)
			}
		})
	}

	if _, err := attestation.Canonicalize([]byte(`{"a":9007199254740992,"b":1e300,"c":-5}`)); err != nil {
		t.Fatalf("2^53, exponents and small negatives must be accepted: %v", err)
	}
}

func TestIsCanonical(t *testing.T) {
	if !attestation.IsCanonical([]byte(`{"a":1,"b":2}`)) {
		t.Fatal("canonical input reported as non-canonical")
	}
	if attestation.IsCanonical([]byte(`{"b":2,"a":1}`)) {
		t.Fatal("unsorted input reported as canonical")
	}
	if attestation.IsCanonical([]byte(`{"a":1,"a":1}`)) {
		t.Fatal("duplicate members reported as canonical")
	}
}

func TestBuildStatementPayloadIsDeterministic(t *testing.T) {
	predicate := testsupport.FixtureBytes(t, "cyclonedx.json")
	first, err := attestation.BuildStatementPayload(testsupport.TestSubjects(), attestation.PredicateTypeCycloneDX, predicate)
	if err != nil {
		t.Fatalf("BuildStatementPayload: %v", err)
	}
	second, err := attestation.BuildStatementPayload(testsupport.TestSubjects(), attestation.PredicateTypeCycloneDX, predicate)
	if err != nil {
		t.Fatalf("BuildStatementPayload: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("payload is not deterministic")
	}
	if !attestation.IsCanonical(first) {
		t.Fatal("payload is not canonical")
	}

	statement, err := attestation.ParseStatement(first)
	if err != nil {
		t.Fatalf("ParseStatement: %v", err)
	}
	if statement.Type != attestation.StatementType || statement.PredicateType != attestation.PredicateTypeCycloneDX {
		t.Fatalf("unexpected statement: %+v", statement)
	}
	if statement.Subject[0].SHA256() != testsupport.TestSubjectDigest {
		t.Fatalf("subject digest = %q", statement.Subject[0].SHA256())
	}
}

func TestBuildStatementPayloadRejectsBadInput(t *testing.T) {
	predicate := testsupport.FixtureBytes(t, "cyclonedx.json")
	cases := []struct {
		name          string
		subjects      []attestation.Subject
		predicateType string
		predicate     []byte
		want          error
	}{
		{"no subjects", nil, attestation.PredicateTypeCycloneDX, predicate, attestation.ErrInvalidSubject},
		{"unknown predicate type", testsupport.TestSubjects(), "https://example.com/other", predicate, attestation.ErrUnsupportedPredicateType},
		{"array predicate", testsupport.TestSubjects(), attestation.PredicateTypeCycloneDX, []byte(`[]`), attestation.ErrInvalidStatement},
		{"invalid predicate", testsupport.TestSubjects(), attestation.PredicateTypeCycloneDX, []byte(`{`), attestation.ErrInvalidStatement},
		{"large integer", testsupport.TestSubjects(), attestation.PredicateTypeCycloneDX, []byte(`{"n":9007199254740993}`), attestation.ErrNonCanonicalizableJSON},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := attestation.BuildStatementPayload(tc.subjects, tc.predicateType, tc.predicate)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestParseStatementRejectsBadStatements(t *testing.T) {
	sub := `[{"name":"a","digest":{"sha256":"` + testsupport.TestSubjectDigest + `"}}]`
	cases := map[string]string{
		"not json":          `{`,
		"unknown field":     `{"_type":"https://in-toto.io/Statement/v1","subject":` + sub + `,"predicateType":"https://cyclonedx.org/bom","predicate":{},"extra":1}`,
		"wrong type":        `{"_type":"https://in-toto.io/Statement/v0.1","subject":` + sub + `,"predicateType":"https://cyclonedx.org/bom","predicate":{}}`,
		"no predicate type": `{"_type":"https://in-toto.io/Statement/v1","subject":` + sub + `,"predicate":{}}`,
		"no predicate":      `{"_type":"https://in-toto.io/Statement/v1","subject":` + sub + `,"predicateType":"https://cyclonedx.org/bom"}`,
		"bad subject":       `{"_type":"https://in-toto.io/Statement/v1","subject":[],"predicateType":"https://cyclonedx.org/bom","predicate":{}}`,
		"trailing data":     `{"_type":"https://in-toto.io/Statement/v1","subject":` + sub + `,"predicateType":"https://cyclonedx.org/bom","predicate":{}} {}`,
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := attestation.ParseStatement([]byte(input)); !errors.Is(err, attestation.ErrInvalidStatement) {
				t.Fatalf("err = %v, want ErrInvalidStatement", err)
			}
		})
	}
}

func TestPredicateTypeForSBOMType(t *testing.T) {
	for in, want := range map[string]string{
		"CycloneDX": attestation.PredicateTypeCycloneDX,
		"SPDX":      attestation.PredicateTypeSPDX,
		"AI-SBOM":   attestation.PredicateTypeAISBOM,
	} {
		got, err := attestation.PredicateTypeForSBOMType(in)
		if err != nil || got != want {
			t.Fatalf("PredicateTypeForSBOMType(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := attestation.PredicateTypeForSBOMType("other"); !errors.Is(err, attestation.ErrUnsupportedPredicateType) {
		t.Fatalf("err = %v, want ErrUnsupportedPredicateType", err)
	}
}

func TestParseEnvelopeRejectsBadEnvelopes(t *testing.T) {
	privKey, _ := testsupport.GenerateKeyPair(t)
	valid := testsupport.SignedAttestation(t, privKey, testKeyID, testsupport.TestSubjects(), attestation.PredicateTypeCycloneDX, testsupport.FixtureBytes(t, "cyclonedx.json"))

	cases := map[string][]byte{
		"not json":       []byte(`{`),
		"unknown field":  []byte(`{"payloadType":"application/vnd.in-toto+json","payload":"e30=","signatures":[{"keyid":"k","sig":"AA=="}],"x":1}`),
		"trailing data":  append(bytes.Clone(valid), []byte(` {}`)...),
		"wrong type":     testsupport.MutateEnvelope(t, valid, func(e *attestation.Envelope) { e.PayloadType = "application/json" }),
		"empty payload":  testsupport.MutateEnvelope(t, valid, func(e *attestation.Envelope) { e.Payload = "" }),
		"url base64":     testsupport.MutateEnvelope(t, valid, func(e *attestation.Envelope) { e.Payload = "-_-_" }),
		"no signatures":  testsupport.MutateEnvelope(t, valid, func(e *attestation.Envelope) { e.Signatures = nil }),
		"two signatures": testsupport.MutateEnvelope(t, valid, func(e *attestation.Envelope) { e.Signatures = append(e.Signatures, e.Signatures[0]) }),
		"no keyid":       testsupport.MutateEnvelope(t, valid, func(e *attestation.Envelope) { e.Signatures[0].KeyID = " " }),
		"empty sig":      testsupport.MutateEnvelope(t, valid, func(e *attestation.Envelope) { e.Signatures[0].Sig = "" }),
		"bad sig base64": testsupport.MutateEnvelope(t, valid, func(e *attestation.Envelope) { e.Signatures[0].Sig = "***" }),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := attestation.ParseEnvelope(input); !errors.Is(err, attestation.ErrInvalidEnvelope) {
				t.Fatalf("err = %v, want ErrInvalidEnvelope", err)
			}
		})
	}

	env, payload, err := attestation.ParseEnvelope(valid)
	if err != nil {
		t.Fatalf("ParseEnvelope(valid): %v", err)
	}
	if env.Signatures[0].KeyID != testKeyID || len(payload) == 0 {
		t.Fatalf("unexpected envelope: %+v", env)
	}
}

func TestVerifyEnvelopeAcceptsEachPredicateType(t *testing.T) {
	privKey, publicKeyPEM := testsupport.GenerateKeyPair(t)
	key := verificationkey.KeyInfo{KeyID: testKeyID, Algorithm: "ES256", PublicKey: publicKeyPEM}

	cases := []struct {
		name          string
		predicateType string
		predicate     []byte
		sbomType      string
	}{
		{"cyclonedx", attestation.PredicateTypeCycloneDX, testsupport.FixtureBytes(t, "cyclonedx.json"), "CycloneDX"},
		{"signed cyclonedx", attestation.PredicateTypeCycloneDX, testsupport.SignedCycloneDXV2WithKey(t, privKey, "ES256"), "CycloneDX"},
		{"spdx", attestation.PredicateTypeSPDX, testsupport.FixtureBytes(t, "spdx.json"), "SPDX"},
		{"ai-sbom", attestation.PredicateTypeAISBOM, testsupport.UnsignedAIBOM(t), "AI-SBOM"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			envelope := testsupport.SignedAttestation(t, privKey, testKeyID, testsupport.TestSubjects(), tc.predicateType, tc.predicate)
			got, err := attestation.VerifyEnvelope(envelope, key, "sha256:"+strings.ToUpper(testsupport.TestSubjectDigest))
			if err != nil {
				t.Fatalf("VerifyEnvelope: %v", err)
			}
			if got.PredicateType != tc.predicateType || got.SBOMType != tc.sbomType || got.KeyID != testKeyID || got.Algorithm != "ES256" {
				t.Fatalf("unexpected result: %+v", got)
			}
			if got.MatchedSubject.SHA256() != testsupport.TestSubjectDigest || len(got.Subjects) != 1 {
				t.Fatalf("unexpected subjects: %+v", got)
			}
			if len(got.PayloadSHA256) != 64 || !json.Valid(got.Predicate) {
				t.Fatalf("unexpected payload digest or predicate: %+v", got)
			}
		})
	}
}

func TestVerifyEnvelopeDefaultsAlgorithmAndAllowsAnyKeyID(t *testing.T) {
	privKey, publicKeyPEM := testsupport.GenerateKeyPair(t)
	envelope := testsupport.SignedAttestation(t, privKey, testKeyID, testsupport.TestSubjects(), attestation.PredicateTypeCycloneDX, testsupport.FixtureBytes(t, "cyclonedx.json"))
	got, err := attestation.VerifyEnvelope(envelope, verificationkey.KeyInfo{PublicKey: publicKeyPEM}, testsupport.TestSubjectDigest)
	if err != nil {
		t.Fatalf("VerifyEnvelope: %v", err)
	}
	if got.Algorithm != "ES256" || got.KeyID != testKeyID {
		t.Fatalf("unexpected result: %+v", got)
	}
}

func TestVerifyEnvelopeFailures(t *testing.T) {
	privKey, publicKeyPEM := testsupport.GenerateKeyPair(t)
	otherKey, otherPublicKeyPEM := testsupport.GenerateKeyPair(t)
	key := verificationkey.KeyInfo{KeyID: testKeyID, Algorithm: "ES256", PublicKey: publicKeyPEM}
	cdx := testsupport.FixtureBytes(t, "cyclonedx.json")
	spdx := testsupport.FixtureBytes(t, "spdx.json")
	valid := testsupport.SignedAttestation(t, privKey, testKeyID, testsupport.TestSubjects(), attestation.PredicateTypeCycloneDX, cdx)
	payload := testsupport.EnvelopePayload(t, valid)

	nonCanonical := append([]byte(" "), payload...)
	tamperedPayload := bytes.Replace(payload, []byte("example-library"), []byte("evil-library-xx"), 1)
	unknownType := []byte(`{"_type":"https://in-toto.io/Statement/v1","predicate":{"a":1},"predicateType":"https://example.com/x","subject":[{"digest":{"sha256":"` + testsupport.TestSubjectDigest + `"},"name":"a"}]}`)
	badStatement := []byte(`{"_type":"https://in-toto.io/Statement/v0.1","predicate":{"a":1},"predicateType":"https://cyclonedx.org/bom","subject":[{"digest":{"sha256":"` + testsupport.TestSubjectDigest + `"},"name":"a"}]}`)
	notSBOM := []byte(`{"_type":"https://in-toto.io/Statement/v1","predicate":{"a":1},"predicateType":"https://cyclonedx.org/bom","subject":[{"digest":{"sha256":"` + testsupport.TestSubjectDigest + `"},"name":"a"}]}`)
	otherDigest := strings.Repeat("ab", 32)

	cases := []struct {
		name     string
		envelope []byte
		key      verificationkey.KeyInfo
		expected string
		want     error
	}{
		{"missing expected digest", valid, key, " ", attestation.ErrExpectedDigestRequired},
		{"malformed expected digest", valid, key, "abc", attestation.ErrExpectedDigestRequired},
		{"invalid envelope", []byte(`{`), key, testsupport.TestSubjectDigest, attestation.ErrInvalidEnvelope},
		{"key id mismatch", valid, verificationkey.KeyInfo{KeyID: "other", PublicKey: publicKeyPEM}, testsupport.TestSubjectDigest, attestation.ErrKeyMismatch},
		{"wrong public key", valid, verificationkey.KeyInfo{KeyID: testKeyID, PublicKey: otherPublicKeyPEM}, testsupport.TestSubjectDigest, attestation.ErrSignatureInvalid},
		{"missing public key", valid, verificationkey.KeyInfo{KeyID: testKeyID}, testsupport.TestSubjectDigest, attestation.ErrSignatureInvalid},
		{"unsupported algorithm", valid, verificationkey.KeyInfo{KeyID: testKeyID, Algorithm: "RS256", PublicKey: publicKeyPEM}, testsupport.TestSubjectDigest, attestation.ErrSignatureInvalid},
		{"bad public key", valid, verificationkey.KeyInfo{KeyID: testKeyID, PublicKey: "not a key"}, testsupport.TestSubjectDigest, attestation.ErrSignatureInvalid},
		{"tampered payload", testsupport.MutateEnvelope(t, valid, func(e *attestation.Envelope) {
			e.Payload = base64.StdEncoding.EncodeToString(tamperedPayload)
		}), key, testsupport.TestSubjectDigest, attestation.ErrSignatureInvalid},
		{"signed by another key", testsupport.SignedAttestation(t, otherKey, testKeyID, testsupport.TestSubjects(), attestation.PredicateTypeCycloneDX, cdx), key, testsupport.TestSubjectDigest, attestation.ErrSignatureInvalid},
		{"non-canonical payload", testsupport.SignedEnvelopeForPayload(t, privKey, testKeyID, nonCanonical), key, testsupport.TestSubjectDigest, attestation.ErrPayloadNotCanonical},
		{"invalid statement", testsupport.SignedEnvelopeForPayload(t, privKey, testKeyID, badStatement), key, testsupport.TestSubjectDigest, attestation.ErrInvalidStatement},
		{"unsupported predicate type", testsupport.SignedEnvelopeForPayload(t, privKey, testKeyID, unknownType), key, testsupport.TestSubjectDigest, attestation.ErrUnsupportedPredicateType},
		{"predicate is not an SBOM", testsupport.SignedEnvelopeForPayload(t, privKey, testKeyID, notSBOM), key, testsupport.TestSubjectDigest, attestation.ErrUnsupportedPredicateType},
		{"predicate type does not match predicate", testsupport.SignedAttestation(t, privKey, testKeyID, testsupport.TestSubjects(), attestation.PredicateTypeCycloneDX, spdx), key, testsupport.TestSubjectDigest, attestation.ErrUnsupportedPredicateType},
		{"subject mismatch", valid, key, otherDigest, attestation.ErrSubjectMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := attestation.VerifyEnvelope(tc.envelope, tc.key, tc.expected)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if got != nil {
				t.Fatalf("result must be nil on failure, got %+v", got)
			}
		})
	}
}

func TestNewEnvelopeRoundTrip(t *testing.T) {
	env := attestation.NewEnvelope([]byte(`{"a":1}`), "k", []byte{1, 2, 3})
	if env.PayloadType != attestation.PayloadType || len(env.Signatures) != 1 || env.Signatures[0].KeyID != "k" {
		t.Fatalf("unexpected envelope: %+v", env)
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(raw), `"keyid":"k"`) || !strings.Contains(string(raw), `"payloadType":"application/vnd.in-toto+json"`) {
		t.Fatalf("unexpected JSON: %s", raw)
	}
}
