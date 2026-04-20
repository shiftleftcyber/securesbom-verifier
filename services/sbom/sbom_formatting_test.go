package sbom

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCanonicalizeUnsignedSBOM(t *testing.T) {
	input := []byte(`{"name":"demo","signature":{"alg":"ES256","value":"abc"}}`)

	got, err := CanonicalizeUnsignedSBOM(input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if strings.Contains(string(got), "signature") {
		t.Fatalf("expected signature field to be removed, got %s", string(got))
	}
}

func TestCanonicalizeUnsignedSBOM_InvalidJSON(t *testing.T) {
	_, err := CanonicalizeUnsignedSBOM([]byte("{"))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCanonicalizeUnsignedSBOMV2(t *testing.T) {
	input := []byte(`{"b":1,"a":2,"signature":{"alg":"ES256","value":"abc"}}`)

	got, err := CanonicalizeUnsignedSBOMV2(input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if string(got) != `{"a":2,"b":1}` {
		t.Fatalf("unexpected canonical form: %s", string(got))
	}
}

func TestExtractCanonicalSBOMAndSignature(t *testing.T) {
	input := []byte(`{"name":"demo","signature":{"alg":"ES256","value":"abc"}}`)

	got, err := ExtractCanonicalSBOMAndSignature(input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if strings.Contains(string(got.CanonicalJSON), "signature") {
		t.Fatal("expected signature removed from canonical JSON")
	}
	if !strings.Contains(string(got.SignatureJSON), `"value":"abc"`) {
		t.Fatal("expected signature JSON to be preserved")
	}
}

func TestExtractCanonicalSBOMAndSignature_MissingSignature(t *testing.T) {
	_, err := ExtractCanonicalSBOMAndSignature([]byte(`{"name":"demo"}`))
	if err == nil || !strings.Contains(err.Error(), "signature object is missing") {
		t.Fatalf("expected missing signature error, got %v", err)
	}
}

func TestExtractCanonicalSBOMAndSignature_InvalidSignatureType(t *testing.T) {
	_, err := ExtractCanonicalSBOMAndSignature([]byte(`{"signature":"bad"}`))
	if err == nil || !strings.Contains(err.Error(), "signature must be an object") {
		t.Fatalf("expected invalid signature type error, got %v", err)
	}
}

func TestCanonicalizeForJSFObject(t *testing.T) {
	input := map[string]any{
		"name": "demo",
		"signature": map[string]any{
			"alg":   "ES256",
			"value": "abc",
		},
	}

	got, err := CanonicalizeForJSFObject(input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if strings.Contains(string(got), `"value"`) {
		t.Fatalf("expected signature value to be removed, got %s", string(got))
	}
}

func TestCanonicalizeForJSF(t *testing.T) {
	signed := []byte(`{"name":"demo","signature":{"alg":"ES256","value":"abc"}}`)
	got, err := CanonicalizeForJSF(signed)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	var obj map[string]any
	if err := json.Unmarshal(got, &obj); err != nil {
		t.Fatalf("expected valid JSON, got %v", err)
	}
	signature := obj["signature"].(map[string]any)
	if _, ok := signature["value"]; ok {
		t.Fatal("expected signature value to be removed")
	}
}

func TestCanonicalizeForJSF_InvalidSignatureType(t *testing.T) {
	_, err := CanonicalizeForJSF([]byte(`{"signature":"bad"}`))
	if err == nil || !strings.Contains(err.Error(), "signature must be an object") {
		t.Fatalf("expected invalid signature type error, got %v", err)
	}
}
