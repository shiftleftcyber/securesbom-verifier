package sbom

import (
	"bytes"
	"encoding/json"
	"encoding/json/jsontext"
	"fmt"
)

const SIGNATURE_PROPERTY = "signature"

func CanonicalizeUnsignedSBOM(sbomJSON []byte) ([]byte, error) {
	var obj map[string]interface{}

	dec := json.NewDecoder(bytes.NewReader(sbomJSON))
	dec.UseNumber()
	if err := dec.Decode(&obj); err != nil {
		return nil, fmt.Errorf("invalid SBOM JSON: %w", err)
	}

	delete(obj, "signature")

	canon, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize canonical SBOM: %w", err)
	}
	return canon, nil
}

func CanonicalizeUnsignedSBOMV2(sbomJSON []byte) ([]byte, error) {
	var obj map[string]any

	dec := json.NewDecoder(bytes.NewReader(sbomJSON))
	dec.UseNumber()
	if err := dec.Decode(&obj); err != nil {
		return nil, fmt.Errorf("invalid SBOM JSON: %w", err)
	}

	delete(obj, "signature")

	raw, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize JSON: %w", err)
	}

	v := jsontext.Value(raw)
	if err := v.Canonicalize(); err != nil {
		return nil, fmt.Errorf("failed to canonicalize JSON (RFC8785): %w", err)
	}

	return []byte(v), nil
}

func ExtractCanonicalSBOMAndSignature(sbomJSON []byte) (*ParsedSBOMSignature, error) {
	var obj map[string]any

	dec := json.NewDecoder(bytes.NewReader(sbomJSON))
	dec.UseNumber()
	if err := dec.Decode(&obj); err != nil {
		return nil, fmt.Errorf("invalid SBOM JSON: %w", err)
	}

	sigAny, ok := obj[SIGNATURE_PROPERTY]
	if !ok {
		return nil, fmt.Errorf("%s object is missing", SIGNATURE_PROPERTY)
	}

	sigObj, ok := sigAny.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an object", SIGNATURE_PROPERTY)
	}

	sigJSON, err := json.Marshal(sigObj)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize signature object: %w", err)
	}

	delete(obj, SIGNATURE_PROPERTY)

	canonical, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize canonical SBOM: %w", err)
	}

	return &ParsedSBOMSignature{
		CanonicalJSON: canonical,
		SignatureJSON: sigJSON,
	}, nil
}

type ParsedSBOMSignature struct {
	CanonicalJSON []byte
	SignatureJSON []byte
}

func CanonicalizeForJSFObject(sbomObj map[string]any) ([]byte, error) {
	raw, err := json.Marshal(sbomObj)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize JSON: %w", err)
	}
	return CanonicalizeForJSF(raw)
}

func CanonicalizeForJSF(sbomJSON []byte) ([]byte, error) {
	var obj map[string]interface{}

	dec := json.NewDecoder(bytes.NewReader(sbomJSON))
	dec.UseNumber()
	if err := dec.Decode(&obj); err != nil {
		return nil, fmt.Errorf("invalid SBOM JSON: %w", err)
	}

	if sigAny, ok := obj[SIGNATURE_PROPERTY]; ok {
		sigObj, ok := sigAny.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("%s must be an object", SIGNATURE_PROPERTY)
		}
		delete(sigObj, "value")
		obj[SIGNATURE_PROPERTY] = sigObj
	}

	raw, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize JSON: %w", err)
	}

	canonicalSBOMNoValue := jsontext.Value(raw)
	if err := canonicalSBOMNoValue.Canonicalize(); err != nil {
		return nil, fmt.Errorf("failed to canonicalize JSON: %w", err)
	}
	return canonicalSBOMNoValue, nil
}
