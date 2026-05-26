package application

import (
	"bytes"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"fmt"
)

const aiBOMSignatureProperty = "sbomAuthorSignature"

func (v *VerifierApp) VerifyAIBOMEmbeddedVersioned(
	signedSBOM []byte,
	publicKeyPEM string,
	version VerificationVersion,
) (*VerificationResult, error) {
	switch version {
	case VerificationV2:
		return v.VerifyAIBOMEmbeddedV2(signedSBOM, publicKeyPEM)
	default:
		return v.VerifyAIBOMEmbeddedV1(signedSBOM, publicKeyPEM)
	}
}

func (v *VerifierApp) VerifyAIBOMEmbeddedV1(signedSBOM []byte, publicKeyPEM string) (*VerificationResult, error) {
	if err := validateSBOM(signedSBOM, "AI-BOM"); err != nil {
		return nil, err
	}

	canonical, signatureValue, algorithm, err := canonicalizeEmbeddedAIBOMForV1(signedSBOM)
	if err != nil {
		return nil, err
	}

	return v.verifyCanonicalJSON(canonical, signatureValue, publicKeyPEM, algorithm, "AI-BOM signature is valid", "ecdsa")
}

func (v *VerifierApp) VerifyAIBOMEmbeddedV2(signedSBOM []byte, publicKeyPEM string) (*VerificationResult, error) {
	if err := validateSBOM(signedSBOM, "AI-BOM"); err != nil {
		return nil, err
	}

	canonical, signatureValue, algorithm, err := canonicalizeEmbeddedAIBOMForV2(signedSBOM)
	if err != nil {
		return nil, err
	}

	return v.verifyCanonicalJSON(canonical, signatureValue, publicKeyPEM, algorithm, "AI-BOM signature is valid", "ecdsa")
}

func canonicalizeEmbeddedAIBOMForV1(signedSBOM []byte) ([]byte, string, string, error) {
	obj, signatureObj, err := extractAIBOMSignatureObject(signedSBOM)
	if err != nil {
		return nil, "", "", err
	}

	signatureValue, algorithm, err := decodeEmbeddedSignatureFields(signatureObj)
	if err != nil {
		return nil, "", "", err
	}

	metadata := obj["metadata"].(map[string]any)
	delete(metadata, aiBOMSignatureProperty)

	canonical, err := json.Marshal(obj)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to serialize canonical AI-BOM: %w", err)
	}

	return canonical, signatureValue, algorithm, nil
}

func canonicalizeEmbeddedAIBOMForV2(signedSBOM []byte) ([]byte, string, string, error) {
	obj, signatureObj, err := extractAIBOMSignatureObject(signedSBOM)
	if err != nil {
		return nil, "", "", err
	}

	signatureValue, algorithm, err := decodeEmbeddedSignatureFields(signatureObj)
	if err != nil {
		return nil, "", "", err
	}

	delete(signatureObj, "value")

	rawNoValue, err := json.Marshal(obj)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to serialize JSON: %w", err)
	}

	canonical := jsontext.Value(rawNoValue)
	if err := canonical.Canonicalize(); err != nil {
		return nil, "", "", fmt.Errorf("failed to canonicalize JSON: %w", err)
	}

	return []byte(canonical), signatureValue, algorithm, nil
}

func extractAIBOMSignatureObject(signedSBOM []byte) (map[string]any, map[string]any, error) {
	var obj map[string]any
	dec := json.NewDecoder(bytes.NewReader(signedSBOM))
	dec.UseNumber()
	if err := dec.Decode(&obj); err != nil {
		return nil, nil, fmt.Errorf("invalid AI-BOM JSON: %w", err)
	}

	metadataAny, ok := obj["metadata"]
	if !ok {
		return nil, nil, errors.New("metadata object is missing")
	}

	metadata, ok := metadataAny.(map[string]any)
	if !ok {
		return nil, nil, errors.New("metadata must be an object")
	}

	sigAny, ok := metadata[aiBOMSignatureProperty]
	if !ok {
		return nil, nil, fmt.Errorf("%s object is missing", aiBOMSignatureProperty)
	}

	sigObj, ok := sigAny.(map[string]any)
	if !ok {
		return nil, nil, fmt.Errorf("%s must be an object", aiBOMSignatureProperty)
	}

	return obj, sigObj, nil
}

func decodeEmbeddedSignatureFields(sigFields map[string]any) (string, string, error) {
	signatureValue, ok := sigFields["value"].(string)
	if !ok || signatureValue == "" {
		return "", "", errors.New("signature value missing or invalid")
	}

	algorithm, _ := sigFields["alg"].(string)
	if algorithm == "" {
		algorithm, _ = sigFields["algorithm"].(string)
	}
	if algorithm == "" {
		algorithm = "ES256"
	}

	return signatureValue, algorithm, nil
}
