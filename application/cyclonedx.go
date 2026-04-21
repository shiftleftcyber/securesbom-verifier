package application

import (
	"bytes"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"fmt"

	digestsbom "github.com/shiftleftcyber/securesbom-verifier/services/sbom"
	"github.com/shiftleftcyber/securesbom-verifier/utils"
)

func (v *VerifierApp) VerifyCycloneDXEmbeddedV1(signedSBOM []byte, publicKeyPEM string) (*VerificationResult, error) {
	if err := validateSBOM(signedSBOM, "SBOM"); err != nil {
		return nil, err
	}

	parsed, err := digestsbom.ExtractCanonicalSBOMAndSignature(signedSBOM)
	if err != nil {
		return nil, err
	}

	signatureValue, algorithm, err := decodeEmbeddedSignature(parsed.SignatureJSON)
	if err != nil {
		return nil, err
	}

	return v.verifyCanonicalJSON(parsed.CanonicalJSON, signatureValue, publicKeyPEM, algorithm, "signature is valid", "ecdsa")
}

func (v *VerifierApp) VerifyCycloneDXEmbeddedV2(signedSBOM []byte, publicKeyPEM string) (*VerificationResult, error) {
	if err := validateSBOM(signedSBOM, "SBOM"); err != nil {
		return nil, err
	}

	canonical, signatureValue, algorithm, err := canonicalizeEmbeddedCycloneDXForV2(signedSBOM)
	if err != nil {
		return nil, err
	}

	return v.verifyCanonicalJSON(canonical, signatureValue, publicKeyPEM, algorithm, "signature is valid", "ecdsa")
}

func decodeEmbeddedSignature(signatureJSON []byte) (string, string, error) {
	var sigFields map[string]any
	if err := json.Unmarshal(signatureJSON, &sigFields); err != nil {
		return "", "", fmt.Errorf("malformed signature object: %w", err)
	}

	signatureValue, ok := sigFields["value"].(string)
	if !ok || signatureValue == "" {
		return "", "", errors.New("signature value missing or invalid")
	}

	algorithm, _ := sigFields["alg"].(string)
	if algorithm == "" {
		algorithm = "ES256"
	}

	return signatureValue, algorithm, nil
}

func canonicalizeEmbeddedCycloneDXForV2(signedSBOM []byte) ([]byte, string, string, error) {
	var obj map[string]any
	dec := json.NewDecoder(bytes.NewReader(signedSBOM))
	dec.UseNumber()
	if err := dec.Decode(&obj); err != nil {
		return nil, "", "", fmt.Errorf("invalid SBOM JSON: %w", err)
	}

	sigAny, ok := obj[signatureProperty]
	if !ok {
		return nil, "", "", fmt.Errorf("%s object is missing", signatureProperty)
	}

	sigObj, ok := sigAny.(map[string]any)
	if !ok {
		return nil, "", "", fmt.Errorf("%s must be an object", signatureProperty)
	}

	sigValAny, ok := sigObj["value"]
	if !ok {
		return nil, "", "", errors.New("signature value missing")
	}

	signatureValue, ok := sigValAny.(string)
	if !ok || signatureValue == "" {
		return nil, "", "", errors.New("signature value missing or invalid")
	}

	algorithm, _ := sigObj["alg"].(string)
	if algorithm == "" {
		algorithm = "ES256"
	}

	delete(sigObj, "value")
	obj[signatureProperty] = sigObj

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

func (v *VerifierApp) verifyCanonicalJSON(
	canonical []byte,
	signatureValue string,
	publicKeyPEM string,
	algorithm string,
	successMessage string,
	resultAlgorithm string,
) (*VerificationResult, error) {
	if publicKeyPEM == "" {
		return nil, errors.New("public key is required for offline verification")
	}

	verifier, err := v.verifierForAlgorithm(algorithm)
	if err != nil {
		return nil, err
	}

	valid, err := verifier.VerifyWithPublicKey(string(canonical), signatureValue, utils.NormalizePublicKeyPEM(publicKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}
	if !valid {
		return nil, errors.New("signature is invalid")
	}

	return &VerificationResult{
		Message:   successMessage,
		Algorithm: resultAlgorithm,
	}, nil
}
