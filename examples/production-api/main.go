package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	securesbomverifier "github.com/shiftleftcyber/securesbom-verifier"
)

type apiServer struct {
	verifier *securesbomverifier.Verifier
	keys     keyClient
}

type keyClient interface {
	GetVerificationKey(ctx context.Context, keyID string) (securesbomverifier.VerificationKey, error)
}

type verifyRequest struct {
	KeyID               string `json:"key_id"`
	Kind                string `json:"kind"`
	HashAlgorithm       string `json:"hash_algorithm,omitempty"`
	Digest              string `json:"digest,omitempty"`
	Signature           string `json:"signature,omitempty"`
	SBOM                []byte `json:"sbom,omitempty"`
	VerificationVersion string `json:"verification_version,omitempty"`
}

type verifyResponse struct {
	Verified  bool   `json:"verified"`
	Message   string `json:"message"`
	Algorithm string `json:"algorithm,omitempty"`
}

func main() {
	srv := &apiServer{
		verifier: securesbomverifier.NewVerifier(),
		keys:     staticKeyClient{},
	}

	http.HandleFunc("/verify", srv.verify)
	_ = http.ListenAndServe(":8080", nil)
}

func (s *apiServer) verify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req verifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON request")
		return
	}

	key, err := s.keys.GetVerificationKey(r.Context(), req.KeyID)
	if err != nil {
		writeError(w, http.StatusNotFound, "verification key not found")
		return
	}

	switch req.Kind {
	case "cyclonedx":
		result, err := s.verifier.VerifyCycloneDXEmbeddedWithKeyVersioned(req.SBOM, key, versionFromRequest(req.VerificationVersion))
		writeVerificationResult(w, result, err)
	case "spdx":
		result, err := s.verifier.VerifySPDXDetachedWithKeyVersioned(req.SBOM, req.Signature, key, versionFromRequest(req.VerificationVersion))
		writeVerificationResult(w, result, err)
	case "digest":
		result, err := s.verifier.VerifyDigest(
			securesbomverifier.VerifyDigestInput{
				KeyID:         req.KeyID,
				HashAlgorithm: req.HashAlgorithm,
				Digest:        req.Digest,
				Signature:     req.Signature,
			},
			key,
		)
		writeDigestResult(w, result, err)
	default:
		writeError(w, http.StatusBadRequest, "unsupported verification kind")
	}
}

func writeVerificationResult(w http.ResponseWriter, result *securesbomverifier.VerificationResult, err error) {
	if err != nil {
		writeMappedError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, verifyResponse{
		Verified:  true,
		Message:   result.Message,
		Algorithm: result.Algorithm,
	})
}

func writeDigestResult(w http.ResponseWriter, result *securesbomverifier.VerifyDigestResult, err error) {
	if err != nil {
		writeMappedError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, verifyResponse{
		Verified:  result.Verified,
		Message:   result.Message,
		Algorithm: result.SigningAlgorithm,
	})
}

func writeMappedError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, securesbomverifier.ErrInvalidSBOM),
		errors.Is(err, securesbomverifier.ErrMissingSignature),
		errors.Is(err, securesbomverifier.ErrInvalidHashAlgorithm),
		errors.Is(err, securesbomverifier.ErrInvalidDigest),
		errors.Is(err, securesbomverifier.ErrInvalidKeyID),
		errors.Is(err, securesbomverifier.ErrInvalidSignature),
		errors.Is(err, securesbomverifier.ErrInvalidKey):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, securesbomverifier.ErrSignatureFail),
		errors.Is(err, securesbomverifier.ErrVerificationFailed):
		writeError(w, http.StatusUnprocessableEntity, "signature verification failed")
	default:
		writeError(w, http.StatusInternalServerError, "verification failed")
	}
}

func versionFromRequest(value string) securesbomverifier.VerificationVersion {
	if value == "v1" {
		return securesbomverifier.VerificationV1
	}
	return securesbomverifier.VerificationV2
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, verifyResponse{Verified: false, Message: message})
}

func writeJSON(w http.ResponseWriter, status int, body verifyResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

type staticKeyClient struct{}

func (staticKeyClient) GetVerificationKey(ctx context.Context, keyID string) (securesbomverifier.VerificationKey, error) {
	if keyID == "" {
		return securesbomverifier.VerificationKey{}, fmt.Errorf("missing key id")
	}

	return securesbomverifier.VerificationKey{
		KeyID:     keyID,
		Algorithm: "ES256",
		PublicKey: "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
	}, nil
}
