package attestation

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Envelope is a DSSE v1 envelope.
type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []Signature `json:"signatures"`
}

// Signature is one DSSE signature. Sig is standard base64.
type Signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// PAE returns the DSSE v1 pre-authentication encoding of a payload:
//
//	"DSSEv1" SP LEN(type) SP type SP LEN(body) SP body
//
// where LEN is the byte length as ASCII decimal. These are the bytes a
// signature covers.
func PAE(payloadType string, payload []byte) []byte {
	var b bytes.Buffer
	b.Grow(len("DSSEv1") + len(payloadType) + len(payload) + 24)
	b.WriteString("DSSEv1 ")
	b.WriteString(strconv.Itoa(len(payloadType)))
	b.WriteByte(' ')
	b.WriteString(payloadType)
	b.WriteByte(' ')
	b.WriteString(strconv.Itoa(len(payload)))
	b.WriteByte(' ')
	b.Write(payload)
	return b.Bytes()
}

// NewEnvelope wraps a signed payload in a single-signature envelope.
func NewEnvelope(payload []byte, keyID string, signature []byte) Envelope {
	return Envelope{
		PayloadType: PayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures: []Signature{{
			KeyID: keyID,
			Sig:   base64.StdEncoding.EncodeToString(signature),
		}},
	}
}

// ParseEnvelope decodes a DSSE envelope and enforces the profile's envelope
// rules: known fields only, the in-toto payload type, a non-empty standard
// base64 payload, and exactly one signature with a key ID.
func ParseEnvelope(data []byte) (*Envelope, []byte, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	var env Envelope
	if err := dec.Decode(&env); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidEnvelope, err)
	}
	if dec.More() {
		return nil, nil, fmt.Errorf("%w: trailing data after envelope", ErrInvalidEnvelope)
	}

	if env.PayloadType != PayloadType {
		return nil, nil, fmt.Errorf("%w: payloadType must be %s", ErrInvalidEnvelope, PayloadType)
	}
	if env.Payload == "" {
		return nil, nil, fmt.Errorf("%w: payload is empty", ErrInvalidEnvelope)
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: payload is not standard base64", ErrInvalidEnvelope)
	}

	if len(env.Signatures) != 1 {
		return nil, nil, fmt.Errorf("%w: exactly one signature is required, got %d", ErrInvalidEnvelope, len(env.Signatures))
	}
	sig := env.Signatures[0]
	if strings.TrimSpace(sig.KeyID) == "" {
		return nil, nil, fmt.Errorf("%w: signature keyid is required", ErrInvalidEnvelope)
	}
	if sig.Sig == "" {
		return nil, nil, fmt.Errorf("%w: signature is empty", ErrInvalidEnvelope)
	}
	if _, err := base64.StdEncoding.DecodeString(sig.Sig); err != nil {
		return nil, nil, fmt.Errorf("%w: signature is not standard base64", ErrInvalidEnvelope)
	}

	return &env, payload, nil
}
