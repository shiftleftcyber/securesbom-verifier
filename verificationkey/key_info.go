package verificationkey

// KeyInfo is the minimal verification key metadata needed by this module.
// The library intentionally excludes key generation, storage backends, and signing.
type KeyInfo struct {
	KeyID     string `json:"id,omitempty"`
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key,omitempty"`
}
