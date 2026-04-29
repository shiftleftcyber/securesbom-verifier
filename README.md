# Secure SBOM Verifier

`securesbom-verifier` is a Go library for verifying signed SBOMs and signed
digests with public keys. It is designed to be reused by:

- API servers that need SBOM verification business logic
- offline or air-gapped verification workflows
- other Go services that need digest signature verification
- command-line tooling that wants to wrap the same library behavior

## What This Project Contains

- CycloneDX embedded signature verification
- SPDX detached signature verification
- digest signature verification
- JSON canonicalization helpers used during verification
- PEM normalization and key utility helpers
- an optional offline verification CLI
- tests for the lower-level verification building blocks

## Verification-Only Scope

This module intentionally excludes:

- key generation
- signing
- private-key verification helpers
- key store backends

The only cryptographic operations here are verification using a public key.

## Quick Start

```bash
make test
make build-cli
```

## Library Usage

Import the module root directly:

```go
import securesbomverifier "github.com/shiftleftcyber/securesbom-verifier"
```

For CycloneDX embedded signatures:

```go
verifier := securesbomverifier.NewVerifier()

result, err := verifier.VerifyCycloneDXEmbeddedVersioned(
  signedSBOM,
  string(publicKeyPEM),
  securesbomverifier.VerificationV2,
)
```

When key metadata is available, use the key-based root API:

```go
result, err := verifier.VerifyCycloneDXEmbeddedWithKeyVersioned(
  signedSBOM,
  securesbomverifier.VerificationKey{
    KeyID:     "production-key-2026-04",
    Algorithm: "ES256",
    PublicKey: string(publicKeyPEM),
  },
  securesbomverifier.VerificationV2,
)
```

For SPDX detached signatures:

```go
verifier := securesbomverifier.NewVerifier()

result, err := verifier.VerifySPDXDetachedVersioned(
  spdxSBOM,
  signatureB64,
  string(publicKeyPEM),
  securesbomverifier.VerificationV2,
)
if err != nil {
  if errors.Is(err, securesbomverifier.ErrSignatureFail) {
    // Signature did not verify.
  }
}
```

For digest verification:

```go
import (
  "errors"

  securesbomverifier "github.com/shiftleftcyber/securesbom-verifier"
)

verifier := securesbomverifier.NewVerifier()

result, err := verifier.VerifyDigest(
  securesbomverifier.VerifyDigestInput{
    KeyID:         "production-key-2026-04",
    HashAlgorithm: "sha256",
    Digest:        digestB64,
    Signature:     signatureB64,
  },
  securesbomverifier.VerificationKey{
    KeyID:     "production-key-2026-04",
    Algorithm: "ES256",
    PublicKey: string(publicKeyPEM),
  },
)
if err != nil {
  switch {
  case errors.Is(err, securesbomverifier.ErrInvalidDigest),
    errors.Is(err, securesbomverifier.ErrInvalidSignature),
    errors.Is(err, securesbomverifier.ErrInvalidHashAlgorithm),
    errors.Is(err, securesbomverifier.ErrInvalidKeyID),
    errors.Is(err, securesbomverifier.ErrInvalidKey):
    // Bad request or bad key metadata.
  case errors.Is(err, securesbomverifier.ErrVerificationFailed):
    // Well-formed input, but the signature did not verify.
  default:
    // Unexpected operational failure.
  }
  return err
}
_ = result.Verified
```

The lower-level packages remain available for advanced integrations:

```go
import (
  digestsigning "github.com/shiftleftcyber/securesbom-verifier/services/digest"
  "github.com/shiftleftcyber/securesbom-verifier/verificationkey"
)
```

## Digest Verification

`VerifyDigest` verifies an ASN.1 DER ECDSA signature over a digest that was
computed by the caller.

Request fields:

- `KeyID`: required key identifier. It must match `VerificationKey.KeyID` when
  the key metadata includes one.
- `HashAlgorithm`: required digest algorithm. Currently only `sha256` is
  supported.
- `Digest`: required standard-base64 encoding of the raw digest bytes. For
  `sha256`, this must decode to exactly 32 bytes.
- `Signature`: required standard-base64 encoding of the ASN.1 DER ECDSA
  signature bytes.

Key metadata uses the same root type for digest and SBOM integrations:

```go
type VerificationKey struct {
  KeyID     string
  Algorithm string
  PublicKey string
}
```

`Algorithm` is the signing key algorithm. Digest verification accepts ECDSA
algorithm labels `ES256`, `ES384`, and `ES512`; current digest hashing is
`sha256`.

## Stable Errors

The root package exports stable errors for mapping verification results to API
responses. Use `errors.Is` because errors may include additional context.

- Bad input or bad metadata: `ErrInvalidSBOM`, `ErrMissingSignature`,
  `ErrInvalidHashAlgorithm`, `ErrInvalidDigest`, `ErrInvalidKeyID`,
  `ErrInvalidSignature`, `ErrInvalidKey`, `ErrKeyNotFound`.
- Cryptographic verification failure: `ErrSignatureFail` for SBOM signatures and
  `ErrVerificationFailed` for digest signatures.

For HTTP APIs, bad input generally maps to `400 Bad Request`, missing keys to
`404 Not Found`, and cryptographic verification failures to `422 Unprocessable
Entity` or a domain-specific verification-failed response.

## Versioned Verification Semantics

Use `VerificationV2` for new integrations.

- `VerificationV1` preserves the original canonicalization behavior used by the
  source service. It is useful when verifying signatures produced by older
  signing flows.
- `VerificationV2` uses the newer canonicalization behavior and is the default
  recommendation for new signatures.

Migration note: keep verifying historical artifacts with the version used when
they were signed. Sign new CycloneDX embedded and SPDX detached artifacts with
`VerificationV2`, then update callers to pass `securesbomverifier.VerificationV2`.

```go
_, err = verifier.VerifyCycloneDXEmbeddedVersioned(signedSBOM, publicKeyPEM, securesbomverifier.VerificationV1)
_, err = verifier.VerifyCycloneDXEmbeddedVersioned(signedSBOM, publicKeyPEM, securesbomverifier.VerificationV2)
_, err = verifier.VerifySPDXDetachedVersioned(spdxSBOM, signatureB64, publicKeyPEM, securesbomverifier.VerificationV1)
_, err = verifier.VerifySPDXDetachedVersioned(spdxSBOM, signatureB64, publicKeyPEM, securesbomverifier.VerificationV2)
```

## Production Integration Example

See [examples/production-api/main.go](examples/production-api/main.go) for an
HTTP-style integration that fetches public key metadata, verifies CycloneDX,
SPDX detached, and digest requests, handles stable errors, and maps them to
responses.

## Contract Fixtures

The `testsupport` package provides reusable fixtures for downstream service
tests:

```go
fixtures := testsupport.NewContractFixtures(t)
```

The fixture set includes valid and invalid CycloneDX embedded signatures, SPDX
detached signatures, and digest signatures, along with public keys and expected
verification outcomes.

## Build Note

This project currently relies on `GOEXPERIMENT=jsonv2`, matching the behavior
already used by the source repository. The included `Makefile` sets that for the
common build and test flows.

## Container Image

Build the offline verification CLI as a container:

```bash
make docker-build
```

Run it locally:

```bash
docker run --rm \
  -v "$PWD:/work" \
  secure-sbom-verification-cli:dev \
  --sbom /work/path/to/signed-sbom.json \
  --pubkey /work/path/to/public.pem
```

## Optional CLI

The offline CLI is an optional command. Library consumers do not need to import
or build it. It lives at:

```text
cmd/sbom-offline-verification
```

Example:

```bash
GOEXPERIMENT=jsonv2 go run ./cmd/sbom-offline-verification \
  --sbom ./path/to/signed-sbom.json \
  --pubkey ./path/to/public.pem
```

For detached SPDX verification:

```bash
GOEXPERIMENT=jsonv2 go run ./cmd/sbom-offline-verification \
  --sbom ./path/to/sample.spdx.json \
  --signature BASE64_SIGNATURE \
  --pubkey ./path/to/public.pem \
  --verification-version v2
```

For digest verification:

```bash
GOEXPERIMENT=jsonv2 go run ./cmd/sbom-offline-verification \
  --digest BASE64_DIGEST \
  --signature BASE64_SIGNATURE \
  --pubkey ./path/to/public.pem \
  --hash-algorithm sha256 \
  --signature-algorithm ES256
```

## Releases

Tagged releases matching `vX.X.X` are built with Goreleaser using
[.goreleaser.yml](.goreleaser.yml). The release workflow publishes multi-platform
CLI archives, a checksum file, and a container image to GitHub-hosted release
surfaces. The container image is published to GitHub Container Registry as
`ghcr.io/<owner>/<repo>` for `linux/amd64` and `linux/arm64`, with tags for the
full version, `vMAJOR.MINOR`, `vMAJOR`, and `latest`.

## Examples

See [examples/library/main.go](examples/library/main.go) for a minimal embedding
example for CycloneDX verification, [examples/spdx-detached/main.go](examples/spdx-detached/main.go)
for SPDX detached verification, [examples/digest/main.go](examples/digest/main.go)
for digest verification, and [MIGRATION.md](MIGRATION.md) for a suggested next-step
extraction plan from `sbom-signing-api`.

The example programs expect you to provide signed content, signatures, and/or a
public key path at runtime depending on the verification mode.
