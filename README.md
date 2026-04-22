# Secure SBOM Verifier

`securesbom-verifier` is a standalone Go module that contains the verification
logic currently embedded in the `sbom-signing-api` service. It is designed to be
published as an open source library and reused by:

- API servers that need SBOM verification business logic
- offline or air-gapped verification workflows
- other Go services that need digest signature verification
- command-line tooling

This staging copy is intentionally duplicated from the current repository so the
extraction can be iterated on without removing code from the API project yet.

## What This Project Contains

- CycloneDX embedded signature verification
- SPDX detached signature verification
- digest signature verification helpers
- JSON canonicalization helpers used during verification
- PEM normalization and key utility helpers
- an offline verification CLI
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

For digest verification, the current library API is exposed through the lower-level
`services/digest` package rather than the root wrapper:

```go
import (
  digestsigning "github.com/shiftleftcyber/securesbom-verifier/services/digest"
  "github.com/shiftleftcyber/securesbom-verifier/verificationkey"
)

validated, err := digestsigning.NewValidator().ValidateVerifyDigestRequest(
  digestsigning.VerifyDigestInput{
    KeyID:         "offline",
    HashAlgorithm: "sha256",
    Digest:        digestB64,
    Signature:     signatureB64,
  },
)
if err != nil {
  return err
}

err = digestsigning.NewCryptoVerifier().Verify(
  &verificationkey.KeyInfo{
    KeyID:     "offline",
    Algorithm: "ES256",
    PublicKey: string(publicKeyPEM),
  },
  validated.Digest,
  validated.Signature,
)
```

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

## CLI

The offline CLI lives at:

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
