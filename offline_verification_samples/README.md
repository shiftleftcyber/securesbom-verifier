# Offline Verification Samples

This directory contains sample artifacts for manually exercising the
`sbom-offline-verification` CLI without calling any remote service. Each sample
uses the same public key in `pubkey.pem`.

The examples cover:

- CycloneDX with an embedded signature
- AI-BOM with an embedded signature
- SPDX with a detached signature
- digest verification with a detached signature

## Build the CLI

From the repository root:

```bash
make build-cli
```

This writes the binary to:

```text
dist/sbom-offline-verification
```

The commands below assume you are running them from this
`offline_verification_samples` directory.

```bash
cd offline_verification_samples
```

## CycloneDX

CycloneDX signatures are embedded in the SBOM JSON, so only the signed SBOM and
public key are required.

```bash
../dist/sbom-offline-verification \
  --pubkey pubkey.pem \
  --sbom sample.cdx.signed.json
```

## AI-BOM

AI-BOM signatures are also embedded in the JSON document. The verifier detects
the file as `AI-SBOM` and verifies the `metadata.sbomAuthorSignature` value.
AI-BOM verification uses the default `v2` verification mode.

```bash
../dist/sbom-offline-verification \
  --pubkey pubkey.pem \
  --sbom sample.aibom.signed.json
```

## SPDX

SPDX verification uses a detached signature, so pass the unsigned SPDX JSON and
the base64 signature from `sample.spdx.sig`.

```bash
../dist/sbom-offline-verification \
  --pubkey pubkey.pem \
  --sbom sample.spdx.json \
  --signature "$(cat sample.spdx.sig)"
```

## Digest

Digest verification checks a base64-encoded digest and its detached signature.
The CLI defaults to `sha256` and `ES256`, which match these samples.

```bash
../dist/sbom-offline-verification \
  --pubkey pubkey.pem \
  --digest "$(cat digest.txt)" \
  --signature "$(cat digest.sig)"
```

## Expected Result

Successful verification prints a `VERIFICATION SUCCESSFUL` block that includes
the verification mode, artifact type, signing algorithm, and confirmation that
the public key was accepted.

If verification fails, the tool exits non-zero and prints a
`VERIFICATION FAILED` block with the reason. Common causes are using the wrong
public key, modifying a signed artifact, or omitting the detached signature for
SPDX and digest verification.
