# SecureSBOM Attestation Signing Profile (`securesbom-attestation-v1`)

This profile defines how SecureSBOM binds an SBOM to the artifact it
describes. Signers and verifiers that follow it produce and accept the same
bytes. The `attestation` package in this repository is the reference
implementation.

## What an attestation proves

A valid attestation proves:

- which key signed it;
- that the Statement has not changed since signing;
- which artifact digests (`subject`) the SBOM is bound to;
- when signed by a SecureSBOM attestation key, that the SecureSBOM attestation
  service produced it after the checks listed under "Signer checks".

It does not prove that the SBOM is complete or accurate, that the subject
digest is the artifact the SBOM was generated from (the digest is the signer's
claim), or anything about how the artifact was built.

## Statement

An [in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md):

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    { "name": "registry.example.com/app", "digest": { "sha256": "<64 lowercase hex>" } }
  ],
  "predicateType": "https://cyclonedx.org/bom",
  "predicate": { "bomFormat": "CycloneDX", "...": "..." }
}
```

Rules:

1. `_type` is exactly `https://in-toto.io/Statement/v1`. No other top-level
   fields are allowed.
2. `subject` has 1 to 64 entries. Each `name` is 1 to 512 bytes of printable
   UTF-8. Each `digest` holds exactly one entry, `sha256`, as 64 lowercase hex
   characters, not all zeros. Digests are unique across subjects.
3. `predicateType` is one of:

   | SBOM format | `predicateType` |
   | --- | --- |
   | CycloneDX | `https://cyclonedx.org/bom` |
   | SPDX | `https://spdx.dev/Document` |
   | SecureSBOM AI-SBOM | `https://shiftleftcyber.io/attestation/ai-sbom/v1` |

   The predicate must be a valid SBOM of that format.
4. `predicate` is the SBOM document itself. An inner SBOM signature is either
   embedded in it the way the format defines (CycloneDX `signature`, AI-SBOM
   `metadata.sbomAuthorSignature`) or kept outside the envelope as a detached
   signature. It is never an extra Statement field.

## Payload encoding

The payload is the [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) (JCS)
canonical form of the Statement. Input JCS cannot represent faithfully is
rejected rather than changed: duplicate member names, and integer literals
whose magnitude exceeds 2^53.

## Envelope and signature

The payload is wrapped in a [DSSE v1](https://github.com/secure-systems-lab/dsse/blob/master/envelope.md)
envelope:

```json
{
  "payloadType": "application/vnd.in-toto+json",
  "payload": "<standard base64 of the canonical Statement>",
  "signatures": [{ "keyid": "<SecureSBOM key id>", "sig": "<standard base64>" }]
}
```

- The signed bytes are the DSSE pre-authentication encoding:
  `"DSSEv1" SP LEN(payloadType) SP payloadType SP LEN(payload) SP payload`,
  where `LEN` is the byte length as ASCII decimal.
- `ES256` keys: ECDSA P-256 over SHA-256 of the PAE bytes; `sig` is the
  ASN.1 DER signature.
- Exactly one signature per envelope. The serialized envelope's media type is
  `application/vnd.dsse.envelope.v1+json`.

## Signer checks

The SecureSBOM API, before signing with an attestation key:

1. validates the SBOM with `sbom-validator` and derives the predicate type from
   the result (never from the caller);
2. validates subjects against rule 2;
3. rejects an SBOM that already carries an embedded signature;
4. applies the requested inner signature (`embedded`, `detached` or `none`)
   before building the Statement, so the outer signature covers it;
5. verifies the finished envelope with this library before returning it.

## Verifier checks

Verifiers run these checks in order and stop at the first failure. The caller
must resolve the artifact digest independently and pass it in; the digest in
the Statement is never trusted on its own.

1. The expected digest is present and well-formed.
2. The envelope parses, `payloadType` is `application/vnd.in-toto+json`, and it
   has exactly one signature with a `keyid`.
3. The signature `keyid` matches the verification key's ID, when known.
4. The signature verifies over the PAE bytes.
5. The payload is byte-identical to its canonical form.
6. The Statement follows rules 1 and 2.
7. `predicateType` is supported and matches the predicate's format.
8. A subject's `sha256` equals the expected digest.
9. An embedded inner signature, when present, verifies; a detached one, when
   supplied, verifies.

The predicate is returned only after every check passes.
