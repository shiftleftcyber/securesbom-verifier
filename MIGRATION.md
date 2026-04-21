# Migration Notes

This directory is a first extraction pass. It duplicates the verification logic
 so the API repository can keep working while the standalone project is shaped.

## Code That Was Duplicated

From `sbom-signing-api` into this module:

- `api/application/sbom_verify_application.go`
- `api/services/sbom/sbom_formatting.go`
- verification-specific parts of `api/services/digest/*`
- verification-specific parts of `api/services/ecdsa.go`
- `api/utils/key_utils.go`
- `api/cli/offline_verification/*`
- minimal key metadata types required by digest verification

## Code That Should Stay In The API Repo

- `api/handlers/*verify*`
- `api/services/verify/service.go`
- request auth and authorization helpers
- Firestore access and customer/key ownership checks
- HTTP contract models
- usage tracking and rate limiting

## Recommended Next Refactor

1. Introduce this module as a dependency in `api/go.mod`.
2. Update `api/application` usage sites to import the external module.
3. Leave `api/services/verify` in place, but change it to call the imported verifier.
4. Leave handlers unchanged except for import path updates caused by step 2.
5. Keep signing and key-generation logic in the API repo.
6. Remove duplicated verification internals from the API repo only after tests pass.

## Notes

- The package layout here intentionally mirrors the current repo in several areas
  to keep the migration low-risk.
- A later cleanup pass can introduce more polished public packages once the
  dependency boundary is proven in production.
- GitHub workflows have been staged under `.github/workflows` inside this
  extracted project. They are intended for the future standalone repository and
  will not run while this project remains nested under `sbom-signing-api`.
