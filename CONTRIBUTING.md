# Contributing

## Development

```bash
go test ./...
go build ./cmd/sbom-offline-verification
```

## Design Intent

- keep transport concerns out of this module
- keep tenancy and infrastructure lookups out of this module
- keep cryptographic verification and canonicalization in this module

## Pull Requests

Please include:

- tests for new verification logic
- fixture or reproduction details for bug fixes
- notes about backwards compatibility when public package APIs change
