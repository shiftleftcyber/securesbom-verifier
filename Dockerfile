FROM golang:1.25.11-alpine3.23@sha256:c05ba4b73604069d376c4f41346b05374335b5ca0c46fb6dfede5a59f5196931 AS builder

ARG GOEXPERIMENT=jsonv2
ARG TARGETOS=linux
ARG TARGETARCH=amd64

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} GOEXPERIMENT=${GOEXPERIMENT} \
    go build -o /out/sbom-offline-verification ./cmd/sbom-offline-verification

FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /
COPY --from=builder /out/sbom-offline-verification /usr/local/bin/sbom-offline-verification

ENTRYPOINT ["/usr/local/bin/sbom-offline-verification"]
