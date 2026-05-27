FROM golang:1.25.10-alpine3.23@sha256:8d22e29d960bc50cd025d93d5b7c7d220b1ee9aa7a239b3c8f55a57e987e8d45 AS builder

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
