BINARY_NAME ?= sbom-offline-verification
GOCACHE ?= $(CURDIR)/.gocache
GOMODCACHE ?= $(GOCACHE)/pkg/mod
GOEXPERIMENT ?= jsonv2
GOFILES := $(shell find . \( -path './.git' -o -path './.gocache' -o -path './dist' -o -path './vendor' \) -prune -o -type f -name "*.go" -print)
GOFMT ?= gofmt "-s"
DIST_DIR ?= dist
IMAGE_NAME ?= secure-sbom-verification-cli
IMAGE_TAG ?= dev
GOVULNCHECK_SCAN ?= package
GOLANGCI_LINT ?= golangci-lint

.PHONY: test coverage build-cli docker-build tidy vulncheck goreleaser-dryrun clean

test:
	mkdir -p $(GOCACHE)
	GOEXPERIMENT=$(GOEXPERIMENT) GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go test ./...

build-cli:
	mkdir -p $(DIST_DIR) $(GOCACHE)
	GOEXPERIMENT=$(GOEXPERIMENT) GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go build -o $(DIST_DIR)/$(BINARY_NAME) ./cmd/sbom-offline-verification

goreleaser-dryrun:
	mkdir -p $(GOCACHE)
	GOEXPERIMENT=$(GOEXPERIMENT) GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) goreleaser release --snapshot --clean

coverage:
	mkdir -p $(GOCACHE)
	GOEXPERIMENT=$(GOEXPERIMENT) GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go test -coverprofile=coverage.out ./...
	GOEXPERIMENT=$(GOEXPERIMENT) GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go tool cover -func=coverage.out

docker-build:
	docker build --build-arg GOEXPERIMENT=$(GOEXPERIMENT) -t $(IMAGE_NAME):$(IMAGE_TAG) .

tidy:
	mkdir -p $(GOCACHE)
	GOEXPERIMENT=$(GOEXPERIMENT) GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go mod tidy

vulncheck:
	mkdir -p $(GOCACHE)
	GOEXPERIMENT=$(GOEXPERIMENT) GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) govulncheck -scan=$(GOVULNCHECK_SCAN) ./...

clean:
	chmod -R u+w $(GOCACHE) 2>/dev/null || true
	rm -rf $(GOCACHE) $(DIST_DIR) coverage.out $(BINARY_NAME) 2>/dev/null || true

.PHONY: fmt
fmt:
	$(GOFMT) -w $(GOFILES)

.PHONY: fmt-check
fmt-check:
	@diff=$$($(GOFMT) -d $(GOFILES)); \
	if [ -n "$$diff" ]; then \
		echo "Please run 'make fmt' and commit the result:"; \
		echo "$${diff}"; \
		exit 1; \
	fi;

.PHONY: lint
lint:
	@docker run --rm -v $(shell pwd):/app -w /app --env GOEXPERIMENT=jsonv2 golangci/golangci-lint:v2.8.0-alpine $(GOLANGCI_LINT) run ./...
