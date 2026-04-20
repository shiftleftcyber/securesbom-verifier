BINARY_NAME ?= sbom-offline-verification
GOCACHE ?= $(CURDIR)/.gocache
GOEXPERIMENT ?= jsonv2
GOFILES := $(shell find . -name "*.go")
GOFMT ?= gofmt "-s"
DIST_DIR ?= dist
IMAGE_NAME ?= secure-sbom-verification-cli
IMAGE_TAG ?= dev

.PHONY: test coverage build-cli docker-build tidy clean

test:
	mkdir -p $(GOCACHE)
	GOEXPERIMENT=$(GOEXPERIMENT) GOCACHE=$(GOCACHE) go test ./...

build-cli:
	mkdir -p $(DIST_DIR) $(GOCACHE)
	GOEXPERIMENT=$(GOEXPERIMENT) GOCACHE=$(GOCACHE) go build -o $(DIST_DIR)/$(BINARY_NAME) ./cmd/sbom-offline-verification

coverage:
	mkdir -p $(GOCACHE)
	GOEXPERIMENT=$(GOEXPERIMENT) GOCACHE=$(GOCACHE) go test -coverprofile=coverage.out ./...
	GOEXPERIMENT=$(GOEXPERIMENT) GOCACHE=$(GOCACHE) go tool cover -func=coverage.out

docker-build:
	docker build --build-arg GOEXPERIMENT=$(GOEXPERIMENT) -t $(IMAGE_NAME):$(IMAGE_TAG) .

tidy:
	mkdir -p $(GOCACHE)
	GOEXPERIMENT=$(GOEXPERIMENT) GOCACHE=$(GOCACHE) go mod tidy

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
	@DOCKER run --rm -v $(shell pwd):/app -w /app --env GOEXPERIMENT=jsonv2 golangci/golangci-lint:v2.8.0-alpine golangci-lint run ./...
