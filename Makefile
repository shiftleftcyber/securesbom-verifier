GOCACHE ?= $(CURDIR)/.gocache
GOEXPERIMENT ?= jsonv2
IMAGE_NAME ?= secure-sbom-verification-cli
IMAGE_TAG ?= dev
BINARY_NAME ?= sbom-offline-verification
DIST_DIR ?= dist

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
