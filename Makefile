BINARY_NAME ?= coraza-envoy-extproc
IMAGE_NAME ?= coraza-envoy-extproc
IMAGE_TAG ?= latest

.PHONY: help build image run clean verify-docker-compose verify test-integration

help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

build: ## Build the binary
	go build -o $(BINARY_NAME) ./cmd/coraza-envoy-extproc

image: ## Build the container image
	docker build -t $(IMAGE_NAME):$(IMAGE_TAG) .

verify-docker-compose: ## Verify that docker compose is available
	@command -v docker >/dev/null 2>&1 || { echo "Error: docker is not installed. Please install Docker: https://docs.docker.com/get-docker/"; exit 1; }
	@docker compose version >/dev/null 2>&1 || { echo "Error: 'docker compose' is not available. Please install Docker Compose v2: https://docs.docker.com/compose/install/"; exit 1; }

verify: ## Run static analysis (go vet, go fix)
	go vet ./...
	go fix ./...

run: verify-docker-compose ## Run the full stack with docker compose (Envoy + WAF + upstream)
	docker compose up --build

test-integration: verify-docker-compose ## Run integration tests (starts docker compose, runs tests, tears down)
	go test -v -count=1 -timeout 120s ./test/integration/

clean: ## Remove build artifacts
	rm -f $(BINARY_NAME)
