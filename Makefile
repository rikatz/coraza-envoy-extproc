BINARY_NAME ?= coraza-envoy-extproc
IMAGE_NAME ?= coraza-envoy-extproc
IMAGE_TAG ?= latest
GOLANGCI_LINT_VERSION ?= v2.11.4
CRS_VERSION ?= v4.25.0
CRS_VERSION_NUM = $(subst v,,$(CRS_VERSION))
CRS_DIR = tmp/coreruleset-$(CRS_VERSION_NUM)
CRS_RULES_DIR = tmp/crs-rules
CRS_LOGFILE = $(CURDIR)/tmp/logs/error.log
GO_FTW_VERSION ?= v2.1.0

.PHONY: help build image run clean verify-docker-compose verify lint test-integration download-crs setup-crs run-crs ftw

help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

build: ## Build the binary
	go build -o $(BINARY_NAME) ./cmd/coraza-envoy-extproc

image: ## Build the container image
	docker build -t $(IMAGE_NAME):$(IMAGE_TAG) .

verify-docker-compose: ## Verify that docker compose is available
	@command -v docker >/dev/null 2>&1 || { echo "Error: docker is not installed. Please install Docker: https://docs.docker.com/get-docker/"; exit 1; }
	@docker compose version >/dev/null 2>&1 || { echo "Error: 'docker compose' is not available. Please install Docker Compose v2: https://docs.docker.com/compose/install/"; exit 1; }

verify: lint ## Run static analysis (go vet, go fix)
	go vet ./...
	go fix ./...

GOLANGCI_LINT = $(shell go env GOPATH)/bin/golangci-lint

lint: $(GOLANGCI_LINT) ## Run golangci-lint
	$(GOLANGCI_LINT) run ./...

$(GOLANGCI_LINT): ## Install golangci-lint using go install
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

run: verify-docker-compose ## Run the full stack with docker compose (Envoy + WAF + upstream)
	docker compose up --build

test-integration: verify-docker-compose ## Run integration tests (starts docker compose, runs tests, tears down)
	go test -v -count=1 -timeout 120s ./test/integration/

download-crs: ## Download CoreRuleSet to tmp/
	@mkdir -p tmp
	@if [ ! -d "$(CRS_DIR)" ]; then \
		echo "Downloading CoreRuleSet $(CRS_VERSION)..."; \
		curl -sL https://github.com/coreruleset/coreruleset/archive/refs/tags/$(CRS_VERSION).tar.gz | tar xz -C tmp; \
	else \
		echo "CoreRuleSet $(CRS_VERSION) already downloaded"; \
	fi

CORAZA_VERSION = $(shell grep 'corazawaf/coraza' go.mod | awk '{print $$2}')
CORAZA_CONF_RECOMMENDED = $(shell go env GOMODCACHE)/github.com/corazawaf/coraza/v3@$(CORAZA_VERSION)/coraza.conf-recommended

setup-crs: download-crs ## Assemble CRS rules in tmp/ for FTW testing
	@rm -rf $(CRS_RULES_DIR)
	@mkdir -p $(CRS_RULES_DIR)/rules
	@cp config/crs/crs-ftw.conf $(CRS_RULES_DIR)/default.conf
	@cp $(CORAZA_CONF_RECOMMENDED) $(CRS_RULES_DIR)/coraza.conf-recommended
	@cp $(CRS_DIR)/crs-setup.conf.example $(CRS_RULES_DIR)/crs-setup.conf
	@cp -r $(CRS_DIR)/rules/* $(CRS_RULES_DIR)/rules/
	@echo "CRS rules assembled in $(CRS_RULES_DIR)"

run-crs: setup-crs verify-docker-compose ## Run with CRS rules for conformance testing
	RULES_DIR=$(CURDIR)/$(CRS_RULES_DIR) docker compose up --build $(DOCKER_COMPOSE_FLAGS)

GO_FTW = $(shell go env GOPATH)/bin/go-ftw

$(GO_FTW): ## Install go-ftw
	go install github.com/coreruleset/go-ftw/v2@$(GO_FTW_VERSION)

ftw: setup-crs $(GO_FTW) verify-docker-compose ## Run CRS FTW conformance tests
	@mkdir -p tmp/logs
	@rm -f $(CRS_LOGFILE)
	@touch $(CRS_LOGFILE)
	@echo "Starting environment in background..."
	RULES_DIR=$(CURDIR)/$(CRS_RULES_DIR) docker compose -f docker-compose.yaml -f docker-compose.ftw.yaml up --build -d
	@echo "Waiting for services to be ready..."
	@for i in $$(seq 1 30); do \
		if curl -sf http://localhost:8000/ > /dev/null 2>&1; then \
			echo "Services are ready."; \
			break; \
		fi; \
		if [ $$i -eq 30 ]; then \
			echo "Error: services did not become ready in time"; \
			docker compose logs; \
			docker compose -f docker-compose.yaml -f docker-compose.ftw.yaml down; \
			exit 1; \
		fi; \
		sleep 1; \
	done
	@echo "Running FTW tests..."
	$(GO_FTW) run -d $(CRS_DIR)/tests/regression/tests --config config/ftw/ftw.yaml --log-file $(CRS_LOGFILE) --overrides config/ftw/overrides.yml; \
		STATUS=$$?; \
		docker compose -f docker-compose.yaml -f docker-compose.ftw.yaml down; \
		exit $$STATUS

clean: ## Remove build artifacts
	rm -f $(BINARY_NAME)
	rm -rf tmp
