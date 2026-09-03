.PHONY: all build test lint fmt clean container dev frontend sbom

VERSION ?= 0.1.0
IMAGE ?= policybridge:latest
GO ?= go
GOLANGCI_LINT ?= golangci-lint

LDFLAGS = -ldflags "-X github.com/policybridge/policybridge/internal/version.Version=$(VERSION)"

all: build

build: frontend
	$(GO) build $(LDFLAGS) -o bin/policybridge ./cmd/policybridge

frontend:
	@if [ -f web/package.json ] && command -v npm >/dev/null 2>&1; then \
		cd web && npm ci --silent 2>/dev/null || npm install --silent; \
		npm run build; \
	else \
		echo "Using pre-built static assets in cmd/policybridge/static/"; \
	fi

test:
	$(GO) test ./... -count=1 -timeout 120s

test-integration:
	$(GO) test ./internal/api/... -count=1 -timeout 180s -tags=integration

lint:
	$(GOLANGCI_LINT) run ./...
	cd web && npm run lint 2>/dev/null || true

fmt:
	$(GO) fmt ./...
	cd web && npm run format 2>/dev/null || true

clean:
	rm -rf bin/ dist/
	$(GO) clean ./...

container:
	podman build -t $(IMAGE) -f Containerfile --build-arg VERSION=$(VERSION) .

container-run:
	podman run --rm -p 127.0.0.1:8080:8080 $(IMAGE)

dev:
	$(GO) run $(LDFLAGS) ./cmd/policybridge

sbom:
	syft $(IMAGE) -o spdx-json=sbom.spdx.json 2>/dev/null || echo "Install syft for SBOM generation"

mod:
	$(GO) mod tidy
	$(GO) mod verify

download-fixtures:
	@mkdir -p testdata/nsx
	@curl -fsSL -o testdata/nsx/Example1.json \
		https://raw.githubusercontent.com/np-guard/vmware-analyzer/v0.2.1/pkg/data/json/Example1.json
	@curl -fsSL -o testdata/nsx/Example2.json \
		https://raw.githubusercontent.com/np-guard/vmware-analyzer/v0.2.1/pkg/data/json/Example2.json
	@curl -fsSL -o testdata/nsx/one_redundant_covered_by_2_rules.json \
		https://raw.githubusercontent.com/np-guard/vmware-analyzer/v0.2.1/pkg/data/json/one_redundant_covered_by_2_rules.json
	@echo "Fixtures downloaded to testdata/nsx/"

.DEFAULT_GOAL := all
