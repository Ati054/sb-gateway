SHELL := /bin/sh

GO ?= go
NPM ?= npm
DOCKER ?= docker
IMAGE ?= sb-gateway:local
PLATFORM ?= linux/arm64
BUILDER ?=

YAML_FILES := gateway.example.yaml \
	config/gateway.yaml \
	config/users.yaml \
	config/networks.yaml \
	config/policies.yaml \
	config/subscriptions.yaml \
	config/rulesets.yaml

.PHONY: help validate validate-config validate-shipped verify-rulesets runtime-check test go-test ui-check \
	image image-bundle clean

help:
	@echo "Development:"
	@echo "  make validate      YAML/JSON/checksum validation"
	@echo "  make test          Go unit tests"
	@echo "  make go-test       Alias for Go unit tests"
	@echo "  make ui-check      Web UI lint/build/render tests"
	@echo "  make image         ARM64 OCI image"
	@echo "  make image-bundle  ARM64 Docker archive + SHA256 for RouterOS/WebFig"
	@echo "  make runtime-check Xray config check + nginx -t via preflight"

validate: validate-config validate-shipped verify-rulesets

validate-config:
	@$(GO) test ./internal/controlplane -run 'TestValidateCurrentConfigAcceptsShippedDefault' -count=1

validate-shipped:
	@$(GO) test ./internal/runtimeconfig ./internal/routeros -count=1

verify-rulesets:
	@$(GO) test ./internal/rulesets -count=1

runtime-check:
	@test -x scripts/preflight.sh || { echo "scripts/preflight.sh is missing or not executable"; exit 1; }
	@./scripts/preflight.sh

test:
	@$(GO) test ./cmd/... ./internal/... ./tests/tools

go-test:
	@$(GO) test ./cmd/... ./internal/...

ui-check:
	@$(NPM) run lint
	@$(NPM) test

image:
	@$(DOCKER) build --platform $(PLATFORM) --tag $(IMAGE) .

image-bundle:
	@$(GO) run ./cmd/routeros-image --engine $(DOCKER) $(if $(BUILDER),--builder $(BUILDER),) --output-dir dist/routeros

clean:
	@echo "No automatic cleanup: generated state, backups and exports may contain recovery data."
