# Vigil — local-first vulnerability intelligence
#
# Convention: every repo exposes a unified `make run` (one-stop run-the-app)
# and `make setup` (one-time setup). Keep those two working above all else.

BINARY := vigil
PKG    := ./cmd/vigil
BIN    := ./bin/$(BINARY)

.DEFAULT_GOAL := help

## run: build and run the CLI (pass ARGS="scan --service foo")
.PHONY: run
run:
	@go run $(PKG) $(ARGS)

## setup: one-time setup — install deps and scaffold local config/store
.PHONY: setup
setup:
	@go mod download
	@go run $(PKG) init || true
	@echo "setup complete — edit ~/.config/vigil/config.toml, then 'make run ARGS=refresh'"

## build: compile a release binary to ./bin/vigil
.PHONY: build
build:
	@mkdir -p bin
	@go build -ldflags "-X github.com/bmsandoval/vigil/internal/cmd.version=$(shell git describe --tags --always --dirty 2>/dev/null || echo dev)" -o $(BIN) $(PKG)
	@echo "built $(BIN)"

## test: run the test suite
.PHONY: test
test:
	@go test ./...

## tidy: sync go.mod/go.sum
.PHONY: tidy
tidy:
	@go mod tidy

## help: list targets
.PHONY: help
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  /'
