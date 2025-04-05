# Project-specific variables
BINARY_NAME := yed
OUTPUT_DIR := bin
CMD_DIR := cmd/yaml-encrypter-decrypter
TAG_NAME ?= $(shell head -n 1 .release-version 2>/dev/null || echo "v0.0.0")
VERSION_RAW ?= $(shell tail -n 1 .release-version 2>/dev/null || echo "dev")
VERSION ?= $(VERSION_RAW)

# Ensure the output directory exists
$(OUTPUT_DIR):
	@mkdir -p $(OUTPUT_DIR)

# Default target
.PHONY: default
default: fmt vet lint build quicktest

# Build and run the application locally
.PHONY: run
run:
	@echo "Running $(BINARY_NAME)..."
	go run main.go

# Install project dependencies
.PHONY: install-deps
install-deps:
	@echo "Installing dependencies..."
	go mod tidy
	go mod vendor

# Clean up dependencies
.PHONY: clean-deps
clean-deps:
	@echo "Cleaning up vendor dependencies..."
	rm -rf vendor

# Build the project for the current OS/architecture
.PHONY: build
build: $(OUTPUT_DIR)
	@echo "Building $(BINARY_NAME) with version $(VERSION)..."
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -ldflags="-X 'main.Version=$(VERSION)'" -o $(OUTPUT_DIR)/$(BINARY_NAME) $(CMD_DIR)/main.go

# Build binaries for multiple platforms
.PHONY: build-cross
build-cross: $(OUTPUT_DIR)
	@echo "Building cross-platform binaries..."
	GOOS=linux   GOARCH=amd64   go build -ldflags="-X 'main.Version=$(VERSION)'" -o $(OUTPUT_DIR)/$(BINARY_NAME)-linux-amd64 $(CMD_DIR)/main.go
	GOOS=darwin  GOARCH=arm64   go build -ldflags="-X 'main.Version=$(VERSION)'" -o $(OUTPUT_DIR)/$(BINARY_NAME)-darwin-arm64 $(CMD_DIR)/main.go
	GOOS=windows GOARCH=amd64   go build -ldflags="-X 'main.Version=$(VERSION)'" -o $(OUTPUT_DIR)/$(BINARY_NAME)-windows-amd64.exe $(CMD_DIR)/main.go
	@echo "Cross-platform binaries are available in $(OUTPUT_DIR):"
	@ls -1 $(OUTPUT_DIR)

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(OUTPUT_DIR)

# Run all tests with coverage and race detection
.PHONY: test
test:
	@echo "Running all tests with race detection and coverage..."
	go test -v -race -cover ./...

# Run quick tests without additional checks
.PHONY: quicktest
quicktest:
	@echo "Running quick tests..."
	go test ./...

# Run tests with coverage report
.PHONY: test-coverage
test-coverage:
	@echo "Running tests with coverage report..."
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Run tests with race detection
.PHONY: test-race
test-race:
	@echo "Running tests with race detection..."
	go test -v -race ./...

# Run benchmarks
.PHONY: test-benchmark
test-benchmark:
	@echo "Running benchmarks..."
	go test -v -bench=. -benchmem ./pkg/...

# Run all tests (coverage, race, and benchmarks)
.PHONY: test-all
test-all: test-coverage test-race test-benchmark

# Clean coverage files
.PHONY: clean-coverage
clean-coverage:
	@echo "Cleaning coverage files..."
	rm -f coverage.out coverage.html

# Check formatting of Go code
.PHONY: fmt
fmt:
	@echo "Checking code formatting..."
	@echo "Formatting pkg directory..."
	@go fmt -x ./pkg/...
	@echo "Formatting cmd directory..."
	@go fmt -x ./cmd/...

# Run go vet to analyze code
.PHONY: vet
vet:
	@echo "Running go vet..."
	go vet ./...

# Display help information
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  default         - Run formatting, vetting, linting, build, and quick tests"
	@echo "  run             - Run the application locally"
	@echo "  install-deps    - Install project dependencies"
	@echo "  clean-deps      - Clean up vendor dependencies"
	@echo "  build           - Build the application for the current OS/architecture"
	@echo "  build-cross     - Build binaries for multiple platforms"
	@echo "  clean           - Clean build artifacts"
	@echo "  test            - Run all tests with race detection and coverage"
	@echo "  quicktest       - Run quick tests without additional checks"
	@echo "  test-coverage   - Run tests with coverage report"
	@echo "  test-race       - Run tests with race detection"
	@echo "  test-benchmark  - Run benchmarks"
	@echo "  test-all        - Run all tests (coverage, race, and benchmarks)"
	@echo "  clean-coverage  - Clean coverage files"
	@echo "  fmt             - Check code formatting"
	@echo "  vet             - Analyze code with go vet"
	@echo "  help            - Display this help message"

.PHONY: test lint lint-fix install-lint

# Install golangci-lint
install-lint:
	@echo "Installing golangci-lint..."
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Run linter
lint:
	@echo "Running linter..."
	@~/go/bin/golangci-lint run

# Run linter with auto-fix
lint-fix:
	@echo "Running linter with auto-fix..."
	@~/go/bin/golangci-lint run --fix