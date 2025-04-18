# Project-specific variables
BINARY_NAME := yed
OUTPUT_DIR := bin
CMD_DIR := cmd/yaml-encrypter-decrypter
TAG_NAME ?= $(shell head -n 1 .release-version 2>/dev/null || echo "v0.0.0")
VERSION_RAW ?= $(shell tail -n 1 .release-version 2>/dev/null || echo "dev")
VERSION ?= $(VERSION_RAW)
GO_FILES := $(wildcard $(CMD_DIR)/*.go)

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
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -ldflags="-X 'main.Version=$(VERSION)'" -o $(OUTPUT_DIR)/$(BINARY_NAME) ./$(CMD_DIR)

# Build binaries for multiple platforms
.PHONY: build-cross
build-cross: $(OUTPUT_DIR)
	@echo "Building cross-platform binaries..."
	GOOS=linux   GOARCH=amd64   go build -ldflags="-X 'main.Version=$(VERSION)'" -o $(OUTPUT_DIR)/$(BINARY_NAME)-linux-amd64 ./$(CMD_DIR)
	GOOS=darwin  GOARCH=arm64   go build -ldflags="-X 'main.Version=$(VERSION)'" -o $(OUTPUT_DIR)/$(BINARY_NAME)-darwin-arm64 ./$(CMD_DIR)
	GOOS=windows GOARCH=amd64   go build -ldflags="-X 'main.Version=$(VERSION)'" -o $(OUTPUT_DIR)/$(BINARY_NAME)-windows-amd64.exe ./$(CMD_DIR)
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

# Benchmark targets
.PHONY: benchmark benchmark-all benchmark-encryption benchmark-algorithms benchmark-argon2 benchmark-long

# Run all basic benchmarks
benchmark:
	@echo "Running benchmarks..."
	go test -v -bench=. -benchmem ./pkg/encryption

# Run comprehensive benchmarks with longer duration (5s per benchmark)
benchmark-long:
	@echo "Running comprehensive benchmarks (longer duration)..."
	go test -v -bench=. -benchmem -benchtime=5s ./pkg/encryption

# Run only encryption/decryption benchmarks
benchmark-encryption:
	@echo "Running encryption/decryption benchmarks..."
	go test -v -bench="BenchmarkEncrypt|BenchmarkDecrypt|BenchmarkEncryptionWithAlgorithms|BenchmarkDecryptionWithAlgorithms" -benchmem ./pkg/encryption

# Run key derivation algorithm comparison benchmarks
benchmark-algorithms:
	@echo "Running key derivation algorithm benchmarks..."
	go test -v -bench=KeyDerivationAlgorithms -benchmem ./pkg/encryption

# Run Argon2 configuration comparison benchmarks
benchmark-argon2:
	@echo "Running Argon2 configuration benchmarks..."
	go test -v -bench=BenchmarkArgon2Configs -benchmem ./pkg/encryption

# Generate a benchmark report in Markdown format
benchmark-report:
	@echo "Generating benchmark report..."
	@echo "# Benchmark Results" > benchmark-report.md
	@echo "\nGenerated on \`$$(date)\`\n" >> benchmark-report.md
	
	@echo "## Key Derivation Algorithms" >> benchmark-report.md
	@echo "| Algorithm | Operations/sec | Time (ns/op) | Memory (B/op) | Allocs/op |" >> benchmark-report.md
	@echo "|-----------|----------------|--------------|---------------|-----------|" >> benchmark-report.md
	@go test -bench=KeyDerivationAlgorithms -benchmem ./pkg/encryption 2>/dev/null | grep "Benchmark" | sed 's/BenchmarkKeyDerivationAlgorithms\///g' | sed 's/\-[0-9]*//g' | sed 's/PBKDF2SHA256/PBKDF2-SHA256/g' | sed 's/PBKDF2SHA512/PBKDF2-SHA512/g' | awk '{print "| " $$1 " | " $$2 " | " $$3 " " $$4 " | " $$5 " " $$6 " | " $$7 " " $$8 " |"}' >> benchmark-report.md
	@echo "" >> benchmark-report.md
	
	@echo "## Argon2 Configurations" >> benchmark-report.md
	@echo "| Configuration | Operations/sec | Time (ns/op) | Memory (B/op) | Allocs/op |" >> benchmark-report.md
	@echo "|--------------|----------------|--------------|---------------|-----------|" >> benchmark-report.md
	@go test -bench=BenchmarkArgon2Configs -benchmem ./pkg/encryption 2>/dev/null | grep "Benchmark" | sed 's/BenchmarkArgon2Configs\///g' | sed 's/\-[0-9]*//g' | sed 's/OWASPcurrent/OWASP-1-current/g' | sed 's/OWASP-2-12/OWASP-2/g' | sed 's/OWASP-3-12/OWASP-3/g' | sed 's/PreviousConfig/Previous-Config/g' | awk '{print "| " $$1 " | " $$2 " | " $$3 " " $$4 " | " $$5 " " $$6 " | " $$7 " " $$8 " |"}' >> benchmark-report.md
	@echo "" >> benchmark-report.md
	
	@echo "## Basic Encryption and Decryption" >> benchmark-report.md
	@echo "| Operation | Operations/sec | Time (ns/op) | Memory (B/op) | Allocs/op |" >> benchmark-report.md
	@echo "|-----------|----------------|--------------|---------------|-----------|" >> benchmark-report.md
	@go test -bench="^BenchmarkEncrypt$$|^BenchmarkDecrypt$$" -benchmem ./pkg/encryption 2>/dev/null | grep "Benchmark" | sed 's/Benchmark//g' | sed 's/\-[0-9]*//g' | awk '{print "| " $$1 " | " $$2 " | " $$3 " " $$4 " | " $$5 " " $$6 " | " $$7 " " $$8 " |"}' >> benchmark-report.md
	@echo "" >> benchmark-report.md
	
	@echo "## Encryption with Different Algorithms" >> benchmark-report.md
	@echo "| Algorithm | Operations/sec | Time (ns/op) | Memory (B/op) | Allocs/op |" >> benchmark-report.md
	@echo "|-----------|----------------|--------------|---------------|-----------|" >> benchmark-report.md
	@go test -bench="BenchmarkEncryptionWithAlgorithms" -benchmem ./pkg/encryption 2>/dev/null | grep "Benchmark" | sed 's/BenchmarkEncryptionWithAlgorithms\///g' | sed 's/\-[0-9]*//g' | sed 's/pbkdf2sha256/pbkdf2-sha256/g' | sed 's/pbkdf2sha512/pbkdf2-sha512/g' | awk '{print "| " $$1 " | " $$2 " | " $$3 " " $$4 " | " $$5 " " $$6 " | " $$7 " " $$8 " |"}' >> benchmark-report.md
	@echo "" >> benchmark-report.md
	
	@echo "## Decryption with Different Algorithms" >> benchmark-report.md
	@echo "| Algorithm | Operations/sec | Time (ns/op) | Memory (B/op) | Allocs/op |" >> benchmark-report.md
	@echo "|-----------|----------------|--------------|---------------|-----------|" >> benchmark-report.md
	@go test -bench="BenchmarkDecryptionWithAlgorithms" -benchmem ./pkg/encryption 2>/dev/null | grep "Benchmark" | sed 's/BenchmarkDecryptionWithAlgorithms\///g' | sed 's/\-[0-9]*//g' | sed 's/pbkdf2sha256/pbkdf2-sha256/g' | sed 's/pbkdf2sha512/pbkdf2-sha512/g' | awk '{print "| " $$1 " | " $$2 " | " $$3 " " $$4 " | " $$5 " " $$6 " | " $$7 " " $$8 " |"}' >> benchmark-report.md
	@echo "" >> benchmark-report.md
	
	@echo "Benchmark report generated: benchmark-report.md"

# Run all benchmarks and tests
.PHONY: test-all
test-all: test-coverage test-race benchmark

# Clean coverage files
.PHONY: clean-coverage
clean-coverage:
	@echo "Cleaning coverage files..."
	rm -f coverage.out coverage.html benchmark-report.md

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
	@echo "  benchmark       - Run basic benchmarks"
	@echo "  benchmark-long  - Run comprehensive benchmarks with longer duration"
	@echo "  benchmark-encryption - Run only encryption/decryption benchmarks"
	@echo "  benchmark-algorithms - Run key derivation algorithm comparison benchmarks"
	@echo "  benchmark-argon2 - Run Argon2 configuration comparison benchmarks"
	@echo "  benchmark-report - Generate a markdown report of all benchmarks"
	@echo "  test-all        - Run all tests and benchmarks"
	@echo "  clean-coverage  - Clean coverage and benchmark files"
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