# Project-specific variables
BINARY_NAME := yed
OUTPUT_DIR := bin
CMD_DIR := cmd/yaml-encrypter-decrypter
TAG_NAME ?= $(shell head -n 1 .release-version 2>/dev/null || echo "v0.0.0")
VERSION_RAW ?= $(shell tail -n 1 .release-version 2>/dev/null || echo "dev")
VERSION ?= $(VERSION_RAW)
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)
GO_FILES := $(wildcard $(CMD_DIR)/*.go)

# Ensure the output directory exists
$(OUTPUT_DIR):
	@mkdir -p $(OUTPUT_DIR)

# Default target
.PHONY: default
default: fmt vet lint staticcheck build quicktest

# Build and run the application locally
.PHONY: run
run:
	@echo "Running $(BINARY_NAME)..."
	go run main.go

.PHONY: test-manual
test-manual: build test-manual-check
# Manual testing of files in .test directory
.PHONY: test-manual-check
test-manual-check:
	@echo "Running manual tests for cert-test.yml..."
	@echo "Creating a copy of the test file for safe testing..."
	@cp -f .test/cert-test.yml .test/cert-test-copy.yml
	@cp -f .test/variables.yml .test/variables-copy.yml
	@echo "Step 1: Testing with dry-run mode on the copy..."
	$(OUTPUT_DIR)/$(BINARY_NAME) --dry-run --config=.test/.yed_config.yml --file=.test/cert-test-copy.yml --operation=encrypt
	$(OUTPUT_DIR)/$(BINARY_NAME) --dry-run --config=.test/.yed_config.yml --file=.test/variables-copy.yml --operation=encrypt
	@echo "Step 2: Testing in debug mode without dry-run on the copy..."
	$(OUTPUT_DIR)/$(BINARY_NAME) --debug --config=.test/.yed_config.yml --file=.test/cert-test-copy.yml --operation=encrypt
	$(OUTPUT_DIR)/$(BINARY_NAME) --debug --config=.test/.yed_config.yml --file=.test/variables-copy.yml --operation=encrypt
	@echo "Step 3: Testing decrypt operation on the copy..."
	$(OUTPUT_DIR)/$(BINARY_NAME) --debug --config=.test/.yed_config.yml --file=.test/cert-test-copy.yml --operation=decrypt
	@echo "Tests completed. Original file was preserved, changes were made to .test/cert-test-copy.yml"

# Install project dependencies
.PHONY: install-deps
install-deps:
	@echo "Installing dependencies..."
	go mod tidy
	go mod vendor

# Upgrade all project dependencies to their latest versions
.PHONY: upgrade-deps
upgrade-deps:
	@echo "Upgrading all dependencies to latest versions..."
	go get -u ./...
	go mod tidy
	go mod vendor
	@echo "Dependencies upgraded. Please test thoroughly before committing!"

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
.PHONY: benchmark benchmark-all benchmark-encryption benchmark-argon2 benchmark-long

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
	@go test -bench=KeyDerivationAlgorithms -benchmem ./pkg/encryption 2>/dev/null | grep "Benchmark" | grep -v "\[DEBUG" | sed 's/BenchmarkKeyDerivationAlgorithms\///g' | sed 's/\-[0-9]*//g' | sed 's/PBKDF2SHA256/pbkdf2sha256/g' | sed 's/PBKDF2SHA512/pbkdf2sha512/g' | awk '{print "| " $$1 " | " $$2 " | " $$3 " " $$4 " | " $$5 " " $$6 " | " $$7 " " $$8 " |"}' >> benchmark-report.md
	@echo "" >> benchmark-report.md
	
	@echo "## Argon2 Configurations" >> benchmark-report.md
	@echo "| Configuration | Operations/sec | Time (ns/op) | Memory (B/op) | Allocs/op |" >> benchmark-report.md
	@echo "|--------------|----------------|--------------|---------------|-----------|" >> benchmark-report.md
	@go test -bench=BenchmarkArgon2Configs -benchmem ./pkg/encryption 2>/dev/null | grep "Benchmark" | grep -v "\[DEBUG" | sed 's/BenchmarkArgon2Configs\///g' | sed 's/\-[0-9]*//g' | sed 's/OWASPcurrent/OWASP-1-current/g' | sed 's/OWASP-2-12/OWASP-2/g' | sed 's/OWASP-3-12/OWASP-3/g' | sed 's/PreviousConfig/Previous-Config/g' | awk '{print "| " $$1 " | " $$2 " | " $$3 " " $$4 " | " $$5 " " $$6 " | " $$7 " " $$8 " |"}' >> benchmark-report.md
	@echo "" >> benchmark-report.md
	
	@echo "## Basic Encryption and Decryption" >> benchmark-report.md
	@echo "| Operation | Operations/sec | Time (ns/op) | Memory (B/op) | Allocs/op |" >> benchmark-report.md
	@echo "|-----------|----------------|--------------|---------------|-----------|" >> benchmark-report.md
	@# Directly extract results from test benchmarks and format them properly
	@go test -bench="^BenchmarkEncrypt$$" -benchmem ./pkg/encryption 2>/dev/null | grep -v "\[DEBUG" | grep "BenchmarkEncrypt-" | awk '{print "| Encrypt | " $$3 " | " $$4 " " $$5 " | " $$6 " " $$7 " | " $$8 " " $$9 " |"}' >> benchmark-report.md
	@go test -bench="^BenchmarkDecrypt$$" -benchmem ./pkg/encryption 2>/dev/null | grep -v "\[DEBUG" | grep "BenchmarkDecrypt-" | awk '{print "| Decrypt | " $$3 " | " $$4 " " $$5 " | " $$6 " " $$7 " | " $$8 " " $$9 " |"}' >> benchmark-report.md
	@echo "" >> benchmark-report.md
	
	@echo "## Encryption with Different Algorithms" >> benchmark-report.md
	@echo "| Algorithm | Operations/sec | Time (ns/op) | Memory (B/op) | Allocs/op |" >> benchmark-report.md
	@echo "|-----------|----------------|--------------|---------------|-----------|" >> benchmark-report.md
	@# Create a temporary file for results
	@go test -bench="BenchmarkEncryptionWithAlgorithms/" -benchmem ./pkg/encryption 2>/dev/null > tmp_bench_encrypt.txt
	@# Extract results for argon2id
	@cat tmp_bench_encrypt.txt | grep "BenchmarkEncryptionWithAlgorithms/argon2id" | grep -v "\[DEBUG" | tail -1 | sed 's/.*BenchmarkEncryptionWithAlgorithms\/\(argon2id\)[^ ]*/\1/' | awk '{print "| argon2id | " $$1 " | " $$2 " " $$3 " | " $$4 " " $$5 " | " $$6 " " $$7 " |"}' >> benchmark-report.md
	@# Extract results for pbkdf2-sha256
	@cat tmp_bench_encrypt.txt | grep "BenchmarkEncryptionWithAlgorithms/pbkdf2-sha256" | grep -v "\[DEBUG" | tail -1 | sed 's/.*BenchmarkEncryptionWithAlgorithms\/\(pbkdf2-sha256\)[^ ]*/\1/' | awk '{print "| pbkdf2-sha256 | " $$1 " | " $$2 " " $$3 " | " $$4 " " $$5 " | " $$6 " " $$7 " |"}' >> benchmark-report.md
	@# Extract results for pbkdf2-sha512
	@cat tmp_bench_encrypt.txt | grep "BenchmarkEncryptionWithAlgorithms/pbkdf2-sha512" | grep -v "\[DEBUG" | tail -1 | sed 's/.*BenchmarkEncryptionWithAlgorithms\/\(pbkdf2-sha512\)[^ ]*/\1/' | awk '{print "| pbkdf2-sha512 | " $$1 " | " $$2 " " $$3 " | " $$4 " " $$5 " | " $$6 " " $$7 " |"}' >> benchmark-report.md
	@rm tmp_bench_encrypt.txt
	@echo "" >> benchmark-report.md
	
	@echo "## Decryption with Different Algorithms" >> benchmark-report.md
	@echo "| Algorithm | Operations/sec | Time (ns/op) | Memory (B/op) | Allocs/op |" >> benchmark-report.md
	@echo "|-----------|----------------|--------------|---------------|-----------|" >> benchmark-report.md
	@# Create a temporary file for results
	@go test -bench="BenchmarkDecryptionWithAlgorithms/" -benchmem ./pkg/encryption 2>/dev/null > tmp_bench_decrypt.txt
	@# Extract results for argon2id
	@cat tmp_bench_decrypt.txt | grep "BenchmarkDecryptionWithAlgorithms/argon2id" | grep -v "\[DEBUG" | tail -1 | sed 's/.*BenchmarkDecryptionWithAlgorithms\/\(argon2id\)[^ ]*/\1/' | awk '{print "| argon2id | " $$1 " | " $$2 " " $$3 " | " $$4 " " $$5 " | " $$6 " " $$7 " |"}' >> benchmark-report.md
	@# Extract results for pbkdf2-sha256
	@cat tmp_bench_decrypt.txt | grep "BenchmarkDecryptionWithAlgorithms/pbkdf2-sha256" | grep -v "\[DEBUG" | tail -1 | sed 's/.*BenchmarkDecryptionWithAlgorithms\/\(pbkdf2-sha256\)[^ ]*/\1/' | awk '{print "| pbkdf2-sha256 | " $$1 " | " $$2 " " $$3 " | " $$4 " " $$5 " | " $$6 " " $$7 " |"}' >> benchmark-report.md
	@# Extract results for pbkdf2-sha512
	@cat tmp_bench_decrypt.txt | grep "BenchmarkDecryptionWithAlgorithms/pbkdf2-sha512" | grep -v "\[DEBUG" | tail -1 | sed 's/.*BenchmarkDecryptionWithAlgorithms\/\(pbkdf2-sha512\)[^ ]*/\1/' | awk '{print "| pbkdf2-sha512 | " $$1 " | " $$2 " " $$3 " | " $$4 " " $$5 " | " $$6 " " $$7 " |"}' >> benchmark-report.md
	@rm tmp_bench_decrypt.txt
	@echo "" >> benchmark-report.md
	
	@echo "## Decryption Algorithm Failures" >> benchmark-report.md
	@echo "| Algorithm | Status | Error |" >> benchmark-report.md
	@echo "|-----------|--------|-------|" >> benchmark-report.md
	@go test -bench="BenchmarkDecryptionWithAlgorithms" -benchmem ./pkg/encryption 2>&1 | grep "benchmark_test.go" | grep -A1 "failed:" | sed 's/.*Decryption with \(.*\) failed: \(.*\)/| \1 | Failed | \2 |/g' >> benchmark-report.md
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

.PHONY: test lint lint-fix install-lint

# Install golangci-lint
install-lint:
	@echo "Installing golangci-lint..."
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Install staticcheck
.PHONY: install-staticcheck
install-staticcheck:
	@echo "Installing staticcheck..."
	@go install honnef.co/go/tools/cmd/staticcheck@latest

# Run linter
lint:
	@echo "Running linter..."
	@~/go/bin/golangci-lint run

# Run staticcheck
.PHONY: staticcheck
staticcheck:
	@echo "Running staticcheck..."
	@~/go/bin/staticcheck ./...

# Run all checks (linter and staticcheck)
.PHONY: check-all
check-all: lint staticcheck
	@echo "All checks completed."

# Run linter with auto-fix
lint-fix:
	@echo "Running linter with auto-fix..."
	@~/go/bin/golangci-lint run --fix

# Build and run the application in a container
.PHONY: build-image run-image

build-image:
	docker build \
	-t yed:$(TAG_NAME) \
	-f Dockerfile .
	@echo "Image built successfully."

run-image:
	docker run -it --rm yed:$(TAG_NAME)
	@echo "Image run successfully."

# Display help information
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  default         		- Run formatting, vetting, linting, staticcheck, build, and quick tests"
	@echo "  run             		- Run the application locally"
	@echo "  install-deps    		- Install project dependencies"
	@echo "  upgrade-deps    		- Upgrade all project dependencies to their latest versions"
	@echo "  clean-deps      		- Clean up vendor dependencies"
	@echo "  build           		- Build the application for the current OS/architecture"
	@echo "  build-cross     		- Build binaries for multiple platforms"
	@echo "  clean           		- Clean build artifacts"
	@echo "  test            		- Run all tests with race detection and coverage"
	@echo "  quicktest       		- Run quick tests without additional checks"
	@echo "  test-coverage   		- Run tests with coverage report"
	@echo "  test-race       		- Run tests with race detection"
	@echo "  test-manual    		- Run manual tests"
	@echo "  test-all        		- Run all tests and benchmarks"
	@echo "  benchmark       		- Run basic benchmarks"
	@echo "  benchmark-long  		- Run comprehensive benchmarks with longer duration"
	@echo "  benchmark-encryption 		- Run only encryption/decryption benchmarks"
	@echo "  benchmark-algorithms 		- Run key derivation algorithm comparison benchmarks"
	@echo "  benchmark-argon2 		- Run Argon2 configuration comparison benchmarks"
	@echo "  benchmark-report 		- Generate a markdown report of all benchmarks"
	@echo "  clean-coverage  		- Clean coverage and benchmark files"
	@echo "  fmt             		- Check code formatting"
	@echo "  vet             		- Analyze code with go vet"
	@echo "  lint            		- Run golangci-lint on the codebase"
	@echo "  install-lint    		- Install golangci-lint"
	@echo "  lint-fix        		- Run golangci-lint with auto-fix"
	@echo "  staticcheck     		- Run staticcheck static analyzer on the codebase"
	@echo "  install-staticcheck 		- Install staticcheck"
	@echo "  check-all       		- Run all code quality checks (lint and staticcheck)"
	@echo "  build-image     		- Build Docker image"
	@echo "  run-image       		- Run Docker image with --version flag"
	@echo "  help            		- Display this help message"
