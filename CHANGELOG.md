# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- [YED-001] New processor package with enhanced YAML processing capabilities
- [YED-002] Extended debug logging functionality
- [YED-003] New security features in encryption package
- Added support for complex conditions in YAML processing using expr library
- Added new helper functions for array operations (all, any, none, one, filter, map)
- Added string manipulation functions in conditions (len, contains, hasPrefix, hasSuffix, lower, upper, trim)
- Added graceful shutdown handling with SIGINT and SIGTERM signals
- Added secure memory handling with memguard for encryption keys
- Added tests for base64 string validation
- Added tests for invalid operation handling
- Added tests for empty value handling
- Added tests for various YAML node types
- Added performance benchmarks

### Changed
- [YED-004] Updated Go version to 1.24.1
- [YED-005] Replaced govaluate with expr-lang/expr v1.17.2
- [YED-006] Enhanced encryption security parameters:
  - Increased salt size to 32 bytes
  - Increased Argon2 iterations to 4
  - Increased memory usage to 256 MB
  - Increased thread count to 8
- [YED-007] Updated .gitignore with extended rules
- [YED-008] Improved debug mode handling
- Improved error handling and validation in main.go
- Enhanced command-line argument handling with better validation
- Updated encryption key handling to use secure memory buffers
- Improved debug logging functionality
- Enhanced validation of encrypted data
- Updated documentation in README.md
- Improved error handling in tests
- Optimized base64 string validation
- Translated all code comments to English for better international collaboration
- Optimized TestParallelProcessing by reducing test data size and using shorter encryption key
- Improved test performance by reducing the number of test keys from 1000 to 10

### Dependencies
- [YED-009] Updated all dependencies to latest stable versions
- [YED-010] Added new security-related dependencies

### Security
- Implemented secure memory handling for sensitive data using memguard
- Added proper cleanup of sensitive data on program interruption

### Fixed
- Fixed base64 string validation with proper padding handling
- Fixed error handling for invalid operations
- Fixed tests for encrypted value validation

### Removed
- Removed deprecated tests from encryption and processor packages
- Removed unused functions and imports

## [0.1.0] - 2024-03-20

### Added
- Initial project version
- Basic encryption/decryption functionality
- YAML file support
- Configuration via .yed_config.yml
- Conditional encryption support
- Debug mode and dry run support 