# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- [YED-001] New processor package with enhanced YAML processing capabilities
- [YED-002] Extended debug logging functionality
- [YED-003] New security features in encryption package

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

### Dependencies
- [YED-009] Updated all dependencies to latest stable versions
- [YED-010] Added new security-related dependencies

## [0.1.0] - 2024-03-22
### Added
- Initial release
- Basic YAML encryption/decryption functionality
- Configuration-based processing rules 