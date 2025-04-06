# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Added support for `action: none` in rules to explicitly exclude paths from encryption
- Added priority-based rule processing where `action: none` rules are processed first
- Added recursive path exclusion for `action: none` rules (all nested paths are also excluded)
- Added detailed documentation for rule configuration in README.md
- Added line numbers in diff output for easier identification of changes
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
- Added support for parallel file processing
- Added golangci-lint configuration
- Added tests for parallel processing
- Added security scanning workflows with Trivy, Nancy, and OSSF Scorecard
- Added GitHub Actions workflow for security checks
- Added security scanning configuration files
- Added constant `MaskedValue` for sensitive information masking
- Enhanced password security:
  - Implemented robust password strength validation according to OWASP guidelines
  - Added support for passwords up to 64 characters to allow strong passphrases
  - Added common password checking to prevent use of easily guessable passwords
  - Improved password strength assessment with categorization (Low/Medium/High)
  - Added password improvement suggestions for weak passwords
  - Maintained backward compatibility while enhancing security
- Added specialized benchmark targets to Makefile:
  - `benchmark` - Basic benchmarks for the encryption package
  - `benchmark-long` - Longer duration benchmarks (5s per test)
  - `benchmark-encryption` - Benchmarks for encryption/decryption operations
  - `benchmark-algorithms` - Benchmarks for key derivation algorithms
  - `benchmark-argon2` - Benchmarks for different Argon2 configurations
  - `benchmark-report` - Generate comprehensive markdown benchmark report
- Enhanced benchmarking suite:
  - Added dedicated tests for comparing encryption/decryption performance across algorithms
  - Added separate benchmarks for PBKDF2-SHA256 and PBKDF2-SHA512
  - Updated all benchmark tests to use strong passwords meeting OWASP guidelines
  - Added more granular algorithm-specific benchmarks
- Improved benchmark-report output:
  - Formatted results as proper Markdown tables
  - Added better formatting of algorithm names with proper hyphenation
  - Enhanced readability by standardizing units and column alignment
  - Improved table layout for better documentation and README inclusion

### Changed
- [YED-004] Updated Go version to 1.24.1
- [YED-005] Replaced govaluate with expr-lang/expr v1.17.2
- [YED-006] Enhanced encryption security parameters:
  - Updated Argon2 parameters to OWASP recommended values:
    - Memory reduced from 256 MB to 9 MB (9216 KiB)
    - Iterations kept at 4
    - Thread count reduced from 8 to 1
  - Performance improvement: ~8x faster key derivation
  - Memory usage reduced by ~27x while maintaining security
- [YED-007] Updated .gitignore with extended rules
- [YED-008] Improved debug mode handling
- Improved error handling and validation in main.go
- Enhanced command-line argument handling with better validation
- Updated encryption key handling to use secure memory buffers
- Improved debug logging functionality
- Enhanced validation of encrypted data
- Updated documentation in README.md
- Updated Russian documentation in localizations/ru-RU/docs/README.md with all latest features and changes
- Improved error handling in tests
- Optimized base64 string validation
- Translated all code comments to English for better international collaboration
- Optimized TestParallelProcessing by reducing test data size and using shorter encryption key
- Improved test performance by reducing the number of test keys from 1000 to 10
- Added error handling for io.Copy in tests
- Removed unused nodePool variable
- Improved error handling in ProcessFile and ProcessNode functions
- Optimized test performance
- Unified error messages for better consistency
- Added MinKeyLength constant to replace magic number
- Updated GitHub Actions workflow configurations
- Fixed GitHub Actions syntax in security scanning workflows
- Improved version output format for better readability
- Version and build number are now displayed on separate lines
- Enhanced version string parsing in displayVersion function
- Removed string literal duplication by using constant for masked values
- Translated all Russian comments to English in processor.go for better code consistency
- Refactored mainWithExitCode function into smaller, more focused functions to reduce cognitive complexity and improve maintainability
- Added detailed performance benchmarks section to README.md with comprehensive comparison of key derivation algorithms

### Dependencies
- [YED-009] Updated all dependencies to latest stable versions
- [YED-010] Added new security-related dependencies

### Security
- Implemented secure memory handling for sensitive data using memguard
- Added proper cleanup of sensitive data on program interruption
- Enhanced memory protection by returning secure LockedBuffer from Decrypt function
- Improved secure memory management with explicit buffer destruction after use
- Added better debug logging for encrypted data with algorithm detection
- Added context information to masked values for improved debugging
- Added detailed documentation on memory security best practices
- Addressed potential memory leaks with sensitive data by properly cleaning buffers
- Added automated security scanning with Trivy for vulnerability detection
- Added dependency scanning with Nancy
- Added OSSF Scorecard integration for security assessment
- Added security event reporting to GitHub Security tab
- Updated golang.org/x/net to v0.38.0 to fix CVE-2024-45338 and CVE-2025-22870
- Added .nancy-ignore file to exclude CVE-2025-22870 from security scanning
- Configured branch protection rules in GitHub:
  - Enabled branch protection for main branch
  - Set CODEOWNERS as required reviewers
  - Enabled linear history requirement
  - Disabled force pushes and branch deletion
  - Required conversation resolution
- Added mandatory code review requirements with CODEOWNERS file
- Restricted GITHUB_TOKEN permissions to minimum required:
  - Set contents permission to read-only
  - Added specific write permissions for checks and pull-requests
  - Improved security by following principle of least privilege
- Updated release version workflow:
  - Removed unnecessary actions: write permission
  - Kept only required permissions for version updates
  - Maintained automatic version bumping functionality
- Pinned GitHub Actions to specific commit hashes:
  - Fixed actions/checkout to commit hash for better security
  - Prevented potential supply chain attacks
  - Improved reproducibility of workflows

### Fixed
- Fixed argument order in encryption/decryption function calls to properly handle key and value parameters
- Fixed base64 string validation with proper padding handling
- Fixed error handling for invalid operations
- Fixed tests for encrypted value validation
- Restored --version flag functionality
- Fixed version information display
- Improved version display functionality:
  - Fixed version string handling in Makefile with proper space escaping in ldflags
  - Fixed build number extraction from version string
  - Fixed version output format for better readability
  - Restored clean version and build number display in CLI output
- Fixed formatting issues in benchmark reports:
  - Corrected table structure for proper rendering in Markdown
  - Fixed alignment of content in report columns
  - Improved algorithm name formatting in reports

### Removed
- Removed deprecated tests from encryption and processor packages
- Removed unused functions and imports

### Enhancements
- [YED-011] Added multiple key derivation algorithms:
  - Added PBKDF2-SHA256 support for NIST/FIPS compatibility (with 600,000 iterations)
  - Added PBKDF2-SHA512 support for NIST/FIPS compatibility (with 210,000 iterations)
  - Maintained Argon2id as default with OWASP recommended parameters
  - Implemented auto-detection of algorithm during decryption
  - Maintained backward compatibility with existing encrypted data
  - Performance improvements: PBKDF2 is significantly faster (~80-180x) with equivalent security
- Improved debug output clarity:
  - Added display of encryption algorithm in debug messages
  - Added field path context to debug messages
  - Enhanced readability of encrypted value masking
  - Improved detection and reporting of encryption algorithm from ciphertext
  - Removed timestamp prefix from encryption key environment variable message for consistent output formatting
- Enhanced memory security with proper buffer handling and explicit destruction
- Improved benchmark reporting:
  - Created professional formatting for benchmark tables
  - Enhanced readability of benchmark results in Markdown
  - Added clear separation between different benchmark categories
  - Added standardized table headers
  - Made benchmark output directly usable in documentation

## [0.1.0] - 2024-03-20

### Added
- Initial project version
- Basic encryption/decryption functionality
- YAML file support
- Configuration via .yed_config.yml
- Conditional encryption support
- Debug mode and dry run support 