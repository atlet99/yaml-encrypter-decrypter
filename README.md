# YAML Encrypter-Decrypter (`yed`)

![Go version](https://img.shields.io/github/go-mod/go-version/atlet99/yaml-encrypter-decrypter/main?style=flat&label=go-version) [![Docker Image Version](https://img.shields.io/docker/v/zetfolder17/yaml-encrypter-decrypter?label=docker%20image&sort=semver)](https://hub.docker.com/r/zetfolder17/yaml-encrypter-decrypter) ![Docker Image Size](https://img.shields.io/docker/image-size/zetfolder17/yaml-encrypter-decrypter/latest) [![CI](https://github.com/atlet99/yaml-encrypter-decrypter/actions/workflows/ci.yml/badge.svg)](https://github.com/atlet99/yaml-encrypter-decrypter/actions/workflows/ci.yml) [![GitHub contributors](https://img.shields.io/github/contributors/atlet99/yaml-encrypter-decrypter)](https://github.com/atlet99/yaml-encrypter-decrypter/graphs/contributors/) [![Go Report Card](https://goreportcard.com/badge/github.com/atlet99/yaml-encrypter-decrypter)](https://goreportcard.com/report/github.com/atlet99/yaml-encrypter-decrypter) [![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/atlet99/yaml-encrypter-decrypter/badge)](https://securityscorecards.dev/viewer/?uri=github.com/atlet99/yaml-encrypter-decrypter) ![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/atlet99/yaml-encrypter-decrypter?sort=semver) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/atlet99/yaml-encrypter-decrypter/blob/main/LICENSE) [![CodeQL](https://github.com/atlet99/yaml-encrypter-decrypter/actions/workflows/codeql.yml/badge.svg)](https://github.com/atlet99/yaml-encrypter-decrypter/actions/workflows/codeql.yml)


*A Go-based CLI tool for encrypting and decrypting sensitive data in YAML files. It uses modern encryption algorithms and a robust configuration system to ensure your data is securely handled.*

Cross-platform utility for encrypting/decrypting values of sensitive data in YAML files.

Utility is especially relevant for developers who can't use Hashicorp Vault or SOPS, but not want to store sensitive data in Git repository.

## **Features**
- AES-256 GCM encryption for data confidentiality and integrity.
- Multiple key derivation algorithms:
  - Argon2id (default) with OWASP recommended parameters
  - PBKDF2-SHA256 (NIST/FIPS compatible) with 600,000 iterations
  - PBKDF2-SHA512 (NIST/FIPS compatible) with 210,000 iterations
- Supports all YAML multiline formats:
  - Literal style (|) with preserved line breaks
  - Folded style (>) for single-line rendering with spaces
  - PEM certificates/keys in both multiline literal and escaped newline formats
- Secure memory handling with memguard to protect sensitive data in memory.
- HMAC for validating data integrity.
- Compression using gzip to optimize data storage.
- Supports cross-platform builds (Linux, macOS, Windows).
- Comprehensive Makefile for building, testing, and running the project.
- Enhanced validation of encrypted data and base64 strings.
- Improved error handling and enhanced debug logging.
- Comprehensive test coverage with race detection.
- Performance benchmarks for encryption/decryption operations.

## **Performance Benchmarks**

The performance of different key derivation algorithms has been extensively benchmarked to help you make an informed choice based on your security and performance requirements.

### **Key Derivation Algorithm Comparison**

| Algorithm | Operations/sec | Time (ns/op) | Memory (B/op) | Allocs/op |
|-----------|----------------|--------------|---------------|-----------|
| Argon2id | 60 | 18,363,235 | 9,442,344 | 49 |
| PBKDF2-SHA256 | 10,000 | 107,746 | 804 | 11 |
| PBKDF2-SHA512 | 4,830 | 236,775 | 1,380 | 11 |

**Key Insights:**
- **PBKDF2-SHA256** is approximately **170x faster** than Argon2id
- **PBKDF2-SHA512** is approximately **78x faster** than Argon2id
- Both PBKDF2 variants use significantly less memory than Argon2id
- The PBKDF2 algorithms are tuned with sufficient iterations to maintain security equivalence

### **Argon2 Configurations Comparison**

| Configuration | Operations/sec | Time (ns/op) | Memory (B/op) | Allocs/op |
|--------------|----------------|--------------|---------------|-----------|
| OWASP-1-current | 67 | 17,818,289 | 9,442,306 | 48 |
| OWASP-2 | 70 | 17,125,754 | 7,345,429 | 56 |
| OWASP-3 | 67 | 17,846,443 | 12,587,776 | 40 |
| Previous-Config | 8 | 138,691,224 | 268,457,400 | 198 |

**Key Improvements:**
- The current OWASP-recommended configuration is **~8x faster** than the previous configuration
- Memory usage has been reduced by **~27x** while maintaining security
- All OWASP-recommended configurations provide similar performance with different memory/iteration trade-offs

### **Basic Encryption and Decryption Performance**

| Operation | Operations/sec | Time (ns/op) | Memory (B/op) | Allocs/op |
|-----------|----------------|--------------|---------------|-----------|
| Encrypt | 66 | 17,791,645 | 10,260,991 | 88 |
| Decrypt | 67 | 19,369,065 | 9,490,663 | 71 |

### **Encryption with Different Algorithms**

| Algorithm | Operations/sec | Time (ns/op) | Memory (B/op) | Allocs/op |
|-----------|----------------|--------------|---------------|-----------|
| argon2id | 61 | 19,897,308 | 10,259,454 | 89 |
| pbkdf2-sha256 | 6,548 | 191,538 | 817,917 | 51 |
| pbkdf2-sha512 | 3,604 | 340,094 | 818,493 | 51 |

### **Decryption with Different Algorithms**

| Algorithm | Operations/sec | Time (ns/op) | Memory (B/op) | Allocs/op |
|-----------|----------------|--------------|---------------|-----------|
| argon2id | 61 | 20,304,921 | 9,486,333 | 68 |
| pbkdf2-sha256 | 7,838 | 160,589 | 44,796 | 30 |
| pbkdf2-sha512 | 3,909 | 313,596 | 45,372 | 30 |

**Note:** These benchmarks were performed on an Apple M3 Pro processor. Performance may vary based on hardware.

You can generate benchmark reports for your own system using:
```bash
make benchmark-report
```

---

## **How It Works**

### **Encryption**
1. The provided plaintext is compressed using `gzip` to reduce size.
2. A random **salt** is generated (32 bytes) to ensure unique encryption even with the same password.
3. The password is converted to a cryptographic key using one of the following key derivation functions:
   - **Argon2id** (default, OWASP recommended parameters):
     - **Memory**: 9 MB (9216 KiB)
     - **Iterations**: 4
     - **Threads**: 1
   - **PBKDF2-SHA256** (optional, NIST/FIPS compatible):
     - **Iterations**: 600,000
   - **PBKDF2-SHA512** (optional, NIST/FIPS compatible):
     - **Iterations**: 210,000
4. The plaintext is encrypted using **AES-256 GCM** (128-bit nonce, 256-bit key) for confidentiality and integrity.
5. An **HMAC** is computed to validate the integrity of the encrypted data.
6. The final result combines the salt, nonce, encrypted data, and HMAC.

### **Secure Memory Handling**
The tool implements robust memory security measures to protect sensitive data:

1. **Secure Memory Buffers**: Uses memguard to create protected memory enclaves for sensitive data.
2. **Memory Protection**: Memory containing sensitive data is protected from swapping to disk.
3. **Automatic Cleanup**: All sensitive buffers are automatically destroyed after use.
4. **Signal Handling**: Properly handles interruption signals to ensure sensitive data is wiped from memory.
5. **Buffer Lifecycle**: Explicit buffer lifecycle management with destroy calls to prevent memory leaks.
6. **Sensitive Data Protection**: Prevents sensitive data from being exposed in logs or error messages.
7. **Strong Password Requirements**: Enforces a minimum key length of 16 characters for both command-line and environment variable provided keys.

### **Multiline YAML Support**
The tool provides comprehensive support for encrypting and decrypting multiline YAML content:

1. **Format Detection**: Automatically detects multiline content by analyzing YAML node style and content.
2. **Style Preservation**: Preserves original YAML multiline styles (literal `|` or folded `>`) during encryption/decryption.
3. **PEM Support**: Special handling for PEM certificates and private keys in both formats:
   - Multiline literal blocks with preserved line breaks
   - Single-line strings with escaped newlines (`\n`)
4. **Smart Formatting**: Applies appropriate style when decrypting based on content type:
   - PEM content uses literal style to preserve exact formatting
   - Content with tabs uses literal style for proper representation
   - Multiline content is formatted according to its original style when possible
5. **Seamless Operation**: No special configuration needed - multiline handling works automatically.

#### **Multiline Encryption Examples**

**Original YAML with multiline content:**
```yaml
# Example with various multiline formats
smart_config:
  auth:
    # Literal style - preserves line breaks
    password: |
      ThisIsAVery
      LongPassword
      WithMultipleLines
    # Folded style - converted to spaces
    description: >
      This is a folded text
      that will be rendered as
      a single line with spaces.

certificates:
  # Multiline literal block for certificates
  public_key: |
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxWzg9vJJR0TIIu5XzCQG
    BijxB+EFPYvkJ/3vbXFNaYQTvMPwcU3I9JXaUFwIHHjMnHElo6oHECBZzj5ki9Dg
    3l1FcJn598L0D0pLECZ9wOJeGHlPP/CGXj6gWVj6kfn3t/9I4hQ7oz5X+JzmqGEg
    /JyqVVZ1BqHd09jrLQIDAQAB
    -----END PUBLIC KEY-----
  
  # Certificate with escaped newlines (quoted style)
  quoted_public_key: "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\nxWzg9vJJR0TIIu5XzCQG\n-----END PUBLIC KEY-----"
```

**After encryption:**
```yaml
# Example with various multiline formats
smart_config:
  auth:
    # Encrypted literal style - will be decrypted with preserved line breaks
    password: AES256:YXJnb24yaWQAAAAAAAAAm+G/h4Mwe5pHQvCxKvS7d2QfcO7N5iUVwVr0BIQ2+eXxPU7KqJMbM5BFnl2i3RiG2LQdKQpWnpxr8WctL3/l83acdTUdqq5YwJLZeWKwxW0qFMJHuGFgxJVJ8CpnFZFOeewVbUoS/oqbjNR9lGqF9I6E/8FJOp/QZUR4VTKxWICMUBeTJBOlf9JHtNJlzeFsQVKQ/Z2PNDvgjfYI0GJ7y5Ry/vdjdXVEDvlKwKTiXBQXvWf8rL7L/T2N9eOiGxZ6iRV+oM8hqQ==
    # Encrypted folded style - will be decrypted with preserved spaces
    description: AES256:YXJnb24yaWQAAAAAAAAAAl5gR1X7uPMikY8sQZP2YjJ8X7ixOu2cY5nAHIMTnxvILrI+Q2FTXxV9wTSOvbTQDlpHmcTCshpfYX3qRYMUBt5FRNtAqeRQxP/5R0zLi0Gg56i/vsDdLRkDXU32T9cAoUHcHN5oOy87tpSWnhrkwp3pzZ9UPPwZsOuOoEP+GDWoRsxNaNKKD7FaXNXRyKqZcQlcHcgVMPtUBx19SrGfE/rVmtO2QzWQl4YLCVXpgMZ4N5A7lZ9zslDFTIzImKUuHC8vWCPcOkTpIgFElhCDz5i0M9hB

certificates:
  # Encrypted certificate - will be decrypted as literal block
  public_key: AES256:YXJnb24yaWQAAAAAAAAAAEUpnFVVS1KZtHZwUWwsaAiFQhszeEM6aYwEJrWvFLMtOozIpcKcyBs0utUs9gvoAaAsiQzCF+ow/hmobI8ghjmo23Aq4hwX9ZzUIo47MeSNsISGtz2R6PBl0mvwLUOp9RARj3U5/RDS1tC7N7qnTpesvVUlt3gDYc2hPhJEauJEekZm9wd6Z26NJTWQKREFi8/ZtzIkPp5/ie+sOFSmWXdajSunYgKk1iBYFhohsv9ULkrCSQke/s1wT9qbDA3HwPyCJ3LdJdE78c+uMRa17Acvi/W/kyFAD3pKliSBWE6ZNc41JGiNAzZ2KpVmOMY6SeYYP/AxBPNfKwgdyHDCyrwf8dIFMNVr6NItbm8D6QhkgA++L0XkksrvbWa8cG+8KwIK75IrP1w4xhYvuRS0qraBVhJIQMu05+0SGNbfmYpSWZJJpDA8hQVBQepPWrxilBg9XiHIvOM84ykVIS6z7InyPwn+sEhcagQUA4NKBiAE6yXT3sV8khhqeM8imsgCjd+8PTDWJDXYyees8LVnQrQWPWBL5lGIQvfBwY7D/vinHvHNCMRCIbbcUD8n9Rk1RWXnz5yaCcZiAd1TNYYlpgya44cIASUVPSzotvKBaYG4a9Wxe3XTmgwkqYwSg0Y7QuRlSeTo8oE=
  
  # Encrypted quoted certificate - will be decrypted with escaped newlines
  quoted_public_key: AES256:YXJnb24yaWQAAAAAAAAAAMsXrCK7X+pgKU8J8C23ns+ubKW/LzFpi0GUcJFMJWgqnHc6RlQhmLuwVtQmvNBwA1C+2is/IjRfnipRdqzMEXz/ULSwMB+H9u2MTHXnXCFjn0wUc1pw0I/9xCVk8yXYVueaCO8kdyFExrTHpT8VfbsQqxKHZ/sEJ4WZIszaHpjkL8rbVKaJxl7hgHXdL1Q3D9oRQ9q/3MOXCLsWj1EPu1bNOQueDdgJTeozKErJGaHQsUB/1ODeiVmjKVlePxdKOlmIsLMCqo0vGx8elvRii3cdnfmCDnz5iT9z6VuYFxDXLtbWSWa41jQMaHMhwW7NnGJEFBzIGr+/yE9+qEqu9VMs4kFA79PRB1vPDVL+SZn62ewg6mbr6992uUJBn6AvtM4RsciQzzR5iE6WcFRer/7ZhfVMcCd27KRNS/X6i+jqzdnFmNLh+wPekApozwcvPPfcLbXtYRE52kNgqaN7/QQjup6EAPgRLB/qW+dAz5CCfGfCwzmAtKV3yiHgeZxwoy9E6YAyqJtmsUamUwkaW/6jA8airYzQ7zdEp15QKLGUDYF3n2OpvhRgwGWfiPfC0TRFmTRFpA4fimzFKkwAad1FKqBcH87HtyVfwgF38NZsPxkC2jqZ44mMcFf4v1f9w/aF4pZ65Q==|escaped_newlines
```

**After decryption (back to original content with preserved styles):**
```yaml
# Example with various multiline formats
smart_config:
  auth:
    # Literal style - preserves line breaks
    password: |
      ThisIsAVery
      LongPassword
      WithMultipleLines
    # Folded style - converted to spaces
    description: >
      This is a folded text
      that will be rendered as
      a single line with spaces.

certificates:
  # Multiline literal block for certificates
  public_key: |
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxWzg9vJJR0TIIu5XzCQG
    BijxB+EFPYvkJ/3vbXFNaYQTvMPwcU3I9JXaUFwIHHjMnHElo6oHECBZzj5ki9Dg
    3l1FcJn598L0D0pLECZ9wOJeGHlPP/CGXj6gWVj6kfn3t/9I4hQ7oz5X+JzmqGEg
    /JyqVVZ1BqHd09jrLQIDAQAB
    -----END PUBLIC KEY-----
  
  # Certificate with escaped newlines (quoted style)
  quoted_public_key: "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\nxWzg9vJJR0TIIu5XzCQG\n-----END PUBLIC KEY-----"
```

#### **How Multiline Processing Works**

When processing multiline YAML content, the tool:

1. **During encryption**:
   - Detects if content is multiline or contains escaped newlines (`\n`)
   - Identifies PEM certificates and keys with special pattern detection
   - Preserves style information during encryption
   - Adds special markers for escaped newline format when needed

2. **During decryption**:
   - Examines the encrypted data and any style markers
   - Restores the appropriate style based on content type and original format
   - Uses appropriate YAML style (literal `|` or double-quoted `"..."`) based on content
   - Special handling for PEM certificates to maintain correct formatting

This ensures that all forms of multiline content, including certificates and keys, maintain their exact formatting and representation after encryption and decryption cycles.

### **Key Derivation Algorithms**
Choose from multiple key derivation algorithms with the `--algorithm` flag:
```bash
./bin/yed --file config.yaml --key="my-secure-key" --operation encrypt --algorithm argon2id
```

Available algorithms:
- `argon2id` (default): Memory-hard algorithm with OWASP recommended parameters
- `pbkdf2-sha256`: NIST/FIPS compatible with 600,000 iterations
- `pbkdf2-sha512`: NIST/FIPS compatible with 210,000 iterations (provides best balance of security and performance)

### **Debug Mode Improvements**
The enhanced debug mode provides detailed insights into the encryption/decryption process:

```bash
./bin/yed --file config.yaml --key="my-secure-key" --operation encrypt --debug
```

Debug output now includes:
- Algorithm detection for each encrypted value
- Field path information for better context
- Length of encrypted data
- Enhanced masking of sensitive values

Example debug output:
```
[DEBUG] Masking encrypted value for field 'smart_config.auth.username' (length: 184, algo: argon2id)
```

This helps in troubleshooting and understanding the encryption process without compromising security.

### **Decryption**
1. The encrypted data is decoded and split into its components: salt, nonce, ciphertext, and HMAC.
2. The password is used to regenerate the cryptographic key using the extracted salt.
3. The HMAC is recomputed and validated.
4. The ciphertext is decrypted using **AES-256 GCM**.
5. The decompressed data is returned as plaintext.

---

## **Getting Started**

### **Requirements**
- Go 1.24.1+ installed.
- Make installed on your system.

### **Steps**
1. Clone the repository:
```bash
git clone https://github.com/atlet99/yaml-encrypter-decrypter.git;
cd yaml-encryptor-decryptor
```

2. Install dependencies:
```bash
make install-deps
```

3. Build the application:
```bash
make build
```

4. Run the tool:
```bash
./bin/yed --help
```

## **Usage**

### **Configuration**

The tool uses a `.yed_config.yml` file for customizable behavior. Place this file in the working directory.

**Example `.yed_config.yml`:**
```yaml
encryption:
  rules:
    - name: "skip_axel_fix"
      block: "axel.fix"
      pattern: "**"
      action: "none"
      description: "Skip encryption for all values in axel.fix block"
    
    - name: "encrypt_smart_config"
      block: "smart_config"
      pattern: "**"
      description: "Encrypt all values in smart_config block"
    
    - name: "encrypt_passwords"
      block: "*"
      pattern: "pass*"
      description: "Encrypt all password fields globally"
  
  unsecure_diff: false  # Set to true to show actual values in diff mode
```

### **Rule Configuration**

Rules in `.yed_config.yml` define which parts of your YAML file should be encrypted or skipped. Each rule consists of:

- `name`: A unique identifier for the rule
- `block`: The YAML block to which the rule applies (e.g., "smart_config" or "*" for any block)
- `pattern`: Pattern for matching fields within the block (e.g., "**" for all fields, "pass*" for fields starting with "pass")
- `action`: Optional. Use "none" to skip encryption for matching paths
- `description`: Human-readable description of the rule's purpose

**Important Rule Processing Details:**

1. **Priority Order**: Rules with `action: none` are processed first to ensure paths are properly excluded from encryption.
2. **Recursive Exclusion**: When a path matches a rule with `action: none`, all its nested paths are also excluded from encryption.
3. **Pattern Matching**:
   - `**` matches any number of nested fields
   - `*` matches any characters within a single field name
   - Exact matches take precedence over patterns

**Example Rule Applications:**

```yaml
# Example YAML structure
smart_config:
  auth:
    username: "admin"
    password: "secret123"
axel:
  fix:
    name: "test"
    password: "test123"
```

With the example rules above:
- All fields under `smart_config` will be encrypted
- All fields under `axel.fix` will be skipped (not encrypted)
- Any field matching `pass*` in other blocks will be encrypted

### **Environment Variable**

Override the encryption key with `YED_ENCRYPTION_KEY`:
```bash
export YED_ENCRYPTION_KEY="my-super-secure-key"
```
**Password Requirements:**
- **Minimum**: 8 characters
- **Maximum**: 64 characters (supports passphrases)
- **Recommendation**: Use a mix of uppercase, lowercase, numbers, and special characters
- **Avoid**: Common passwords will be rejected for security

### **Command-Line Interface**

*The tool provides various options to encrypt and decrypt data:*

**Encrypt a Single Value**
```bash
./bin/yed --operation encrypt --value="MySecretData" --key="my-super-secure-key"
```

**Decrypt a Single Value**
```bash
./bin/yed --operation decrypt --value="AES256:...encrypted_value..." --key="my-super-secure-key"
```

### **Process a YAML File**

**Encrypt or decrypt a YAML file:**
```bash
./bin/yed --file config.yaml --key="my-super-secure-key" --operation encrypt
```

**Dry-Run Mode with Diff:**
```bash
./bin/yed --file config.yaml --key="my-super-secure-key" --operation encrypt --dry-run --diff
```

This will show a preview of changes that would be made to the YAML file, including line numbers for easier identification:
```
smart_config.auth.username:
  [3] - admin
  [3] + AES256:gt1***A==
smart_config.auth.password:
  [4] - SecRet@osd49
  [4] + AES256:V24***xQ=
```

**Debug Mode:**
```bash
./bin/yed --file config.yaml --key="my-super-secure-key" --operation encrypt --debug
```

---

### **Makefile Commands**

| Target            | Description                                                    |
| ----------------- | -------------------------------------------------------------- |
| make build        | Build the application for the current OS and architecture.     |
| make run          | Run the application locally.                                   |
| make build-cross  | Build binaries for multiple platforms (Linux, macOS, Windows). |
| make test         | Run all tests with race detection and coverage enabled.        |
| make test-coverage| Run tests with coverage report.                               |
| make test-race    | Run tests with race detector.                                 |
| make test-benchmark| Run performance benchmarks.                                   |
| make test-all     | Run all tests and benchmarks.                                 |
| make quicktest    | Run quick tests without additional checks.                     |
| make fmt          | Check code formatting with gofmt.                              |
| make vet          | Analyze code using go vet.                                     |
| make install-deps | Install project dependencies.                                  |
| make clean        | Remove build artifacts.                                        |
| make help         | Display help information for Makefile targets.                 |

### **Build Cross-Platform Binaries**

*You can build binaries for multiple platforms using:*
```bash
make build-cross
```

*Output binaries will be available in the `bin/` directory:*
* bin/yed-linux-amd64
* bin/yed-darwin-arm64
* bin/yed-windows-amd64.exe

---

### **Algorithms Used**

1. **AES-256 GCM:**
   * Authenticated encryption for data confidentiality and integrity.
   * Ensures encrypted data cannot be tampered with.
2. **Argon2id:**
   * Secure password-based key derivation, winner of the 2015 Password Hashing Competition.
   * Configured according to OWASP recommendations for optimal security-performance balance.
   * Memory-hard to resist brute-force attacks, especially GPU-based ones.
3. **HMAC-SHA256:**
   * Validates integrity of encrypted data.
4. **Gzip Compression:**
   * Reduces size of plaintext before encryption.

---

### **Performance Measurement**

**The tool automatically measures the time taken for encryption, decryption, and YAML file processing.**

*Example:*
```bash
./bin/yed --file test.yml --key="my-super-secure-key" --operation encrypt
```

*Output:*
```bash
YAML processing completed in 227.072083ms
File test.yml updated successfully.
```

*Dry-run mode with diff:*
```bash
./bin/yed --file test.yml --key="my-super-secure-key" --operation encrypt --dry-run --diff
YAML processing completed in 237.009042ms
Dry-run mode: The following changes would be applied:
```

## **Recent Updates**

### **Algorithm Flexibility**
- Added support for multiple key derivation algorithms:
  - **Argon2id**: Default algorithm recommended by OWASP
  - **PBKDF2-SHA256**: Added for NIST/FIPS compatibility (600,000 iterations)
  - **PBKDF2-SHA512**: Added for NIST/FIPS compatibility (210,000 iterations)
- Performance comparison:
  - PBKDF2-SHA256 is ~180x faster than Argon2id with comparable security
  - PBKDF2-SHA512 is ~80x faster than Argon2id with comparable security
- Algorithm is auto-detected during decryption
- Maintains backward compatibility with previously encrypted data
- Algorithm can be specified via command-line argument
- Added `SetKeyDerivationAlgorithm` function to the processor package for flexible algorithm selection

### **Password Security Enhancements**
- Implemented robust password strength validation according to OWASP:
  - Support for passwords up to 64 characters to allow passphrases
  - Detection and prevention of common/compromised passwords
  - Password strength assessment (Low/Medium/High)
  - Intelligent suggestions for password improvement
  - Character diversity checks (uppercase, lowercase, digits, symbols)
  - No arbitrary rules limiting character types

### **Performance Optimizations**
- Optimized Argon2id parameters according to OWASP recommendations:
  - Memory reduced from 256 MB to 9 MB (9216 KiB)
  - Thread count reduced from 8 to 1 while maintaining 4 iterations
  - Key derivation is ~8x faster (reduced from ~136ms to ~17ms)
  - Memory usage reduced by 27x (from ~268 MB to ~10 MB)
  - Maintains the same security level with significantly reduced resource consumption
  - Improved performance on resource-constrained devices
  - Reduced risk of memory-based DoS attacks

### **Build System Improvements**
- Fixed Makefile for proper compilation of all source files:
  - Updated build targets to correctly include all source files
  - Changed build commands to target directories instead of individual files
  - Added proper path prefixes to ensure correct Go module resolution
  - Ensured consistent building across all platforms

### **Enhanced Diff Output**
- Added line numbers to diff output for easier change identification
- Output format now shows: `[line_number] - old_value` and `[line_number] + new_value`
- Added support for masking sensitive information in debug output and diff mode

### **Security Improvements**
- Added proper masking of sensitive values in debug output and diff mode
- Implemented configurable masking via `unsecure_diff` parameter
- Enhanced protection of encrypted values with partial display

### **Bug Fixes and Improvements**
- Fixed argument order in encryption/decryption function calls to properly handle key and value parameters
- Improved handling of short values that previously couldn't be encrypted due to parameter confusion
- Reduced cognitive complexity of functions for better maintainability
- Improved handling of rules with `action: none` to correctly exclude paths from encryption
- Translated all code comments to English for better international collaboration
- Added `MaskedValue` constant to eliminate string literal duplication

### **Configuration Enhancements**
- Added clearer examples of rule configuration
- Improved processing of exclusion rules
- Added detailed documentation for rule parameters
- Added `unsecure_diff` parameter to control visibility of sensitive values in diff output

---

### **License**

This is an open source project under the [MIT](https://github.com/atlet99/yaml-encrypter-decrypter/blob/main/LICENSE) license.

### **Environment Variables**

You can override command-line flags using environment variables:

```bash
# Set encryption key (must be at least 16 characters long)
export YED_ENCRYPTION_KEY="my-super-secure-key"

# Then run without specifying key on command line
./bin/yed --file config.yaml --operation encrypt
```

The environment variable approach provides an alternative to passing sensitive data on the command line, which might be visible in process listings.