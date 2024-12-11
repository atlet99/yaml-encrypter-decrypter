# YAML Encrypter-Decrypter (`yed`)

![Go version](https://img.shields.io/github/go-mod/go-version/atlet99/yaml-encrypter-decrypter/main?style=flat&label=go-version) [![Docker Image Version](https://img.shields.io/docker/v/zetfolder17/yaml-encrypter-decrypter?label=docker%20image&sort=semver)](https://hub.docker.com/r/zetfolder17/yaml-encrypter-decrypter) ![Docker Image Size](https://img.shields.io/docker/image-size/zetfolder17/yaml-encrypter-decrypter/latest) [![CI](https://github.com/atlet99/yaml-encrypter-decrypter/actions/workflows/ci.yml/badge.svg)](https://github.com/atlet99/yaml-encrypter-decrypter/actions/workflows/ci.yml) [![GitHub contributors](https://img.shields.io/github/contributors/atlet99/yaml-encrypter-decrypter)](https://github.com/atlet99/yaml-encrypter-decrypter/graphs/contributors/) [![Go Report Card](https://goreportcard.com/badge/github.com/atlet99/yaml-encrypter-decrypter)](https://goreportcard.com/report/github.com/atlet99/yaml-encrypter-decrypter) [![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/atlet99/yaml-encrypter-decrypter/badge)](https://securityscorecards.dev/viewer/?uri=github.com/atlet99/yaml-encrypter-decrypter) ![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/atlet99/yaml-encrypter-decrypter?sort=semver)

*A Go-based CLI tool for encrypting and decrypting sensitive data in YAML files. It uses modern encryption algorithms and a robust configuration system to ensure your data is securely handled.*

Cross-platform utility for encrypting/decrypting values of sensitive data in YAML files.

Utility is especially relevant for developers who can't use Hashicorp Vault or SOPS, but not want to store sensitive data in Git repository.

## **Features**
- AES-256 GCM encryption for data confidentiality and integrity.
- Argon2 for secure password-based key derivation.
- HMAC for validating data integrity.
- Compression using gzip to optimize data storage.
- Supports cross-platform builds (Linux, macOS, Windows).
- Comprehensive Makefile for building, testing, and running the project.

---

## **How It Works**

### **Encryption**
1. The provided plaintext is compressed using `gzip` to reduce size.
2. A random **salt** is generated (16 bytes) to ensure unique encryption even with the same password.
3. The password is converted to a cryptographic key using **Argon2** key derivation with customizable parameters:
   - **Memory**: 128 MB
   - **Iterations**: 3
   - **Threads**: 4
4. The plaintext is encrypted using **AES-256 GCM** (128-bit nonce, 256-bit key) for confidentiality and integrity.
5. An **HMAC** is computed to validate the integrity of the encrypted data.
6. The final result combines the salt, nonce, encrypted data, and HMAC.

### **Decryption**
1. The encrypted data is decoded and split into its components: salt, nonce, ciphertext, and HMAC.
2. The password is used to regenerate the cryptographic key using the extracted salt.
3. The HMAC is recomputed and validated.
4. The ciphertext is decrypted using **AES-256 GCM**.
5. The decompressed data is returned as plaintext.

---

## **Getting Started**

### **Requirements**
- Go 1.20+ installed.
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
```bash
encryption:
  key: "my-secure-key"    # default encryption key, pls, do not used in production, only YED_ENCRYPTION_KEY
  env_blocks:
    - "secure.password"
    - "secure.api_key"
    - "variable.default if sensitive = true" # if it meets the condition
logging:
  level: "debug"           # Log level (debug, info, warn, error)
```

### **Environment Variable**

Override the encryption key with `YED_ENCRYPTION_KEY`:
```bash
export YED_ENCRYPTION_KEY="my-super-secure-key"
```
**(!) At least 8 characters for passphrase.**

### **Command-Line Interface**

*The tool provides various options to encrypt and decrypt data:*

**Encrypt a Single Value**
```bash
./bin/yed -operation=encrypt -value="MySecretData"
```

**Decrypt a Single Value**
```bash
./bin/yed -operation=decrypt -value="AES256:...encrypted_value..."
```

### **Process a YAML File**

**Encrypt or decrypt specific blocks in a YAML file:**
```bash
./bin/yed -operation=encrypt -filename="config.yaml" -env-blocks="secure.password,secure.api_key"
```

**Dry-Run Mode:**
```bash
./bin/yed -operation=encrypt -filename="config.yaml" -dry-run
```

---

**Makefile Commands**

| Target            | Description                                                    |
| ----------------- | -------------------------------------------------------------- |
| make build        | Build the application for the current OS and architecture.     |
| make run          | Run the application locally.                                   |
| make build-cross  | Build binaries for multiple platforms (Linux, macOS, Windows). |
| make test         | Run all tests with race detection and coverage enabled.        |
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
2. **Argon2:**
   * Secure password-based key derivation.
   * Memory-hard to resist brute-force attacks.
3. **HMAC-SHA256:**
   * Validates integrity of encrypted data.
4. **Gzip Compression:**
   * Reduces size of plaintext before encryption.

---

### **Performance Measurement**

**The tool automatically measures the time taken for encryption, decryption, and YAML file processing.**

*Example:*
```bash
./bin/yed -operation=encrypt -filename=test.tf
```

*Output:*
```bash
YAML processing completed in 227.072083ms
File test.tf updated successfully.
```

*Dry-run mode:*
```bash
yed -filename test.tf --operation encrypt --dry-run
YAML processing completed in 237.009042ms
Dry-run mode enabled. The following changes would be applied:
- [6]: default = "sensitive_hidden_text"
+ [6]: default = "AES256:BVBBV2l...xxOjYyjGdloHq8bBpg=="
```

### **License**

This is an open source project under the [MIT](https://github.com/atlet99/yaml-encrypter-decrypter/blob/main/LICENSE) license.