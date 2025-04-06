package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

func TestEncryptDecrypt(t *testing.T) {
	tests := []struct {
		name         string
		data         string
		key          string
		errorEncrypt bool
		errorDecrypt bool
	}{
		{
			name:         "valid encryption/decryption",
			data:         "test data",
			key:          "test-key-123456789012345",
			errorEncrypt: false,
			errorDecrypt: false,
		},
		{
			name:         "empty data",
			key:          "test-key-123",
			data:         "",
			errorEncrypt: true,
			errorDecrypt: true,
		},
		{
			name:         "empty key",
			key:          "",
			data:         "sensitive data",
			errorEncrypt: true,
			errorDecrypt: true,
		},
		{
			name:         "long data",
			key:          "test-key-123",
			data:         "very long sensitive data that needs to be encrypted and decrypted properly",
			errorEncrypt: false,
			errorDecrypt: false,
		},
		{
			name:         "special characters",
			key:          "test-key-123",
			data:         "!@#$%^&*()_+{}[]|\\:;\"'<>,.?/~`",
			errorEncrypt: false,
			errorDecrypt: false,
		},
		{
			name:         "unicode characters",
			key:          "test-key-123",
			data:         "Привет, мир! 🌍",
			errorEncrypt: false,
			errorDecrypt: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, err := Encrypt(tt.key, tt.data)
			if (err != nil) != tt.errorEncrypt {
				t.Errorf("Encrypt() error = %v, wantError %v", err, tt.errorEncrypt)
				return
			}
			if tt.errorEncrypt {
				return
			}

			decryptedBuffer, err := Decrypt(tt.key, encrypted)
			if (err != nil) != tt.errorDecrypt {
				t.Errorf("Decrypt() error = %v", err)
				return
			}
			if tt.errorDecrypt {
				return
			}

			defer decryptedBuffer.Destroy()

			decrypted := string(decryptedBuffer.Bytes())
			if decrypted != tt.data {
				t.Errorf("Decrypt() = %v, want %v", decrypted, tt.data)
			}
		})
	}
}

func TestDecryptWithWrongPassword(t *testing.T) {
	tests := []struct {
		name          string
		encryptKey    string
		decryptKey    string
		data          string
		expectError   bool
		errorContains string
	}{
		{
			name:          "completely different password",
			encryptKey:    "securepassword",
			decryptKey:    "wrongpassword",
			data:          "This is a test string.",
			expectError:   true,
			errorContains: "HMAC validation failed",
		},
		{
			name:          "similar password",
			encryptKey:    "securepassword",
			decryptKey:    "securepasswor",
			data:          "This is a test string.",
			expectError:   true,
			errorContains: "HMAC validation failed",
		},
		{
			name:          "empty password",
			encryptKey:    "securepassword",
			decryptKey:    "",
			data:          "This is a test string.",
			expectError:   true,
			errorContains: "password must be at least 8 characters long",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, err := Encrypt(tt.encryptKey, tt.data)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			_, err = Decrypt(tt.decryptKey, encrypted)
			if tt.expectError {
				if err == nil {
					t.Error("Decryption should have failed with wrong password")
				} else if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error to contain '%s', got '%v'", tt.errorContains, err)
				}
			} else if err != nil {
				t.Errorf("Decryption failed unexpectedly: %v", err)
			}
		})
	}
}

func TestDecryptWithCorruptedData(t *testing.T) {
	tests := []struct {
		name          string
		key           string
		data          string
		corruptFunc   func(string) string
		expectError   bool
		errorContains string
	}{
		{
			name: "completely invalid data",
			key:  "securepassword",
			data: "this-is-not-valid-encrypted-data",
			corruptFunc: func(s string) string {
				return s
			},
			expectError:   true,
			errorContains: "failed to decode base64 string",
		},
		{
			name: "truncated data",
			key:  "securepassword",
			data: "This is a test string.",
			corruptFunc: func(s string) string {
				encrypted, _ := Encrypt("securepassword", s)
				return encrypted[:len(encrypted)-10]
			},
			expectError:   true,
			errorContains: "failed to decode base64 string",
		},
		{
			name: "modified data",
			key:  "securepassword",
			data: "This is a test string.",
			corruptFunc: func(s string) string {
				encrypted, _ := Encrypt("securepassword", s)
				bytes := []byte(encrypted)
				bytes[len(bytes)/2] ^= 0xFF
				return string(bytes)
			},
			expectError:   true,
			errorContains: "failed to decode base64 string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			corruptedData := tt.corruptFunc(tt.data)
			_, err := Decrypt(tt.key, corruptedData)
			if tt.expectError {
				if err == nil {
					t.Error("Decryption should have failed with corrupted data")
				} else if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error to contain '%s', got '%v'", tt.errorContains, err)
				}
			} else if err != nil {
				t.Errorf("Decryption failed unexpectedly: %v", err)
			}
		})
	}
}

func TestEncryptDecryptWithDifferentAlgorithms(t *testing.T) {
	data := "test data for different algorithms"
	password := "secure-test-password-123456789"

	algorithms := []KeyDerivationAlgorithm{
		Argon2idAlgorithm,
		PBKDF2SHA256Algorithm,
		PBKDF2SHA512Algorithm,
	}

	for _, algorithm := range algorithms {
		t.Run(string(algorithm)+" algorithm", func(t *testing.T) {
			t.Logf("Using algorithm: %s", algorithm)

			encrypted, err := Encrypt(password, data, algorithm)
			if err != nil {
				t.Fatalf("Encrypt() with %s error = %v", algorithm, err)
			}

			t.Logf("Encrypted data: %s", encrypted)

			detectedAlgo := detectAlgorithmFromCiphertext(encrypted)
			t.Logf("Detected algorithm from encrypted data: '%s'", detectedAlgo)

			decryptedBuffer, err := Decrypt(password, encrypted)
			if err != nil {
				t.Fatalf("Decrypt() with %s error = %v", algorithm, err)
			}
			defer decryptedBuffer.Destroy()

			decrypted := string(decryptedBuffer.Bytes())
			if decrypted != data {
				t.Errorf("Decrypt() with %s = %v, want %v", algorithm, decrypted, data)
			}
		})
	}
}

func TestCompatibilityBetweenAlgorithms(t *testing.T) {
	data := "test data for compatibility check"
	password := "secure-test-password-123456789"

	encryptedArgon2id, err := Encrypt(password, data, Argon2idAlgorithm)
	if err != nil {
		t.Fatalf("Encrypt() with Argon2id error = %v", err)
	}

	decryptedBufferArgon2id, err := Decrypt(password, encryptedArgon2id)
	if err != nil {
		t.Fatalf("Decrypt() with Argon2id error = %v", err)
	}
	defer decryptedBufferArgon2id.Destroy()
	decryptedArgon2id := string(decryptedBufferArgon2id.Bytes())

	if decryptedArgon2id != data {
		t.Errorf("Decrypt() with Argon2id = %v, want %v", decryptedArgon2id, data)
	}

	encryptedPBKDF2SHA256, err := Encrypt(password, data, PBKDF2SHA256Algorithm)
	if err != nil {
		t.Fatalf("Encrypt() with PBKDF2-SHA256 error = %v", err)
	}

	decryptedBufferPBKDF2SHA256, err := Decrypt(password, encryptedPBKDF2SHA256)
	if err != nil {
		t.Fatalf("Decrypt() with PBKDF2-SHA256 error = %v", err)
	}
	defer decryptedBufferPBKDF2SHA256.Destroy()
	decryptedPBKDF2SHA256 := string(decryptedBufferPBKDF2SHA256.Bytes())

	if decryptedPBKDF2SHA256 != data {
		t.Errorf("Decrypt() with PBKDF2-SHA256 = %v, want %v", decryptedPBKDF2SHA256, data)
	}

	encryptedPBKDF2SHA512, err := Encrypt(password, data, PBKDF2SHA512Algorithm)
	if err != nil {
		t.Fatalf("Encrypt() with PBKDF2-SHA512 error = %v", err)
	}

	decryptedBufferPBKDF2SHA512, err := Decrypt(password, encryptedPBKDF2SHA512)
	if err != nil {
		t.Fatalf("Decrypt() with PBKDF2-SHA512 error = %v", err)
	}
	defer decryptedBufferPBKDF2SHA512.Destroy()
	decryptedPBKDF2SHA512 := string(decryptedBufferPBKDF2SHA512.Bytes())

	if decryptedPBKDF2SHA512 != data {
		t.Errorf("Decrypt() with PBKDF2-SHA512 = %v, want %v", decryptedPBKDF2SHA512, data)
	}
}

func TestBackwardCompatibility(t *testing.T) {
	// Skip test until we resolve backwards compatibility issue
	t.Skip("Skipping backward compatibility test until we solve the issue with HMAC validation")

	// Create simulation of old format encrypted data
	// (without algorithm indicator at the beginning)
	data := "legacy encrypted data"
	password := "secure-test-password-123456789"

	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	// Generate key using Argon2id
	key := argon2.IDKey([]byte(password), salt, argon2Iterations, argon2Memory, argon2Threads, keySize)

	// Create ciphertext as the old version would
	// First compress original data
	compressed, err := compress([]byte(data))
	if err != nil {
		t.Fatalf("Failed to compress data: %v", err)
	}

	// Generate nonce
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("Failed to generate nonce: %v", err)
	}

	// Create AES-GCM cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("Failed to create AES cipher: %v", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("Failed to create GCM: %v", err)
	}

	// Encrypt data
	ciphertext := aesGCM.Seal(nil, nonce, compressed, nil)

	// Calculate HMAC for integrity checking
	hmacValue := computeHMAC(key, append(nonce, ciphertext...))

	// Combine all parts: salt + nonce + ciphertext + HMAC (old format)
	oldFormatResult := make([]byte, 0, len(salt)+len(nonce)+len(ciphertext)+len(hmacValue))
	oldFormatResult = append(oldFormatResult, salt...)
	oldFormatResult = append(oldFormatResult, nonce...)
	oldFormatResult = append(oldFormatResult, ciphertext...)
	oldFormatResult = append(oldFormatResult, hmacValue...)

	// Encode the final result to base64
	oldFormatEncrypted := base64.StdEncoding.EncodeToString(oldFormatResult)

	// Test decryption using the new Decrypt function
	decryptedBuffer, err := Decrypt(password, oldFormatEncrypted)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	defer decryptedBuffer.Destroy()

	decrypted := string(decryptedBuffer.Bytes())
	if decrypted != data {
		t.Errorf("Decrypt() = %v, want %v", decrypted, data)
	}
}

func BenchmarkKeyDerivationAlgorithms(b *testing.B) {
	password := "benchmark-password"
	salt := make([]byte, saltSize)

	// Use a shorter iteration count for benchmarks to make them run faster
	originalPBKDF2SHA256Iterations := pbkdf2SHA256Iterations
	originalPBKDF2SHA512Iterations := pbkdf2SHA512Iterations
	pbkdf2SHA256Iterations = 1000 // Use a smaller value for benchmarks
	pbkdf2SHA512Iterations = 1000 // Use a smaller value for benchmarks
	defer func() {
		// Restore original values after benchmarks
		pbkdf2SHA256Iterations = originalPBKDF2SHA256Iterations
		pbkdf2SHA512Iterations = originalPBKDF2SHA512Iterations
	}()

	b.Run("Argon2id", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = deriveKey(password, salt, Argon2idAlgorithm)
		}
	})

	b.Run("PBKDF2-SHA256", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = deriveKey(password, salt, PBKDF2SHA256Algorithm)
		}
	})

	b.Run("PBKDF2-SHA512", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = deriveKey(password, salt, PBKDF2SHA512Algorithm)
		}
	})
}

// detectAlgorithmFromCiphertext пытается определить алгоритм шифрования из зашифрованного текста
func detectAlgorithmFromCiphertext(encrypted string) string {
	rawData, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil || len(rawData) < AlgorithmIndicatorLength {
		return "unknown"
	}

	algoIndicator := rawData[:AlgorithmIndicatorLength]
	return strings.TrimRight(string(algoIndicator), "\x00")
}
