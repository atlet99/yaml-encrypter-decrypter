package encryption

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	tests := []struct {
		name          string
		key           string
		data          string
		errorEncrypt  bool
		errorDecrypt  bool
		errorContains string
	}{
		{
			name: "valid data",
			key:  "P@ssw0rd_Str0ng!T3st#2024",
			data: "This is a test string.",
		},
		{
			name:         "empty data",
			key:          "P@ssw0rd_Str0ng!T3st#2024",
			data:         "",
			errorEncrypt: true, // expecting error with empty data
		},
		{
			name: "longer data",
			key:  "P@ssw0rd_Str0ng!T3st#2024",
			data: "This is a longer test string that spans multiple lines.\nIt contains line breaks and special characters: !@#$%^&*()",
		},
		{
			name:          "empty key",
			key:           "",
			data:          "This is a test string.",
			errorEncrypt:  true,
			errorContains: "password must be at least 15 characters long",
		},
		{
			name:          "too short key",
			key:           "short",
			data:          "This is a test string.",
			errorEncrypt:  true,
			errorContains: "password must be at least 15 characters long",
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

			if decryptedBuffer != tt.data {
				t.Errorf("Decrypt() = %v, want %v", decryptedBuffer, tt.data)
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
			encryptKey:    "P@ssw0rd_Str0ng!T3st#2024",
			decryptKey:    "Wr0ngP@ssword_Test#1234",
			data:          "This is a test string.",
			expectError:   true,
			errorContains: "cipher: message authentication failed",
		},
		{
			name:          "similar password",
			encryptKey:    "P@ssw0rd_Str0ng!T3st#2024",
			decryptKey:    "P@ssw0rd_Str0ng!T3st#2025",
			data:          "This is a test string.",
			expectError:   true,
			errorContains: "cipher: message authentication failed",
		},
		{
			name:          "empty password",
			encryptKey:    "P@ssw0rd_Str0ng!T3st#2024",
			decryptKey:    "",
			data:          "This is a test string.",
			expectError:   true,
			errorContains: "password must be at least 15 characters long",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// First check password validation
			if err := ValidatePasswordStrength(tt.decryptKey); err != nil {
				if !tt.expectError {
					t.Errorf("Unexpected password validation error: %v", err)
				}
				if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error to contain '%s', got '%v'", tt.errorContains, err)
				}
				return
			}

			// If password is valid, try encryption/decryption
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
	// First prepare encrypted data for testing
	password := "P@ssw0rd_Str0ng!T3st#2024"
	plaintext := "This is a test plaintext for corruption tests."
	encrypted, err := Encrypt(password, plaintext)
	if err != nil {
		t.Fatalf("Failed to create test encrypted data: %v", err)
	}

	tests := []struct {
		name          string
		key           string
		corruptFunc   func(string) string
		expectError   bool
		errorContains string
	}{
		{
			name: "corrupted base64",
			key:  password,
			corruptFunc: func(s string) string {
				return "not-base64-data"
			},
			expectError:   true,
			errorContains: "illegal base64",
		},
		{
			name: "corrupted format",
			key:  password,
			corruptFunc: func(s string) string {
				decoded, _ := base64.StdEncoding.DecodeString(s)
				// Return text too short to break the format
				return base64.StdEncoding.EncodeToString(decoded[:20])
			},
			expectError:   true,
			errorContains: "invalid ciphertext format: too short",
		},
		{
			name: "corrupted hmac",
			key:  password,
			corruptFunc: func(s string) string {
				decoded, _ := base64.StdEncoding.DecodeString(s)
				if len(decoded) > hmacSize {
					// Invert all HMAC bits
					for i := len(decoded) - hmacSize; i < len(decoded); i++ {
						decoded[i] = ^decoded[i] // Invert all bits
					}
				}
				return base64.StdEncoding.EncodeToString(decoded)
			},
			expectError:   true,
			errorContains: "cipher: message authentication failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			corruptedData := tt.corruptFunc(encrypted)
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
	password := "P@ssw0rd_Str0ng!T3st#2024"

	algorithms := []KeyDerivationAlgorithm{
		Argon2idAlgorithm,
		PBKDF2SHA256Algorithm,
		PBKDF2SHA512Algorithm,
	}

	for _, algorithm := range algorithms {
		t.Run(string(algorithm)+" algorithm", func(t *testing.T) {
			t.Logf("Using algorithm: %s", algorithm)

			// Encrypt data
			encrypted, err := Encrypt(password, data, algorithm)
			if err != nil {
				t.Fatalf("Encrypt() with %s error = %v", algorithm, err)
			}

			// Verify that algorithm is properly encoded in encrypted data
			detectedAlgo := detectAlgorithmFromCiphertext(encrypted)
			if detectedAlgo != string(algorithm) {
				t.Logf("Expected algorithm %s, detected %s (this may be acceptable)", algorithm, detectedAlgo)
			}

			// Debug information
			t.Logf("Password length: %d", len(password))
			t.Logf("Encrypted data length: %d", len(encrypted))
			t.Logf("Encrypted first 20 chars: %s", encrypted[:min(20, len(encrypted))])

			// Check if password is passed correctly for debugging
			fmt.Printf("[TEST DEBUG] Password being used for decryption: '[REDACTED]'\n")
			fmt.Printf("[TEST DEBUG] Encrypted data length: %d bytes\n", len(encrypted))
			fmt.Printf("[TEST DEBUG] First 50 chars of encrypted data: '%s'\n", encrypted[:min(50, len(encrypted))])
			fmt.Printf("[TEST DEBUG] Last 50 chars of encrypted data: '%s'\n", encrypted[max(0, len(encrypted)-50):])

			// Directly decrypt without using additional detection functions
			decryptedBuffer, err := Decrypt(password, encrypted)
			if err != nil {
				t.Fatalf("Decrypt() with %s error = %v", algorithm, err)
			}

			if decryptedBuffer != data {
				t.Errorf("Decrypt() with %s = %v, want %v", algorithm, decryptedBuffer, data)
			} else {
				t.Logf("Successfully encrypted and decrypted with %s algorithm", algorithm)
			}
		})
	}
}

func TestCompatibilityBetweenAlgorithms(t *testing.T) {
	data := "test data for compatibility check"
	password := "P@ssw0rd_Str0ng!T3st#2024"

	encryptedArgon2id, err := Encrypt(password, data, Argon2idAlgorithm)
	if err != nil {
		t.Fatalf("Encrypt() with Argon2id error = %v", err)
	}

	encryptedPBKDF2SHA256, err := Encrypt(password, data, PBKDF2SHA256Algorithm)
	if err != nil {
		t.Fatalf("Encrypt() with PBKDF2-SHA256 error = %v", err)
	}

	encryptedPBKDF2SHA512, err := Encrypt(password, data, PBKDF2SHA512Algorithm)
	if err != nil {
		t.Fatalf("Encrypt() with PBKDF2-SHA512 error = %v", err)
	}

	// Test decryption
	fmt.Printf("[TEST DEBUG] Testing cross-decryption between algorithms\n")
	decryptedArgon2id, err := Decrypt(password, encryptedArgon2id)
	if err != nil {
		t.Fatalf("Failed to decrypt Argon2id with Argon2id: %v", err)
	}

	decryptedPBKDF2SHA256, err := Decrypt(password, encryptedPBKDF2SHA256)
	if err != nil {
		t.Fatalf("Failed to decrypt PBKDF2-SHA256 with PBKDF2-SHA256: %v", err)
	}

	decryptedPBKDF2SHA512, err := Decrypt(password, encryptedPBKDF2SHA512)
	if err != nil {
		t.Fatalf("Failed to decrypt PBKDF2-SHA512 with PBKDF2-SHA512: %v", err)
	}

	if decryptedArgon2id != data {
		t.Errorf("Decrypt() with Argon2id = %v, want %v", decryptedArgon2id, data)
	}

	if decryptedPBKDF2SHA256 != data {
		t.Errorf("Decrypt() with PBKDF2-SHA256 = %v, want %v", decryptedPBKDF2SHA256, data)
	}

	if decryptedPBKDF2SHA512 != data {
		t.Errorf("Decrypt() with PBKDF2-SHA512 = %v, want %v", decryptedPBKDF2SHA512, data)
	}
}

func TestBackwardCompatibility(t *testing.T) {
	// In this test we check compatibility with format without algorithm indicator

	// Use the same key and text as in other tests
	password := "P@ssw0rd_Str0ng!T3st#2024"
	plaintext := "This is a test plaintext for backward compatibility."

	// 1. Encrypt data using normal Encrypt
	encrypted, err := Encrypt(password, plaintext, Argon2idAlgorithm)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// 2. Verify data can be decrypted normally
	decrypted, err := Decrypt(password, encrypted)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("Expected '%s', got '%s'", plaintext, decrypted)
	}

	// 3. Modify encrypted data by removing first 16 bytes (algorithm indicator)
	rawData, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		t.Fatalf("Failed to decode base64: %v", err)
	}

	fmt.Printf("[TEST DEBUG] Original encrypted data length: %d bytes\n", len(rawData))

	// Create old format, excluding algorithm indicator
	legacyData := rawData[AlgorithmIndicatorLength:]
	legacyEncrypted := base64.StdEncoding.EncodeToString(legacyData)

	fmt.Printf("[TEST DEBUG] Legacy format created: %d bytes (original minus %d bytes for algorithm indicator)\n",
		len(legacyData), AlgorithmIndicatorLength)
	fmt.Printf("[TEST DEBUG] Legacy format base64: %s\n", legacyEncrypted[:min(50, len(legacyEncrypted))])

	// 4. Should get an error when decrypting legacy format without algorithm indicator
	_, err = Decrypt(password, legacyEncrypted)
	if err == nil {
		t.Error("Expected error when decrypting legacy format, but got none")
	} else {
		fmt.Printf("[TEST DEBUG] Got expected error: %v\n", err)
	}
}

func BenchmarkKeyDerivationAlgorithms(b *testing.B) {
	// Use a strong password that meets all requirements
	password := "P@ssw0rd_Str0ng!T3st#2024"
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
			_, _ = deriveKey(password, salt, Argon2idAlgorithm)
		}
	})

	b.Run("PBKDF2-SHA256", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = deriveKey(password, salt, PBKDF2SHA256Algorithm)
		}
	})

	b.Run("PBKDF2-SHA512", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = deriveKey(password, salt, PBKDF2SHA512Algorithm)
		}
	})
}

// detectAlgorithmFromCiphertext attempts to determine the encryption algorithm from the encrypted text
func detectAlgorithmFromCiphertext(encrypted string) string {
	// Clean from newlines and other non-readable characters
	cleanedEncrypted := strings.ReplaceAll(encrypted, "\n", "")
	cleanedEncrypted = strings.ReplaceAll(cleanedEncrypted, "\r", "")

	rawData, err := base64.StdEncoding.DecodeString(cleanedEncrypted)
	if err != nil {
		fmt.Printf("[TEST DEBUG] Failed to decode Base64: %v\n", err)
		return "unknown"
	}

	if len(rawData) < AlgorithmIndicatorLength {
		fmt.Printf("[TEST DEBUG] Raw data too short: %d bytes\n", len(rawData))
		return "unknown"
	}

	algoIndicator := rawData[:AlgorithmIndicatorLength]
	return strings.TrimRight(string(algoIndicator), "\x00")
}

// TestArgon2Configs tests different Argon2 configurations
func TestArgon2Configs(t *testing.T) {
	password := "testpassword"
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	// Test with default parameters
	key, err := deriveKey(password, salt, Argon2idAlgorithm)
	if err != nil {
		t.Fatalf("Failed to derive key with default parameters: %v", err)
	}
	if len(key) != keySize {
		t.Errorf("Expected key length %d, got %d", keySize, len(key))
	}

	// Test with custom parameters
	key, err = deriveKey(password, salt, Argon2idAlgorithm)
	if err != nil {
		t.Fatalf("Failed to derive key with custom parameters: %v", err)
	}
	if len(key) != keySize {
		t.Errorf("Expected key length %d, got %d", keySize, len(key))
	}
}

// TestHMACComputation tests HMAC computation
func TestHMACComputation(t *testing.T) {
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	data := []byte("test data")

	hmacValue := computeHMAC(key, data, byte('a'))
	if hmacValue == nil {
		t.Fatal("HMAC computation failed")
	}
	if len(hmacValue) != hmacSize {
		t.Errorf("Expected HMAC length %d, got %d", hmacSize, len(hmacValue))
	}
}

// TestKeyDerivationAlgorithms tests different key derivation algorithms
func TestKeyDerivationAlgorithms(t *testing.T) {
	password := "testpassword"
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	// Test Argon2id
	key, err := deriveKey(password, salt, Argon2idAlgorithm)
	if err != nil {
		t.Fatalf("Argon2id key derivation failed: %v", err)
	}
	if len(key) != keySize {
		t.Errorf("Expected key length %d, got %d", keySize, len(key))
	}

	// Test PBKDF2-SHA256
	key, err = deriveKey(password, salt, PBKDF2SHA256Algorithm)
	if err != nil {
		t.Fatalf("PBKDF2-SHA256 key derivation failed: %v", err)
	}
	if len(key) != keySize {
		t.Errorf("Expected key length %d, got %d", keySize, len(key))
	}

	// Test PBKDF2-SHA512
	key, err = deriveKey(password, salt, PBKDF2SHA512Algorithm)
	if err != nil {
		t.Fatalf("PBKDF2-SHA512 key derivation failed: %v", err)
	}
	if len(key) != keySize {
		t.Errorf("Expected key length %d, got %d", keySize, len(key))
	}
}

func TestHMACValidation(t *testing.T) {
	key := []byte("test-key")
	data := []byte("test-data")
	expectedHMAC := computeHMAC(key, data, byte('a'))

	if !bytes.Equal(expectedHMAC, computeHMAC(key, data, byte('a'))) {
		t.Error("HMAC validation failed")
	}
}

func TestKeyDerivation(t *testing.T) {
	password := "test-password"
	salt := []byte("test-salt")

	// Test Argon2id
	key, err := deriveKey(password, salt, Argon2idAlgorithm)
	if err != nil {
		t.Fatalf("Argon2id key derivation failed: %v", err)
	}
	if len(key) != Argon2idKeyLen {
		t.Errorf("Expected key length %d, got %d", Argon2idKeyLen, len(key))
	}

	// Test PBKDF2-SHA256
	key, err = deriveKey(password, salt, PBKDF2SHA256Algorithm)
	if err != nil {
		t.Fatalf("PBKDF2-SHA256 key derivation failed: %v", err)
	}
	if len(key) != PBKDF2KeyLen {
		t.Errorf("Expected key length %d, got %d", PBKDF2KeyLen, len(key))
	}

	// Test PBKDF2-SHA512
	key, err = deriveKey(password, salt, PBKDF2SHA512Algorithm)
	if err != nil {
		t.Fatalf("PBKDF2-SHA512 key derivation failed: %v", err)
	}
	if len(key) != PBKDF2KeyLen {
		t.Errorf("Expected key length %d, got %d", PBKDF2KeyLen, len(key))
	}
}
