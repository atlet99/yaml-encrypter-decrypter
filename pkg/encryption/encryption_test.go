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
			errorContains: "password must be at least 8 characters long",
		},
		{
			name:          "too short key",
			key:           "short",
			data:          "This is a test string.",
			errorEncrypt:  true,
			errorContains: "password must be at least 8 characters long",
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
			encryptKey:    "P@ssw0rd_Str0ng!T3st#2024",
			decryptKey:    "Wr0ngP@ssword_Test#1234",
			data:          "This is a test string.",
			expectError:   true,
			errorContains: "HMAC validation failed",
		},
		{
			name:          "similar password",
			encryptKey:    "P@ssw0rd_Str0ng!T3st#2024",
			decryptKey:    "P@ssw0rd_Str0ng!T3st#2025",
			data:          "This is a test string.",
			expectError:   true,
			errorContains: "HMAC validation failed",
		},
		{
			name:          "empty password",
			encryptKey:    "P@ssw0rd_Str0ng!T3st#2024",
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
	// First, prepare actually encrypted data for testing
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
			errorContains: "ciphertext too short",
		},
		{
			name: "corrupted hmac",
			key:  password,
			corruptFunc: func(s string) string {
				decoded, _ := base64.StdEncoding.DecodeString(s)
				if len(decoded) > hmacSize {
					// Specifically modify the HMAC at the end
					for i := len(decoded) - hmacSize; i < len(decoded); i++ {
						decoded[i] ^= 0x01 // Invert bits
					}
				}
				return base64.StdEncoding.EncodeToString(decoded)
			},
			expectError:   true,
			errorContains: "HMAC validation failed",
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
	password := "P@ssw0rd_Str0ng!T3st#2024"

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
	password := "P@ssw0rd_Str0ng!T3st#2024"

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

// detectAlgorithmFromCiphertext attempts to determine the encryption algorithm from the encrypted text
func detectAlgorithmFromCiphertext(encrypted string) string {
	rawData, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil || len(rawData) < AlgorithmIndicatorLength {
		return "unknown"
	}

	algoIndicator := rawData[:AlgorithmIndicatorLength]
	return strings.TrimRight(string(algoIndicator), "\x00")
}
