package encryption

import (
	"strings"
	"testing"
)

func BenchmarkEncrypt(b *testing.B) {
	// Use a strong password that meets all requirements
	password := "P@ssw0rd_Str0ng!T3st#2024"
	plaintext := strings.Repeat("This is a test. ", 100)

	for i := 0; i < b.N; i++ {
		_, err := Encrypt(password, plaintext)
		if err != nil {
			b.Fatalf("Encryption failed: %v", err)
		}
	}
}

func BenchmarkDecrypt(b *testing.B) {
	// Use a strong password that meets all requirements
	password := "P@ssw0rd_Str0ng!T3st#2024"
	plaintext := strings.Repeat("This is a test. ", 100)

	encrypted, err := Encrypt(password, plaintext)
	if err != nil {
		b.Fatalf("Encryption failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Decrypt(password, encrypted)
		if err != nil {
			b.Fatalf("Decryption failed: %v", err)
		}
	}
}

// BenchmarkEncryptionWithAlgorithms compares the performance of encryption with different algorithms
func BenchmarkEncryptionWithAlgorithms(b *testing.B) {
	// Use a strong password that meets all requirements
	password := "P@ssw0rd_Str0ng!T3st#2024"
	plaintext := "This is sensitive data that needs to be encrypted"

	algorithms := []KeyDerivationAlgorithm{
		Argon2idAlgorithm,
		PBKDF2SHA256Algorithm,
		PBKDF2SHA512Algorithm,
	}

	for _, algo := range algorithms {
		b.Run(string(algo), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, err := Encrypt(password, plaintext, algo)
				if err != nil {
					b.Fatalf("Encryption with %s failed: %v", algo, err)
				}
			}
		})
	}
}

// BenchmarkDecryptionWithAlgorithms compares the performance of decryption with different algorithms
func BenchmarkDecryptionWithAlgorithms(b *testing.B) {
	// Use a strong password that meets all requirements
	password := "P@ssw0rd_Str0ng!T3st#2024"
	plaintext := "This is sensitive data that needs to be encrypted"

	algorithms := []KeyDerivationAlgorithm{
		Argon2idAlgorithm,
		PBKDF2SHA256Algorithm,
		PBKDF2SHA512Algorithm,
	}

	// Prepare encrypted data in advance
	encryptedData := make(map[KeyDerivationAlgorithm]string)

	for _, algo := range algorithms {
		encrypted, err := Encrypt(password, plaintext, algo)
		if err != nil {
			b.Fatalf("Pre-encryption with %s failed: %v", algo, err)
		}
		encryptedData[algo] = encrypted
	}

	b.ResetTimer()

	for _, algo := range algorithms {
		b.Run(string(algo), func(b *testing.B) {
			encrypted := encryptedData[algo]
			for i := 0; i < b.N; i++ {
				_, err := Decrypt(password, encrypted)
				if err != nil {
					b.Fatalf("Decryption with %s failed: %v", algo, err)
				}
			}
		})
	}
}

func TestPBKDF2SHA256Iterations(t *testing.T) {
	// Save the original value
	originalIterations := pbkdf2SHA256Iterations
	defer func() { pbkdf2SHA256Iterations = originalIterations }()

	// Set the test value
	pbkdf2SHA256Iterations = 1000

	// Test key derivation
	key, err := deriveKey("test-password", []byte("test-salt"), PBKDF2SHA256Algorithm)
	if err != nil {
		t.Fatalf("Failed to derive key: %v", err)
	}
	if len(key) != PBKDF2KeyLen {
		t.Errorf("Expected key length %d, got %d", PBKDF2KeyLen, len(key))
	}
}

func TestPBKDF2SHA512Iterations(t *testing.T) {
	// Save the original value
	originalIterations := pbkdf2SHA512Iterations
	defer func() { pbkdf2SHA512Iterations = originalIterations }()

	// Set the test value
	pbkdf2SHA512Iterations = 1000

	// Test key derivation
	key, err := deriveKey("test-password", []byte("test-salt"), PBKDF2SHA512Algorithm)
	if err != nil {
		t.Fatalf("Failed to derive key: %v", err)
	}
	if len(key) != PBKDF2KeyLen {
		t.Errorf("Expected key length %d, got %d", PBKDF2KeyLen, len(key))
	}
}
