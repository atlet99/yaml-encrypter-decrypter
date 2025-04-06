package encryption

import (
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
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
		buffer, err := Decrypt(password, encrypted)
		if err != nil {
			b.Fatalf("Decryption failed: %v", err)
		}
		// Clean up the buffer after use
		buffer.Destroy()
	}
}

// TestArgon2Configs compares execution time of various Argon2id configurations
func TestArgon2Configs(t *testing.T) {
	// Use a strong password that meets all requirements
	password := []byte("P@ssw0rd_Str0ng!T3st#2024")
	salt := make([]byte, 32)

	// Tested configurations from OWASP recommendations and our current one
	configs := []struct {
		name string
		m    uint32 // memory in KiB
		t    uint32 // iterations
		p    uint8  // parallelism
	}{
		{"OWASP-1-current", 9216, 4, 1},       // Our current configuration
		{"OWASP-2", 7168, 5, 1},               // Alternative configuration
		{"OWASP-3", 12288, 3, 1},              // Another alternative
		{"Previous-Config", 256 * 1024, 4, 8}, // Our previous configuration
	}

	for _, cfg := range configs {
		t.Run(cfg.name, func(t *testing.T) {
			start := time.Now()
			_ = argon2.IDKey(password, salt, cfg.t, cfg.m, cfg.p, 32)
			elapsed := time.Since(start)
			t.Logf("Configuration %s took %s", cfg.name, elapsed)
		})
	}
}

// BenchmarkArgon2Configs conducts more detailed comparison of configurations
func BenchmarkArgon2Configs(b *testing.B) {
	// Use a strong password that meets all requirements
	password := []byte("P@ssw0rd_Str0ng!T3st#2024")
	salt := make([]byte, 32)

	configs := []struct {
		name string
		m    uint32
		t    uint32
		p    uint8
	}{
		{"OWASP-1-current", 9216, 4, 1},
		{"OWASP-2", 7168, 5, 1},
		{"OWASP-3", 12288, 3, 1},
		{"Previous-Config", 256 * 1024, 4, 8},
	}

	for _, cfg := range configs {
		b.Run(cfg.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = argon2.IDKey(password, salt, cfg.t, cfg.m, cfg.p, 32)
			}
		})
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

	// Use a smaller number of iterations for benchmarks
	originalPBKDF2SHA256Iterations := pbkdf2SHA256Iterations
	originalPBKDF2SHA512Iterations := pbkdf2SHA512Iterations
	pbkdf2SHA256Iterations = 1000
	pbkdf2SHA512Iterations = 1000
	defer func() {
		// Restore original values after benchmark
		pbkdf2SHA256Iterations = originalPBKDF2SHA256Iterations
		pbkdf2SHA512Iterations = originalPBKDF2SHA512Iterations
	}()

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

	// Use a smaller number of iterations for benchmarks
	originalPBKDF2SHA256Iterations := pbkdf2SHA256Iterations
	originalPBKDF2SHA512Iterations := pbkdf2SHA512Iterations
	pbkdf2SHA256Iterations = 1000
	pbkdf2SHA512Iterations = 1000

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
				buffer, err := Decrypt(password, encrypted)
				if err != nil {
					b.Fatalf("Decryption with %s failed: %v", algo, err)
				}
				buffer.Destroy()
			}
		})
	}

	// Restore original values after all tests
	pbkdf2SHA256Iterations = originalPBKDF2SHA256Iterations
	pbkdf2SHA512Iterations = originalPBKDF2SHA512Iterations
}
