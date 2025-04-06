package encryption

import (
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
)

func BenchmarkEncrypt(b *testing.B) {
	password := "securepassword"
	plaintext := strings.Repeat("This is a test. ", 100)

	for i := 0; i < b.N; i++ {
		_, err := Encrypt(password, plaintext)
		if err != nil {
			b.Fatalf("Encryption failed: %v", err)
		}
	}
}

func BenchmarkDecrypt(b *testing.B) {
	password := "securepassword"
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
	// Password and salt for testing
	password := []byte("securepassword")
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
	password := []byte("securepassword")
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
