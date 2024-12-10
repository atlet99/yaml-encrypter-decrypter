package tests

import (
	"strings"
	"testing"
	"yaml-encrypter-decrypter/pkg/encryption"
)

func BenchmarkEncrypt(b *testing.B) {
	password := "securepassword"
	plaintext := strings.Repeat("This is a test. ", 100)

	for i := 0; i < b.N; i++ {
		_, err := encryption.Encrypt(password, plaintext)
		if err != nil {
			b.Fatalf("Encryption failed: %v", err)
		}
	}
}

func BenchmarkDecrypt(b *testing.B) {
	password := "securepassword"
	plaintext := strings.Repeat("This is a test. ", 100)

	encrypted, err := encryption.Encrypt(password, plaintext)
	if err != nil {
		b.Fatalf("Encryption failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := encryption.Decrypt(password, encrypted)
		if err != nil {
			b.Fatalf("Decryption failed: %v", err)
		}
	}
}
