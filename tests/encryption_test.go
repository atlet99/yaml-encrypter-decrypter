package tests

import (
	"testing"
	"yaml-encrypter-decrypter/pkg/encryption"
)

func TestEncryptDecrypt(t *testing.T) {
	password := "securepassword"
	plaintext := "This is a test string."

	encrypted, err := encryption.Encrypt(password, plaintext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decrypted, err := encryption.Decrypt(password, encrypted)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if decrypted != plaintext {
		t.Fatalf("Expected decrypted text to be '%s', got '%s'", plaintext, decrypted)
	}
}

func TestDecryptWithWrongPassword(t *testing.T) {
	password := "securepassword"
	wrongPassword := "wrongpassword"
	plaintext := "This is a test string."

	encrypted, err := encryption.Encrypt(password, plaintext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	_, err = encryption.Decrypt(wrongPassword, encrypted)
	if err == nil {
		t.Fatalf("Decryption should have failed with the wrong password")
	}
}

func TestEncryptWithEmptyPassword(t *testing.T) {
	_, err := encryption.Encrypt("", "plaintext")
	if err == nil {
		t.Fatalf("Encryption should have failed with an empty password")
	}
}

func TestDecryptWithCorruptedData(t *testing.T) {
	password := "securepassword"
	corruptedData := "this-is-not-valid-encrypted-data"

	_, err := encryption.Decrypt(password, corruptedData)
	if err == nil {
		t.Fatalf("Decryption should have failed with corrupted data")
	}
}
