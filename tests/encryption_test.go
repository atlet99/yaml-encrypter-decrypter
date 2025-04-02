package tests

import (
	"strings"
	"testing"
	"yaml-encrypter-decrypter/pkg/encryption"
)

func TestEncryptDecrypt(t *testing.T) {
	tests := []struct {
		name      string
		key       string
		data      string
		wantError bool
	}{
		{
			name:      "valid encryption/decryption",
			key:       "test-key-123",
			data:      "sensitive data",
			wantError: false,
		},
		{
			name:      "empty data",
			key:       "test-key-123",
			data:      "",
			wantError: true,
		},
		{
			name:      "empty key",
			key:       "",
			data:      "sensitive data",
			wantError: true,
		},
		{
			name:      "long data",
			key:       "test-key-123",
			data:      "very long sensitive data that needs to be encrypted and decrypted properly",
			wantError: false,
		},
		{
			name:      "special characters",
			key:       "test-key-123",
			data:      "!@#$%^&*()_+{}[]|\\:;\"'<>,.?/~`",
			wantError: false,
		},
		{
			name:      "unicode characters",
			key:       "test-key-123",
			data:      "Привет, мир! 🌍",
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encrypt
			encrypted, err := encryption.Encrypt(tt.key, tt.data)
			if tt.wantError && err == nil {
				t.Errorf("Encrypt() error = nil, wantError %v", tt.wantError)
				return
			}
			if !tt.wantError && err != nil {
				t.Errorf("Encrypt() error = %v, wantError %v", err, tt.wantError)
				return
			}

			if !tt.wantError {
				// Decrypt
				decrypted, err := encryption.Decrypt(tt.key, encrypted)
				if err != nil {
					t.Errorf("Decrypt() error = %v", err)
					return
				}

				if decrypted != tt.data {
					t.Errorf("Decrypt() = %v, want %v", decrypted, tt.data)
				}
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
			encrypted, err := encryption.Encrypt(tt.encryptKey, tt.data)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			_, err = encryption.Decrypt(tt.decryptKey, encrypted)
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
				encrypted, _ := encryption.Encrypt("securepassword", s)
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
				encrypted, _ := encryption.Encrypt("securepassword", s)
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
			_, err := encryption.Decrypt(tt.key, corruptedData)
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
