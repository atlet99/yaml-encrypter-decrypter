package encryption

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"github.com/awnumar/memguard"
	"golang.org/x/crypto/argon2"
)

const (
	saltSize   = 32 // Увеличиваем размер соли для большей безопасности
	nonceSize  = 12
	keySize    = 32         // AES-256
	iterations = 4          // Увеличиваем количество итераций
	memory     = 256 * 1024 // Увеличиваем память до 256 MB
	threads    = 8          // Увеличиваем количество потоков
	hmacSize   = sha256.Size
)

// Encrypt encrypts a plaintext string using AES-256 GCM with Argon2 key derivation and returns a base64-encoded ciphertext.
func Encrypt(password, plaintext string) (string, error) {
	if len(password) < 8 {
		return "", errors.New("password must be at least 8 characters long")
	}
	if len(plaintext) == 0 {
		return "", errors.New("plaintext cannot be empty")
	}

	// Protect plaintext with memguard
	protectedPlaintext := memguard.NewBufferFromBytes([]byte(plaintext))
	defer protectedPlaintext.Destroy()

	// Compress plaintext
	compressed, err := compress(protectedPlaintext.Bytes())
	if err != nil {
		return "", fmt.Errorf("failed to compress plaintext: %w", err)
	}

	// Generate random salt
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive key from password and salt
	key := deriveKey(password, salt)

	// Generate random nonce
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// Encrypt the plaintext
	ciphertext := aesGCM.Seal(nil, nonce, compressed, nil)

	// Compute HMAC for integrity check
	hmacValue := computeHMAC(key, append(nonce, ciphertext...))

	// Combine salt, nonce, ciphertext, and HMAC
	result := append(salt, nonce...)
	result = append(result, ciphertext...)
	result = append(result, hmacValue...)

	// Return base64-encoded result
	return base64.StdEncoding.EncodeToString(result), nil
}

// Decrypt decrypts a base64-encoded ciphertext string using AES-256 GCM and Argon2 key derivation and returns the plaintext.
func Decrypt(password, crypt64 string) (string, error) {
	if len(password) < 8 {
		return "", errors.New("password must be at least 8 characters long")
	}
	if len(crypt64) == 0 {
		return "", errors.New("encrypted text cannot be empty")
	}

	crypt, err := base64.StdEncoding.DecodeString(crypt64)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64 string: %w", err)
	}

	if len(crypt) < saltSize+nonceSize+hmacSize {
		return "", errors.New("ciphertext too short")
	}

	// Extract salt, nonce, and ciphertext
	salt := crypt[:saltSize]
	nonce := crypt[saltSize : saltSize+nonceSize]
	ciphertext := crypt[saltSize+nonceSize : len(crypt)-hmacSize]
	hmacValue := crypt[len(crypt)-hmacSize:]

	// Derive key from password and salt
	key := deriveKey(password, salt)

	// Verify HMAC
	expectedHMAC := computeHMAC(key, append(nonce, ciphertext...))
	if !hmac.Equal(hmacValue, expectedHMAC) {
		return "", errors.New("HMAC validation failed: possible incorrect password or corrupted data")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// Decrypt the ciphertext
	compressed, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt ciphertext: %w", err)
	}

	// Decompress plaintext
	plaintext, err := decompress(compressed)
	if err != nil {
		return "", fmt.Errorf("failed to decompress plaintext: %w", err)
	}

	// Protect plaintext with memguard before returning
	protectedPlaintext := memguard.NewBufferFromBytes(plaintext)
	defer protectedPlaintext.Destroy()

	return string(protectedPlaintext.Bytes()), nil
}

// deriveKey derives a 32-byte key from the given password and salt using Argon2id.
func deriveKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, iterations, memory, threads, keySize)
}

// computeHMAC computes the HMAC for given data using the provided key.
func computeHMAC(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// compress compresses data using gzip.
func compress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	_, err := writer.Write(data)
	if err != nil {
		return nil, err
	}
	writer.Close()
	return buf.Bytes(), nil
}

// decompress decompresses gzip-compressed data.
func decompress(data []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(reader)
}
