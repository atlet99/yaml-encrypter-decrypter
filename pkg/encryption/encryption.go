package encryption

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// Encrypt encrypts a plaintext string using AES-256 CBC encryption and returns a base64-encoded ciphertext.
func Encrypt(password, plaintext string) (string, error) {
	if len(plaintext) == 0 {
		return "", errors.New("plaintext cannot be empty")
	}

	key := deriveKey(password)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	content := pad([]byte(plaintext), block.BlockSize())
	ciphertext := make([]byte, aes.BlockSize+len(content))

	// Generate and use a random IV for each encryption
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("failed to generate IV: %w", err)
	}

	// Encrypt using CBC mode
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], content)

	// Return base64-encoded ciphertext
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts a base64-encoded ciphertext string using AES-256 CBC and returns the plaintext.
func Decrypt(password, crypt64 string) (string, error) {
	if len(crypt64) == 0 {
		return "", errors.New("encrypted text cannot be empty")
	}

	crypt, err := base64.StdEncoding.DecodeString(crypt64)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64 string: %w", err)
	}

	key := deriveKey(password)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	if len(crypt) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}

	// Extract IV from the beginning of the ciphertext
	iv := crypt[:aes.BlockSize]
	crypt = crypt[aes.BlockSize:]
	decrypted := make([]byte, len(crypt))

	// Decrypt using CBC mode
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(decrypted, crypt)

	// Remove padding and return plaintext
	decrypted, err = unpad(decrypted)
	if err != nil {
		return "", fmt.Errorf("failed to unpad decrypted text: %w", err)
	}

	return string(decrypted), nil
}

// deriveKey derives a 32-byte key from the given password for AES-256.
func deriveKey(password string) []byte {
	key := make([]byte, 32)
	copy(key, []byte(password))
	return key
}

// pad adds PKCS#7 padding to data to ensure it fits the block size.
func pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

func unpad(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("unpad error: input data is empty")
	}

	padding := int(data[length-1])
	// Check if padding is within valid bounds
	if padding <= 0 || padding > length {
		return nil, errors.New("unpad error: invalid padding size")
	}

	// Validate that all padding bytes match the padding value
	for i := length - padding; i < length; i++ {
		if data[i] != byte(padding) {
			return nil, errors.New("unpad error: inconsistent padding")
		}
	}

	return data[:(length - padding)], nil
}
