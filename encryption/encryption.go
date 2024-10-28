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

// Encrypt encrypts a plaintext string using AES encryption and returns a base64-encoded ciphertext.
func Encrypt(password, plaintext string) (string, error) {
	if plaintext == "" {
		return "", errors.New("plaintext is empty")
	}

	key := make([]byte, 32)
	copy(key, []byte(password))

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %v", err)
	}

	content := pad([]byte(plaintext), block.BlockSize())
	ciphertext := make([]byte, aes.BlockSize+len(content))

	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("failed to generate IV: %v", err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], content)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts a base64-encoded ciphertext string using AES and returns the plaintext.
func Decrypt(password, crypt64 string) (string, error) {
	if crypt64 == "" {
		return "", errors.New("encrypted text is empty")
	}

	crypt, err := base64.StdEncoding.DecodeString(crypt64)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64 string: %v", err)
	}

	key := make([]byte, 32)
	copy(key, []byte(password))

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %v", err)
	}

	iv := crypt[:aes.BlockSize]
	crypt = crypt[aes.BlockSize:]
	decrypted := make([]byte, len(crypt))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(decrypted, crypt)

	return string(unpad(decrypted)), nil
}

// pad adds padding to data to ensure it fits AES block size requirements
func pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

// unpad removes padding from data, reversing the padding added by pad
func unpad(data []byte) []byte {
	length := len(data)
	unpadding := int(data[length-1])
	return data[:(length - unpadding)]
}
