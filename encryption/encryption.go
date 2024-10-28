package encryption

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
)

// Encrypt encrypts a plaintext string using AES encryption
func Encrypt(password, plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	key := make([]byte, 32)
	copy(key, []byte(password))
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	content := pad([]byte(plaintext), block.BlockSize())
	ciphertext := make([]byte, aes.BlockSize+len(content))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], content)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts an AES-encrypted string
func Decrypt(password, crypt64 string) (string, error) {
	if crypt64 == "" {
		return "", nil
	}
	key := make([]byte, 32)
	copy(key, []byte(password))

	crypt, err := base64.StdEncoding.DecodeString(crypt64)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
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

// unpad removes padding from data
func unpad(data []byte) []byte {
	length := len(data)
	unpadding := int(data[length-1])
	return data[:(length - unpadding)]
}
