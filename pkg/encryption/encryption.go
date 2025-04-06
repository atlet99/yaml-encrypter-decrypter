package encryption

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/awnumar/memguard"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

// KeyDerivationAlgorithm represents the key derivation algorithm to use
type KeyDerivationAlgorithm string

const (
	// Argon2idAlgorithm represents the Argon2id key derivation algorithm
	Argon2idAlgorithm KeyDerivationAlgorithm = "argon2id"

	// PBKDF2SHA256Algorithm represents the PBKDF2 with HMAC-SHA256 key derivation algorithm
	PBKDF2SHA256Algorithm KeyDerivationAlgorithm = "pbkdf2-sha256"

	// PBKDF2SHA512Algorithm represents the PBKDF2 with HMAC-SHA512 key derivation algorithm
	PBKDF2SHA512Algorithm KeyDerivationAlgorithm = "pbkdf2-sha512"
)

const (
	saltSize  = 32 // Increased salt size for better security
	nonceSize = 12
	keySize   = 32 // AES-256
	hmacSize  = sha256.Size

	// Key derivation constants
	argon2IterationsCount = 4    // Argon2 iterations (t)
	argon2MemoryKiB       = 9216 // Memory usage to 9 MiB (OWASP recommendation)
	argon2ThreadCount     = 1    // Threads (p) as per OWASP recommendation
)

// Argon2id parameters (OWASP recommended)
var (
	argon2Iterations = uint32(argon2IterationsCount) // Argon2 iterations (t)
	argon2Memory     = uint32(argon2MemoryKiB)       // Memory usage to 9 MiB (OWASP recommendation)
	argon2Threads    = uint8(argon2ThreadCount)      // Threads (p) as per OWASP recommendation

	// PBKDF2 parameters (OWASP recommended)
	pbkdf2SHA256Iterations = 600000 // PBKDF2-HMAC-SHA256: 600,000 iterations
	pbkdf2SHA512Iterations = 210000 // PBKDF2-HMAC-SHA512: 210,000 iterations

	// AlgorithmIndicatorLength is the length of the algorithm indicator prefix in ciphertext
	AlgorithmIndicatorLength = 16
)

// DefaultKeyDerivationAlgorithm is the default key derivation algorithm
var DefaultKeyDerivationAlgorithm = Argon2idAlgorithm

// Encrypt encrypts a plaintext string using AES-256 GCM with the specified key derivation algorithm and returns a base64-encoded ciphertext.
func Encrypt(password, plaintext string, algorithm ...KeyDerivationAlgorithm) (string, error) {
	// Validate password strength
	if err := ValidatePasswordStrength(password); err != nil {
		return "", err
	}

	if len(plaintext) == 0 {
		return "", errors.New("plaintext cannot be empty")
	}

	// Determine which algorithm to use
	algo := DefaultKeyDerivationAlgorithm
	if len(algorithm) > 0 && algorithm[0] != "" {
		algo = algorithm[0]
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

	// Derive key from password and salt using the selected algorithm
	key := deriveKey(password, salt, algo)

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

	// Combine algorithm indicator, salt, nonce, ciphertext, and HMAC
	result := make([]byte, 0, len(salt)+len(nonce)+len(ciphertext)+len(hmacValue)+AlgorithmIndicatorLength)

	// Add algorithm indicator as first part of the result (padded with zeros to fixed length)
	algoBytes := []byte(algo)
	algoIndicator := make([]byte, AlgorithmIndicatorLength)
	copy(algoIndicator, algoBytes)
	result = append(result, algoIndicator...)

	result = append(result, salt...)
	result = append(result, nonce...)
	result = append(result, ciphertext...)
	result = append(result, hmacValue...)

	// Return base64-encoded result
	return base64.StdEncoding.EncodeToString(result), nil
}

// Decrypt decrypts a base64-encoded ciphertext string using AES-256 GCM and the appropriate key derivation algorithm and returns the plaintext.
// The returned buffer must be destroyed by caller after use with defer buffer.Destroy()
func Decrypt(password, crypt64 string) (*memguard.LockedBuffer, error) {
	// Basic length check for password
	if len(password) < PasswordMinLength {
		return nil, fmt.Errorf("password must be at least %d characters long", PasswordMinLength)
	}

	if len(crypt64) == 0 {
		return nil, errors.New("encrypted text cannot be empty")
	}

	crypt, err := base64.StdEncoding.DecodeString(crypt64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 string: %w", err)
	}

	// Check if we have the algorithm indicator by checking the length
	var algorithm KeyDerivationAlgorithm
	var salt, nonce, ciphertext, hmacValue []byte

	// Modern format with algorithm indicator
	if len(crypt) >= AlgorithmIndicatorLength+saltSize+nonceSize+hmacSize {
		// Extract algorithm indicator (trim nulls)
		algoBytes := crypt[:AlgorithmIndicatorLength]
		algoStr := strings.TrimRight(string(algoBytes), "\x00")
		if algoStr != "" {
			// Detect which algorithm it is
			switch {
			case strings.HasPrefix(algoStr, string(PBKDF2SHA512Algorithm)):
				algorithm = PBKDF2SHA512Algorithm
			case strings.HasPrefix(algoStr, string(PBKDF2SHA256Algorithm)):
				algorithm = PBKDF2SHA256Algorithm
			case strings.HasPrefix(algoStr, string(Argon2idAlgorithm)):
				algorithm = Argon2idAlgorithm
			default:
				// Unknown algorithm
				algorithm = KeyDerivationAlgorithm(algoStr)
			}

			salt = crypt[AlgorithmIndicatorLength : AlgorithmIndicatorLength+saltSize]
			nonce = crypt[AlgorithmIndicatorLength+saltSize : AlgorithmIndicatorLength+saltSize+nonceSize]
			ciphertext = crypt[AlgorithmIndicatorLength+saltSize+nonceSize : len(crypt)-hmacSize]
			hmacValue = crypt[len(crypt)-hmacSize:]
		}
	}

	// Legacy format (without algorithm indicator)
	if algorithm == "" {
		if len(crypt) < saltSize+nonceSize+hmacSize {
			return nil, errors.New("ciphertext too short")
		}
		algorithm = Argon2idAlgorithm // Default to Argon2id for backward compatibility
		salt = crypt[:saltSize]
		nonce = crypt[saltSize : saltSize+nonceSize]
		ciphertext = crypt[saltSize+nonceSize : len(crypt)-hmacSize]
		hmacValue = crypt[len(crypt)-hmacSize:]
	}

	// Derive key from password and salt using the detected algorithm
	key := deriveKey(password, salt, algorithm)

	// Verify HMAC
	expectedHMAC := computeHMAC(key, append(nonce, ciphertext...))
	if !hmac.Equal(hmacValue, expectedHMAC) {
		return nil, errors.New("HMAC validation failed: possible incorrect password or corrupted data")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Decrypt the ciphertext
	compressed, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt ciphertext: %w", err)
	}

	// Decompress plaintext
	plaintext, err := decompress(compressed)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress plaintext: %w", err)
	}

	// Protect plaintext with memguard and return the protected buffer
	// IMPORTANT: The caller must destroy this buffer after use
	return memguard.NewBufferFromBytes(plaintext), nil
}

// DecryptToString decrypts a base64-encoded ciphertext string and returns the plaintext as a string.
// Note: This is less secure than Decrypt as it creates an unprotected string copy of the data.
func DecryptToString(password, crypt64 string) (string, error) {
	buffer, err := Decrypt(password, crypt64)
	if err != nil {
		return "", err
	}
	defer buffer.Destroy()

	return string(buffer.Bytes()), nil
}

// deriveKey derives a 32-byte key from the given password and salt using the specified algorithm.
func deriveKey(password string, salt []byte, algorithm KeyDerivationAlgorithm) []byte {
	switch algorithm {
	case PBKDF2SHA256Algorithm:
		return pbkdf2.Key([]byte(password), salt, pbkdf2SHA256Iterations, keySize, sha256.New)
	case PBKDF2SHA512Algorithm:
		return pbkdf2.Key([]byte(password), salt, pbkdf2SHA512Iterations, keySize, sha512.New)
	default:
		// Default to Argon2id
		return argon2.IDKey([]byte(password), salt, argon2Iterations, argon2Memory, argon2Threads, keySize)
	}
}

// GetAvailableKeyDerivationAlgorithms returns the list of available key derivation algorithms
func GetAvailableKeyDerivationAlgorithms() []KeyDerivationAlgorithm {
	return []KeyDerivationAlgorithm{
		Argon2idAlgorithm,
		PBKDF2SHA256Algorithm,
		PBKDF2SHA512Algorithm,
	}
}

// computeHMAC computes the HMAC for given data using the provided key.
func computeHMAC(key, data []byte) []byte {
	if key == nil {
		panic("key cannot be nil")
	}
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// compress compresses data using gzip.
func compress(data []byte) ([]byte, error) {
	if data == nil {
		return nil, errors.New("data cannot be nil")
	}
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
	if data == nil {
		return nil, errors.New("data cannot be nil")
	}
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(reader)
}
