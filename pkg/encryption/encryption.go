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
	"os"
	"strings"
	"time"

	"github.com/awnumar/memguard"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

// KeyDerivationAlgorithm represents the algorithm used for key derivation
type KeyDerivationAlgorithm string

const (
	// Key derivation algorithms
	PBKDF2SHA512Algorithm KeyDerivationAlgorithm = "pbkdf2-sha512"
	PBKDF2SHA256Algorithm KeyDerivationAlgorithm = "pbkdf2-sha256"
	Argon2idAlgorithm     KeyDerivationAlgorithm = "argon2id"

	// Key sizes
	keySize = 32 // 256 bits for AES-256

	// Salt and nonce sizes
	saltSize  = 32
	nonceSize = 12

	// HMAC size
	hmacSize = 32

	// Algorithm indicator size
	AlgorithmIndicatorLength = 1

	// Key derivation constants
	argon2IterationsCount = 4    // Argon2 iterations (t)
	argon2MemoryKiB       = 9216 // Memory usage to 9 MiB (OWASP recommendation)
	argon2ThreadCount     = 1    // Threads (p) as per OWASP recommendation

	// These constants needed for tests
	Argon2idTime    = 4
	Argon2idMemory  = 9216
	Argon2idThreads = 1
	Argon2idKeyLen  = 32
	PBKDF2KeyLen    = 32

	// Constants for cutting data parts for debugging
	previewShortBytes = 4  // Minimum number of bytes for preview
	previewBytes      = 16 // Standard number of bytes for preview
	previewChars      = 20 // Number of characters to display for preview
	maxCiphertextLen  = 64 // Maximum length for ciphertext
	minPasswordLen    = 15 // Minimum password length (NIST SP 800-63B)
	maxPasswordLen    = 64 // Maximum password length
	shortPasswPreview = 10 // Number of characters to display at the beginning of password
	shortEncPreview   = 20 // Number of characters to display at the beginning of encrypted text

	// Constants for algorithm indicators
	Argon2idIndicator     byte = 0x01
	PBKDF2SHA256Indicator byte = 0x02
	PBKDF2SHA512Indicator byte = 0x03

	// Constants for percentage calculations
	percentMultiplier = 100.0 // Multiplier for percentage calculations

	// Constants for normalization factor in compression calculation
	normalizationFactor = 1.0 // Normalization factor for ratio calculations
)

// Argon2id parameters (OWASP recommended)
var (
	argon2Iterations = uint32(argon2IterationsCount) // Argon2 iterations (t)
	argon2Memory     = uint32(argon2MemoryKiB)       // Memory usage to 9 MiB (OWASP recommendation)
	argon2Threads    = uint8(argon2ThreadCount)      // Threads (p) as per OWASP recommendation

	// PBKDF2 parameters (OWASP recommended)
	pbkdf2SHA256Iterations = 600000 // PBKDF2-HMAC-SHA256: 600,000 iterations
	pbkdf2SHA512Iterations = 210000 // PBKDF2-HMAC-SHA512: 210,000 iterations
)

// Global variables
var (
	debugMode                     bool                   = false
	DefaultKeyDerivationAlgorithm KeyDerivationAlgorithm = Argon2idAlgorithm
)

// init initializes encryption parameters and checks the debug flag
func init() {
	// Check for the --debug argument
	for _, arg := range os.Args {
		if arg == "--debug" {
			debugMode = true
			break
		}
	}
}

// debugPrint outputs debug messages only when debug mode is enabled
func debugPrint(format string, args ...interface{}) {
	if debugMode {
		fmt.Printf(format, args...)
	}
}

// maskSensitiveData masks sensitive data for display in debug logs
func maskSensitiveData(data []byte) string {
	if len(data) == 0 {
		return "[]"
	}

	// Use constant instead of magic number
	if len(data) <= previewShortBytes {
		return fmt.Sprintf("%x... (%d bytes)", data[:1], len(data))
	}

	// Show first two and last two bytes with length
	return fmt.Sprintf("%x...%x (%d bytes)",
		data[:2],
		data[len(data)-2:],
		len(data))
}

// Encrypt encrypts a plaintext string using AES-256 GCM with the specified key derivation algorithm and returns a base64-encoded ciphertext.
func Encrypt(password, plaintext string, algorithm ...KeyDerivationAlgorithm) (string, error) {
	debugPrint("[DEBUG:Encrypt] Starting encryption process\n")
	debugPrint("[DEBUG:Encrypt] Input length: %d bytes\n", len(plaintext))

	// Check password strength
	if err := ValidatePasswordStrength(password); err != nil {
		debugPrint("[DEBUG:Encrypt] Password validation failed: %v\n", err)
		return "", err
	}

	if len(plaintext) == 0 {
		debugPrint("[DEBUG:Encrypt] Error: plaintext is empty\n")
		return "", errors.New("plaintext cannot be empty")
	}

	// Set default algorithm if not specified
	var algo KeyDerivationAlgorithm
	if len(algorithm) > 0 && algorithm[0] != "" {
		algo = algorithm[0]
		debugPrint("[DEBUG:Encrypt] Using provided algorithm: '%s'\n", algo)
	} else {
		algo = DefaultKeyDerivationAlgorithm
		debugPrint("[DEBUG:Encrypt] Using default algorithm: '%s'\n", algo)
	}

	// Check for style suffixes
	styleSuffix := ""
	for _, suffix := range []string{"|", ">"} {
		if strings.HasSuffix(plaintext, suffix) {
			styleSuffix = suffix
			plaintext = plaintext[:len(plaintext)-len(suffix)]
			debugPrint("[DEBUG:Encrypt] Detected style suffix: '%s'\n", styleSuffix)
			break
		}
	}

	// Compress plaintext
	debugPrint("[DEBUG:Encrypt] Compressing plaintext (%d bytes)\n", len(plaintext))
	compressed, err := compress([]byte(plaintext))
	if err != nil {
		debugPrint("[DEBUG:Encrypt] Compression failed: %v\n", err)
		return "", fmt.Errorf("failed to compress plaintext: %w", err)
	}
	debugPrint("[DEBUG:Encrypt] Compressed size: %d bytes (%.1f%% reduction)\n",
		len(compressed), percentMultiplier*(normalizationFactor-float64(len(compressed))/float64(len(plaintext))))

	// Generate random salt
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		debugPrint("[DEBUG:Encrypt] Failed to generate salt: %v\n", err)
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}
	debugPrint("[DEBUG:Encrypt] Generated salt: %s\n", maskSensitiveData(salt))

	// Derive key from password and salt
	debugPrint("[DEBUG:Encrypt] Deriving key using algorithm: %s\n", algo)
	key, err := deriveKey(password, salt, algo)
	if err != nil {
		debugPrint("[DEBUG:Encrypt] Key derivation failed: %v\n", err)
		return "", fmt.Errorf("failed to derive key: %w", err)
	}
	debugPrint("[DEBUG:Encrypt] Key derived successfully: %s\n", maskSensitiveData(key))

	// Create secure buffer for the key
	keyBuf := memguard.NewBufferFromBytes(key)
	if keyBuf == nil {
		debugPrint("[DEBUG:Encrypt] Failed to create secure buffer for key\n")
		return "", fmt.Errorf("failed to create secure buffer for key")
	}
	defer keyBuf.Destroy()
	debugPrint("[DEBUG:Encrypt] Created secure key buffer\n")

	// Generate random nonce
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		debugPrint("[DEBUG:Encrypt] Failed to generate nonce: %v\n", err)
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}
	debugPrint("[DEBUG:Encrypt] Generated nonce: %s\n", maskSensitiveData(nonce))

	// Create AES cipher
	debugPrint("[DEBUG:Encrypt] Creating AES cipher\n")
	block, err := aes.NewCipher(keyBuf.Bytes())
	if err != nil {
		debugPrint("[DEBUG:Encrypt] Failed to create AES cipher: %v\n", err)
		return "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		debugPrint("[DEBUG:Encrypt] Failed to create GCM: %v\n", err)
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}
	debugPrint("[DEBUG:Encrypt] AES-GCM cipher created successfully\n")

	// Encrypt data
	debugPrint("[DEBUG:Encrypt] Encrypting %d bytes of data\n", len(compressed))
	ciphertext := aesGCM.Seal(nil, nonce, compressed, nil)
	debugPrint("[DEBUG:Encrypt] Encrypted data size: %d bytes\n", len(ciphertext))

	// Combine all components
	result := make([]byte, 0, 1+len(salt)+len(nonce)+len(ciphertext))
	result = append(result, byte(algo[0]))
	result = append(result, salt...)
	result = append(result, nonce...)
	result = append(result, ciphertext...)

	// Calculate HMAC for all data up to this point
	debugPrint("[DEBUG:Encrypt] Calculating HMAC\n")
	hmacValue := computeHMAC(key, result, byte(algo[0]))
	debugPrint("[DEBUG:Encrypt] HMAC calculated: %s\n", maskSensitiveData(hmacValue))

	// Add HMAC to the result
	result = append(result, hmacValue...)
	debugPrint("[DEBUG:Encrypt] Final payload size: %d bytes\n", len(result))

	// Encode in base64
	encoded := base64.StdEncoding.EncodeToString(result)
	if styleSuffix != "" {
		encoded += styleSuffix
		debugPrint("[DEBUG:Encrypt] Added style suffix: '%s'\n", styleSuffix)
	}
	debugPrint("[DEBUG:Encrypt] Final base64 output length: %d characters\n", len(encoded))

	// Securely wipe sensitive data
	memguard.WipeBytes(key)
	debugPrint("[DEBUG:Encrypt] Sensitive data wiped\n")

	return encoded, nil
}

// Decrypt decrypts a base64-encoded ciphertext using AES-256 GCM with the specified key derivation algorithm and returns the plaintext.
func Decrypt(password, ciphertext string, algorithm ...KeyDerivationAlgorithm) (string, error) {
	debugPrint("[DEBUG:Decrypt] Starting decryption process\n")
	debugPrint("[DEBUG:Decrypt] Input length: %d bytes\n", len(ciphertext))

	if err := ValidatePasswordStrength(password); err != nil {
		debugPrint("[DEBUG:Decrypt] Password validation failed: %v\n", err)
		return "", err
	}

	if len(ciphertext) == 0 {
		debugPrint("[DEBUG:Decrypt] Error: ciphertext is empty\n")
		return "", errors.New("ciphertext cannot be empty")
	}

	// Set default algorithm if not provided
	var algo KeyDerivationAlgorithm
	if len(algorithm) > 0 && algorithm[0] != "" {
		algo = algorithm[0]
		debugPrint("[DEBUG:Decrypt] Using provided algorithm: '%s'\n", algo)
	} else {
		algo = DefaultKeyDerivationAlgorithm
		debugPrint("[DEBUG:Decrypt] Using default algorithm: '%s'\n", algo)
	}

	// Decode base64 ciphertext
	debugPrint("[DEBUG:Decrypt] Decoding base64 input\n")
	decoded, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		debugPrint("[DEBUG:Decrypt] Base64 decoding failed: %v\n", err)
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}
	debugPrint("[DEBUG:Decrypt] Decoded data size: %d bytes\n", len(decoded))

	// Extract components
	if len(decoded) < saltSize+nonceSize+1+hmacSize {
		debugPrint("[DEBUG:Decrypt] Error: payload too short (need at least %d bytes, got %d)\n",
			saltSize+nonceSize+1+hmacSize, len(decoded))
		return "", errors.New("invalid ciphertext: too short")
	}

	algorithmByte := decoded[0]
	salt := decoded[1 : 1+saltSize]
	nonce := decoded[1+saltSize : 1+saltSize+nonceSize]
	encryptedData := decoded[1+saltSize+nonceSize : len(decoded)-hmacSize]
	hmacValue := decoded[len(decoded)-hmacSize:]

	debugPrint("[DEBUG:Decrypt] Algorithm byte: 0x%02x\n", algorithmByte)
	debugPrint("[DEBUG:Decrypt] Salt: %s\n", maskSensitiveData(salt))
	debugPrint("[DEBUG:Decrypt] Nonce: %s\n", maskSensitiveData(nonce))
	debugPrint("[DEBUG:Decrypt] Encrypted data size: %d bytes\n", len(encryptedData))
	debugPrint("[DEBUG:Decrypt] HMAC: %s\n", maskSensitiveData(hmacValue))

	// Derive key
	debugPrint("[DEBUG:Decrypt] Deriving key using algorithm: %s\n", algo)
	key, err := deriveKey(password, salt, algo)
	if err != nil {
		debugPrint("[DEBUG:Decrypt] Key derivation failed: %v\n", err)
		return "", fmt.Errorf("failed to derive key: %w", err)
	}
	debugPrint("[DEBUG:Decrypt] Key derived successfully: %s\n", maskSensitiveData(key))

	// Create secure buffer for key
	keyBuf := memguard.NewBufferFromBytes(key)
	if keyBuf == nil {
		debugPrint("[DEBUG:Decrypt] Failed to create secure buffer for key\n")
		return "", fmt.Errorf("failed to create secure buffer for key")
	}
	defer keyBuf.Destroy()
	debugPrint("[DEBUG:Decrypt] Created secure key buffer\n")

	// Verify HMAC
	debugPrint("[DEBUG:Decrypt] Verifying HMAC\n")
	hmacData := decoded[:len(decoded)-hmacSize]
	expectedHMAC := computeHMAC(key, hmacData, algorithmByte)
	if !hmac.Equal(expectedHMAC, hmacValue) {
		debugPrint("[DEBUG:Decrypt] HMAC verification failed!\n")
		debugPrint("[DEBUG:Decrypt] Expected HMAC: %s\n", maskSensitiveData(expectedHMAC))
		debugPrint("[DEBUG:Decrypt] Received HMAC: %s\n", maskSensitiveData(hmacValue))
		return "", errors.New("cipher: message authentication failed")
	}
	debugPrint("[DEBUG:Decrypt] HMAC verified successfully\n")

	// Create cipher
	debugPrint("[DEBUG:Decrypt] Creating AES cipher\n")
	block, err := aes.NewCipher(keyBuf.Bytes())
	if err != nil {
		debugPrint("[DEBUG:Decrypt] Failed to create cipher: %v\n", err)
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		debugPrint("[DEBUG:Decrypt] Failed to create GCM: %v\n", err)
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}
	debugPrint("[DEBUG:Decrypt] AES-GCM cipher created successfully\n")

	// Decrypt data
	debugPrint("[DEBUG:Decrypt] Decrypting %d bytes of data\n", len(encryptedData))
	decryptedData, err := aesgcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		debugPrint("[DEBUG:Decrypt] Decryption failed: %v\n", err)
		return "", fmt.Errorf("failed to decrypt data: %w", err)
	}
	debugPrint("[DEBUG:Decrypt] Decrypted data size: %d bytes\n", len(decryptedData))

	// Decompress data
	debugPrint("[DEBUG:Decrypt] Decompressing data\n")
	decompressedData, err := decompress(decryptedData)
	if err != nil {
		debugPrint("[DEBUG:Decrypt] Decompression failed: %v\n", err)
		return "", fmt.Errorf("failed to decompress data: %w", err)
	}
	debugPrint("[DEBUG:Decrypt] Decompressed size: %d bytes\n", len(decompressedData))
	debugPrint("[DEBUG:Decrypt] Decryption completed successfully\n")

	return string(decompressedData), nil
}

// DecryptToString decrypts a base64-encoded ciphertext string and returns the plaintext as a string.
// Note: This is less secure than Decrypt as it creates an unprotected string copy of the data.
func DecryptToString(encrypted string, password string) (string, error) {
	// Add debug information for checking argument order
	debugPrint("[DEBUG] DecryptToString call - Password length: %d, Encrypted length: %d\n",
		len(password), len(encrypted))

	// Never show the password, always mask
	debugPrint("[DEBUG] Password: '[REDACTED]'\n")

	if len(encrypted) < shortEncPreview {
		debugPrint("[DEBUG] Encrypted: '%s'\n", encrypted)
	} else {
		debugPrint("[DEBUG] Encrypted starts with: '%s'\n", encrypted[:min(shortEncPreview, len(encrypted))])
	}

	// Ensure we're not trying to decrypt the key itself
	if len(encrypted) < 20 && strings.HasPrefix(password, encrypted) {
		return "", fmt.Errorf("error: attempting to decrypt the password itself, check argument order")
	}

	// Correctly pass arguments - first password, second encrypted text
	return Decrypt(password, encrypted)
}

// min returns the smaller of x or y.
func min(x, y int) int {
	if x < y {
		return x
	}
	return y
}

// max returns the maximum of two integers
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// compress compresses data using gzip.
func compress(data []byte) ([]byte, error) {
	debugPrint("[DEBUG:Compress] Compressing %d bytes of data\n", len(data))
	startTime := time.Now()

	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		debugPrint("[DEBUG:Compress] Error creating gzip writer: %v\n", err)
		return nil, err
	}

	// Write data to gzip writer
	bytesWritten, err := zw.Write(data)
	if err != nil {
		debugPrint("[DEBUG:Compress] Error writing to gzip: %v\n", err)
		return nil, err
	}
	debugPrint("[DEBUG:Compress] Written %d bytes to gzip writer\n", bytesWritten)

	if err := zw.Close(); err != nil {
		debugPrint("[DEBUG:Compress] Error closing gzip writer: %v\n", err)
		return nil, err
	}

	compressedData := buf.Bytes()
	compressionRatio := float64(len(compressedData)) / float64(len(data)) * percentMultiplier
	debugPrint("[DEBUG:Compress] Compression complete in %v\n", time.Since(startTime))
	debugPrint("[DEBUG:Compress] Original: %d bytes, Compressed: %d bytes (%.2f%%)\n",
		len(data), len(compressedData), compressionRatio)

	return compressedData, nil
}

// decompress decompresses gzipped data.
func decompress(compressedData []byte) ([]byte, error) {
	debugPrint("[DEBUG:Decompress] Decompressing %d bytes of data\n", len(compressedData))
	startTime := time.Now()

	// Create a reader for the compressed data
	reader, err := gzip.NewReader(bytes.NewReader(compressedData))
	if err != nil {
		debugPrint("[DEBUG:Decompress] Error creating gzip reader: %v\n", err)
		return nil, err
	}
	defer reader.Close()
	debugPrint("[DEBUG:Decompress] Gzip reader created successfully\n")

	// Read the decompressed data
	decompressedData, err := io.ReadAll(reader)
	if err != nil {
		debugPrint("[DEBUG:Decompress] Error reading decompressed data: %v\n", err)
		return nil, err
	}

	expansionRatio := float64(len(decompressedData)) / float64(len(compressedData))
	debugPrint("[DEBUG:Decompress] Decompression complete in %v\n", time.Since(startTime))
	debugPrint("[DEBUG:Decompress] Compressed: %d bytes, Decompressed: %d bytes (%.2fx larger)\n",
		len(compressedData), len(decompressedData), expansionRatio)

	return decompressedData, nil
}

// SetDefaultAlgorithm sets the default key derivation algorithm
func SetDefaultAlgorithm(algorithm KeyDerivationAlgorithm) {
	DefaultKeyDerivationAlgorithm = algorithm
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
func computeHMAC(key, data []byte, algorithm ...byte) []byte {
	debugPrint("[DEBUG:HMAC] Computing HMAC for %d bytes of data\n", len(data))

	// Create secure buffer for the key
	keyBuf := memguard.NewBufferFromBytes(key)
	if keyBuf == nil {
		debugPrint("[DEBUG:HMAC] Failed to create secure buffer for key\n")
		return nil
	}
	defer keyBuf.Destroy()
	debugPrint("[DEBUG:HMAC] Created secure buffer for key\n")

	// Create HMAC with key from secure buffer
	h := hmac.New(sha256.New, keyBuf.Bytes())

	// Write data directly to HMAC (not using secure buffer for data)
	h.Write(data)

	// Add algorithm byte to HMAC
	if len(algorithm) > 0 {
		alg := algorithm[0]
		debugPrint("[DEBUG:HMAC] Including algorithm byte in HMAC calculation: 0x%02x\n", alg)
		h.Write([]byte{alg})
	}

	// Get the result
	result := h.Sum(nil)
	debugPrint("[DEBUG:HMAC] HMAC calculation complete: %s\n", maskSensitiveData(result))

	return result
}

// deriveKey derives a 32-byte key from the given password and salt using the specified algorithm.
func deriveKey(password string, salt []byte, algorithm KeyDerivationAlgorithm) ([]byte, error) {
	debugPrint("[DEBUG:KeyDerive] Starting key derivation with algorithm: %s\n", algorithm)
	debugPrint("[DEBUG:KeyDerive] Password length: %d chars, Salt length: %d bytes\n",
		len(password), len(salt))

	// Derive key in regular memory
	var key []byte
	var timeTaken time.Time

	switch algorithm {
	case PBKDF2SHA512Algorithm:
		debugPrint("[DEBUG:KeyDerive] Using PBKDF2-SHA512 with %d iterations\n", pbkdf2SHA512Iterations)
		timeTaken = time.Now()
		key = pbkdf2.Key([]byte(password), salt, pbkdf2SHA512Iterations, keySize, sha512.New)
		debugPrint("[DEBUG:KeyDerive] PBKDF2-SHA512 completed in %v\n", time.Since(timeTaken))
	case PBKDF2SHA256Algorithm:
		debugPrint("[DEBUG:KeyDerive] Using PBKDF2-SHA256 with %d iterations\n", pbkdf2SHA256Iterations)
		timeTaken = time.Now()
		key = pbkdf2.Key([]byte(password), salt, pbkdf2SHA256Iterations, keySize, sha256.New)
		debugPrint("[DEBUG:KeyDerive] PBKDF2-SHA256 completed in %v\n", time.Since(timeTaken))
	case Argon2idAlgorithm:
		debugPrint("[DEBUG:KeyDerive] Using Argon2id with params: time=%d, memory=%dKiB, threads=%d\n",
			argon2Iterations, argon2Memory, argon2Threads)
		timeTaken = time.Now()
		key = argon2.IDKey([]byte(password), salt, argon2Iterations, argon2Memory, argon2Threads, keySize)
		debugPrint("[DEBUG:KeyDerive] Argon2id completed in %v\n", time.Since(timeTaken))
	default:
		err := fmt.Errorf("unsupported key derivation algorithm: %s", algorithm)
		debugPrint("[DEBUG:KeyDerive] Error: %v\n", err)
		return nil, err
	}

	// Create a copy of the key to return
	result := make([]byte, keySize)
	copy(result, key)
	debugPrint("[DEBUG:KeyDerive] Key derivation successful: %s\n", maskSensitiveData(result))

	// Wipe the original key from memory
	memguard.WipeBytes(key)
	debugPrint("[DEBUG:KeyDerive] Wiped original key from memory\n")

	return result, nil
}
