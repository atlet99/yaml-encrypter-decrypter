package processor

import (
	"strings"

	"github.com/atlet99/yaml-encrypter-decrypter/pkg/encryption"
	"gopkg.in/yaml.v3"
)

// MultilineStyle represents different YAML multiline styles
type MultilineStyle int

const (
	// NotMultiline indicates a regular scalar node
	NotMultiline MultilineStyle = iota
	// LiteralStyle represents the literal style (|)
	LiteralStyle
	// FoldedStyle represents the folded style (>)
	FoldedStyle
)

// Constants for various paths and markers
const (
	// PathQuotedPublicKey is the path for the quoted public key in certificates
	PathQuotedPublicKey = "certificates.quoted_public_key"
	// MarkerQuotedKeyWithEscapes indicates a quoted key with escaped newlines
	MarkerQuotedKeyWithEscapes = "|quoted_key_with_escapes"
	// MarkerEscapedNewlines indicates a node with escaped newlines
	MarkerEscapedNewlines = "|escaped_newlines"
)

// DetectMultilineStyle detects the multiline style of a YAML node
func DetectMultilineStyle(node *yaml.Node) MultilineStyle {
	if node == nil || node.Kind != yaml.ScalarNode {
		return NotMultiline
	}

	// Check for literal style (|)
	if node.Style == yaml.LiteralStyle {
		return LiteralStyle
	}

	// Check for folded style (>)
	if node.Style == yaml.FoldedStyle {
		return FoldedStyle
	}

	return NotMultiline
}

// EncryptMultiline encrypts a multiline scalar node
func EncryptMultiline(node *yaml.Node, key string, debug bool) error {
	if node == nil || node.Kind != yaml.ScalarNode {
		return nil
	}

	// Check for multiline style (literal or folded)
	style := DetectMultilineStyle(node)

	// Also check if this is a node with DoubleQuotedStyle that may contain escaped newlines
	hasEscapedNewlines := false
	isMultilineQuotedStyle := false

	if node.Style == yaml.DoubleQuotedStyle {
		hasEscapedNewlines = strings.Contains(node.Value, "\\n")
		isMultilineQuotedStyle = hasEscapedNewlines && hasCertificateKeyPatterns(node.Value)
	}

	// Only continue if this is a multiline node or has escaped newlines in DoubleQuotedStyle
	if style == NotMultiline && !isMultilineQuotedStyle {
		return nil
	}

	// Store the original style
	originalStyle := node.Style

	// Add debug log
	debugLog(debug, "Encrypting multiline node with style %v, hasEscapedNewlines=%v", originalStyle, hasEscapedNewlines)

	// Encrypt the value
	encryptedValue, err := encryption.Encrypt(key, node.Value)
	if err != nil {
		return err
	}

	// Set the encrypted value with the AES prefix
	node.Value = AES + encryptedValue

	// Add style marker for nodes with escaped newlines
	if hasEscapedNewlines || node.Style == yaml.DoubleQuotedStyle {
		// Add a marker to indicate this was in DoubleQuotedStyle
		node.Value += MarkerEscapedNewlines
		debugLog(debug, "Added escaped_newlines marker")
	}

	// Reset the style to plain (0 is no style, which is the default for plain scalar)
	node.Style = 0

	debugLog(debug, "Encrypted multiline node with style: %v", originalStyle)
	return nil
}

// DecryptMultiline decrypts a multiline YAML node value and restores its style if needed
func DecryptMultiline(node *yaml.Node, decryptFn func(string) (string, error)) error {
	if node == nil || node.Kind != yaml.ScalarNode {
		return nil
	}

	// Store the original style before decryption
	originalStyle := node.Style

	// If the value doesn't start with our encryption marker, there's nothing to decrypt
	if !strings.HasPrefix(node.Value, AES) {
		return nil
	}

	// Extract the encrypted value (skipping the AES marker)
	encryptedValue := strings.TrimPrefix(node.Value, AES)

	// Check for and remove any style markers
	hasEscapedNewlines := strings.HasSuffix(encryptedValue, MarkerEscapedNewlines)
	if hasEscapedNewlines {
		encryptedValue = strings.TrimSuffix(encryptedValue, MarkerEscapedNewlines)
	}

	// Decrypt the value using the provided decryption function
	decryptedValue, err := decryptFn(AES + encryptedValue)
	if err != nil {
		return err
	}

	// Update the node value with the decrypted value
	node.Value = decryptedValue

	// Check for common conditions
	hasMultilineContent := strings.Contains(decryptedValue, "\n")
	isPEMFormat := strings.HasPrefix(decryptedValue, "-----BEGIN") && strings.Contains(decryptedValue, "-----END")
	hasCertOrKey := hasCertificateKeyPatterns(decryptedValue)

	// Restore the style based on content
	switch {
	case hasCertOrKey && strings.Contains(decryptedValue, "\\n"):
		// For certificates/keys with escaped newlines, use DoubleQuotedStyle
		node.Style = yaml.DoubleQuotedStyle
	case hasMultilineContent && isPEMFormat:
		// For PEM formatted data
		switch {
		case strings.Contains(decryptedValue, "CERTIFICATE") || strings.Contains(decryptedValue, "PUBLIC KEY"):
			// Use LiteralStyle for certificates and public keys when they have actual newlines
			// This preserves proper formatting in YAML
			switch {
			case strings.Contains(decryptedValue, "\\n"):
				// Use DoubleQuotedStyle only for escaped newlines
				node.Style = yaml.DoubleQuotedStyle
			case originalStyle == yaml.LiteralStyle:
				// Preserve literal style if it was set
				node.Style = originalStyle
			default:
				// Default is LiteralStyle for better readability
				node.Style = yaml.LiteralStyle
			}
		case originalStyle == yaml.LiteralStyle || originalStyle == yaml.FoldedStyle:
			// Preserve original style if it was literal or folded
			node.Style = originalStyle
		default:
			// Default to LiteralStyle for other PEM content
			node.Style = yaml.LiteralStyle
		}
	case hasMultilineContent && (originalStyle == yaml.LiteralStyle || originalStyle == yaml.FoldedStyle):
		// Preserve literal or folded style for other multiline content
		node.Style = originalStyle
	case hasMultilineContent:
		// Default to LiteralStyle for multiline content with no specific style
		node.Style = yaml.LiteralStyle
	case originalStyle != 0:
		// If there was a specific style originally, restore it for non-multiline content
		node.Style = originalStyle
	}

	return nil
}

// processQuotedPublicKeyDecryption performs special processing for quoted_public_key during decryption
func processQuotedPublicKeyDecryption(node *yaml.Node, key string, debug bool) (bool, error) {
	if strings.HasPrefix(node.Value, AES) {
		// Decrypt the value
		decryptedBuffer, err := encryption.Decrypt(key, strings.TrimPrefix(node.Value, AES))
		if err != nil {
			return false, err
		}
		defer decryptedBuffer.Destroy()

		// Get the decrypted value
		node.Value = string(decryptedBuffer.Bytes())

		// Explicitly set the style for string with escaped newlines
		node.Style = yaml.DoubleQuotedStyle

		return true, nil
	}
	return false, nil
}

// determineNodeStyleForEncryption determines the node style for encryption
func determineNodeStyleForEncryption(node *yaml.Node, path string, debug bool) (bool, bool) {
	// First check if the node already has a multiline style
	style := DetectMultilineStyle(node)
	isMultiline := style != NotMultiline

	// If not a multiline style, check the content
	if !isMultiline {
		// Check if the string contains actual newlines
		isMultiline = IsMultilineContent(node.Value)

		// Check for content with escaped newlines
		hasEscapedNewlines := strings.Contains(node.Value, "\\n")
		if hasEscapedNewlines && hasCertificateKeyPatterns(node.Value) {
			isMultiline = true
		}

		// For special content types, we need to consider them multiline even if they don't have explicit newlines yet
		if !isMultiline {
			// Check for certificate/key content patterns that might need to be treated as multiline
			if hasCertificateKeyPatterns(node.Value) {
				isMultiline = true
				debugLog(debug, "Detected certificate/key content for multiline treatment at path %s", path)

				// For content with escaped newlines, preserve DoubleQuoted style
				if strings.Contains(node.Value, "\\n") {
					node.Style = yaml.DoubleQuotedStyle
				} else {
					// Set literal style for certificate/key content
					node.Style = yaml.LiteralStyle
				}
			}
		} else {
			// Content has newlines, set appropriate style
			if strings.Contains(node.Value, "\\n") {
				node.Style = yaml.DoubleQuotedStyle
				debugLog(debug, "Setting double quoted style for content with escaped newlines at path %s", path)
			} else {
				node.Style = yaml.LiteralStyle
				debugLog(debug, "Setting literal style for content with newlines at path %s", path)
			}
		}
	}

	return isMultiline, strings.Contains(node.Value, "\\n")
}

// processEncryptedNodeForDecryption processes an encrypted node for decryption
func processEncryptedNodeForDecryption(node *yaml.Node, path string, key string, debug bool) (bool, error) {
	debugLog(debug, "Processing encrypted node for decryption at path %s", path)
	debugLog(debug, "Node style before processing: %d", node.Style)

	// Store original style to preserve it if needed
	originalStyle := node.Style

	// Check for special marker for quoted_public_key
	isQuotedKeyWithEscapes := strings.HasSuffix(node.Value, MarkerQuotedKeyWithEscapes)
	if isQuotedKeyWithEscapes {
		// Remove the marker
		node.Value = strings.TrimSuffix(node.Value, MarkerQuotedKeyWithEscapes)
	}

	// Check if this was a node with a certificate or key with escaped newlines
	// For this, we'll look at the encrypted data
	encrypted := strings.TrimPrefix(node.Value, AES)
	decryptedBuffer, err := encryption.Decrypt(key, encrypted)
	if err != nil {
		return false, err
	}

	// Check the decrypted content to determine style
	decryptedValue := string(decryptedBuffer.Bytes())
	decryptedBuffer.Destroy()

	// Prepare the node for re-decryption
	node.Value = AES + encrypted

	// Set style based on content and original style
	switch {
	case originalStyle == yaml.LiteralStyle:
		// Explicitly preserve LiteralStyle (|-) if it was set
		debugLog(debug, "Preserving original LiteralStyle (|-) for node at path %s", path)
		// We'll let DecryptMultiline handle the final style setting
	case isQuotedKeyWithEscapes || path == PathQuotedPublicKey ||
		(strings.Contains(decryptedValue, "\\n") && strings.Contains(decryptedValue, "PUBLIC KEY")):
		// Force DoubleQuoted style for strings with escaped newlines
		node.Style = yaml.DoubleQuotedStyle
	case IsMultilineContent(decryptedValue):
		// If there are actual newlines, use LiteralStyle
		node.Style = yaml.LiteralStyle
	}

	// Try to restore the style based on current context
	if err := DecryptMultiline(node, func(value string) (string, error) {
		decryptedBuffer, err := encryption.Decrypt(key, strings.TrimPrefix(value, AES))
		if err != nil {
			return "", err
		}
		defer decryptedBuffer.Destroy()
		return string(decryptedBuffer.Bytes()), nil
	}); err != nil {
		return false, err
	}

	// Additional check for quoted_public_key
	if path == PathQuotedPublicKey && !strings.Contains(node.Value, "\\n") {
		// Explicitly convert newlines to escaped newlines if they're not already there
		node.Value = strings.ReplaceAll(node.Value, "\n", "\\n")
		node.Style = yaml.DoubleQuotedStyle
	}

	debugLog(debug, "Node style after processing: %d", node.Style)
	return true, nil
}

// ProcessMultilineNode processes a scalar node with multiline handling
func ProcessMultilineNode(node *yaml.Node, path string, key, operation string, debug bool) (bool, error) {
	if node == nil || node.Kind != yaml.ScalarNode {
		return false, nil
	}

	debugLog(debug, "Checking multiline node at path %s with style %v", path, node.Style)

	// For preserving escaped newlines in quoted_public_key
	if path == PathQuotedPublicKey && operation == OperationDecrypt {
		processed, err := processQuotedPublicKeyDecryption(node, key, debug)
		if err != nil || processed {
			return processed, err
		}
	}

	// For encryption, check if node has a multiline style or multiline content
	if operation == OperationEncrypt {
		// Determine the node style
		isMultiline, hasEscapedNewlines := determineNodeStyleForEncryption(node, path, debug)

		// If multiline content or style is detected, encrypt it
		if isMultiline && !strings.HasPrefix(node.Value, AES) {
			debugLog(debug, "Processing multiline node for encryption at path %s with style %v", path, node.Style)
			if err := EncryptMultiline(node, key, debug); err != nil {
				return false, err
			}

			// For the path certificates.quoted_public_key save information about escaped newlines
			if path == PathQuotedPublicKey && hasEscapedNewlines {
				// Add a special marker for quoted_public_key
				node.Value += MarkerQuotedKeyWithEscapes
			}

			return true, nil // Processed
		}
	} else if operation == OperationDecrypt {
		// For decryption, check if the value starts with AES prefix
		if strings.HasPrefix(node.Value, AES) {
			return processEncryptedNodeForDecryption(node, path, key, debug)
		}
	}

	return false, nil
}

// IsMultilineContent checks if a string is likely multiline content
func IsMultilineContent(content string) bool {
	return strings.Contains(content, "\n")
}

// hasCertificateKeyPatterns checks if a string has patterns typical for certificates or keys
func hasCertificateKeyPatterns(content string) bool {
	// Check for escaped newlines as might be present in quoted strings
	hasEscapedNewlines := strings.Contains(content, "\\n")

	// Look for common certificate/key markers
	patterns := []string{
		"-----BEGIN", "-----END", // Generic certificate/key markers
		"PRIVATE KEY", "PUBLIC KEY", "CERTIFICATE", // Common key/cert types
		"RSA PRIVATE", "DSA PRIVATE", "EC PRIVATE", // Specific key types
		"OPENSSH PRIVATE", "SSH2 ENCRYPTED", // SSH keys
		"PGP PRIVATE", "PGP PUBLIC", // PGP keys
		"X509", // X509 certificates
	}

	// Check for certificate/key patterns regardless of newline style
	for _, pattern := range patterns {
		if strings.Contains(content, pattern) {
			// Return true if it's a certificate/key with or without escaped newlines
			return hasEscapedNewlines || IsMultilineContent(content)
		}
	}

	return false
}
