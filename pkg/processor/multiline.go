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

// DecryptMultiline decrypts a previously encrypted multiline scalar node
func DecryptMultiline(node *yaml.Node, key string, originalStyle yaml.Style, debug bool) error {
	if node == nil || node.Kind != yaml.ScalarNode || !strings.HasPrefix(node.Value, AES) {
		return nil
	}

	// Check for style marker
	hasEscapedNewlinesMarker := strings.HasSuffix(node.Value, MarkerEscapedNewlines)
	if hasEscapedNewlinesMarker {
		// Remove the marker before decryption
		node.Value = strings.TrimSuffix(node.Value, MarkerEscapedNewlines)
	}

	// Decrypt the value
	decryptedBuffer, err := encryption.Decrypt(key, strings.TrimPrefix(node.Value, AES))
	if err != nil {
		return err
	}
	defer decryptedBuffer.Destroy() // Clean up the protected buffer

	// Set the decrypted value
	decryptedValue := string(decryptedBuffer.Bytes())

	// Check if this is content with escaped newlines (like a certificate in a quoted string)
	hasEscapedNewlines := strings.Contains(decryptedValue, "\\n")

	// If it has escaped newlines or had the marker, preserve that format
	if hasEscapedNewlines || hasEscapedNewlinesMarker {
		debugLog(debug, "Preserving escaped newlines format")
		node.Value = decryptedValue
		// For escaped newline format, we should use DoubleQuotedStyle
		node.Style = yaml.DoubleQuotedStyle
		return nil
	}

	// For regular multiline content
	node.Value = decryptedValue

	// Determine the appropriate style based on content and original style
	if IsMultilineContent(decryptedValue) {
		// If we're restoring a multiline value, ensure we use an appropriate style
		if originalStyle == 0 || originalStyle == yaml.TaggedStyle || originalStyle == yaml.DoubleQuotedStyle || originalStyle == yaml.SingleQuotedStyle {
			// For certain content types, we need to ensure appropriate styling
			switch {
			case hasCertificateKeyPatterns(decryptedValue):
				// Check if this content should be represented with escaped newlines
				if strings.Contains(decryptedValue, "PUBLIC KEY") || strings.Contains(decryptedValue, "CERTIFICATE") {
					// If this is certificate content with real newlines that should be escaped
					// we'll keep the actual newlines and set double quoted style
					node.Style = yaml.DoubleQuotedStyle
					debugLog(debug, "Setting double quoted style for certificate content")
				} else {
					// Other certificate/key content should use literal style to preserve exact formatting
					node.Style = yaml.LiteralStyle
					debugLog(debug, "Setting literal style for certificate/key content")
				}
			case strings.Contains(decryptedValue, "\t"):
				// Content with tabs should use literal style
				node.Style = yaml.LiteralStyle
				debugLog(debug, "Setting literal style for content with tabs")
			default:
				// Default to original style or literal style if original is plain
				node.Style = originalStyle
				if node.Style == 0 {
					node.Style = yaml.LiteralStyle
				}
			}
		} else {
			// Use the original style if it was already a multiline style
			node.Style = originalStyle
		}
	} else {
		// For single-line content, use plain style
		node.Style = 0
	}

	debugLog(debug, "Decrypted multiline node and set style: %v", node.Style)
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

	// Set appropriate style based on content
	originalStyle := yaml.LiteralStyle

	// Explicit check for quoted key
	if isQuotedKeyWithEscapes || path == PathQuotedPublicKey ||
		(strings.Contains(decryptedValue, "\\n") && strings.Contains(decryptedValue, "PUBLIC KEY")) {
		// Force DoubleQuoted style for strings with escaped newlines
		originalStyle = yaml.DoubleQuotedStyle
	} else if IsMultilineContent(decryptedValue) {
		// If there are actual newlines, use LiteralStyle
		originalStyle = yaml.LiteralStyle
	}

	// Try to restore the style based on current context
	if err := DecryptMultiline(node, key, originalStyle, debug); err != nil {
		return false, err
	}

	// Additional check for quoted_public_key
	if path == PathQuotedPublicKey && !strings.Contains(node.Value, "\\n") {
		// Explicitly convert newlines to escaped newlines if they're not already there
		node.Value = strings.ReplaceAll(node.Value, "\n", "\\n")
		node.Style = yaml.DoubleQuotedStyle
	}

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
