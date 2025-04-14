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

	style := DetectMultilineStyle(node)
	if style == NotMultiline {
		return nil // Not a multiline node
	}

	// Store the original style
	originalStyle := node.Style

	// Encrypt the value
	encryptedValue, err := encryption.Encrypt(key, node.Value)
	if err != nil {
		return err
	}

	// Set the encrypted value with the AES prefix
	node.Value = AES + encryptedValue

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

	// Decrypt the value
	decryptedBuffer, err := encryption.Decrypt(key, strings.TrimPrefix(node.Value, AES))
	if err != nil {
		return err
	}
	defer decryptedBuffer.Destroy() // Clean up the protected buffer

	// Set the decrypted value
	decryptedValue := string(decryptedBuffer.Bytes())

	// Check if this is PEM content with escaped newlines
	isPEMWithEscapedNewlines := strings.Contains(decryptedValue, "\\n") &&
		strings.Contains(decryptedValue, "-----BEGIN") &&
		strings.Contains(decryptedValue, "-----END")

	// If it's a PEM with escaped newlines, preserve that format
	if isPEMWithEscapedNewlines {
		debugLog(debug, "Preserving PEM with escaped newlines format")
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
			case strings.Contains(decryptedValue, "-----BEGIN") && strings.Contains(decryptedValue, "-----END"):
				// PEM keys should use literal style to preserve exact formatting
				node.Style = yaml.LiteralStyle
				debugLog(debug, "Setting literal style for PEM content")
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

// ProcessMultilineNode processes a scalar node with multiline handling
func ProcessMultilineNode(node *yaml.Node, path string, key, operation string, debug bool) (bool, error) {
	if node == nil || node.Kind != yaml.ScalarNode {
		return false, nil
	}

	debugLog(debug, "Checking multiline node at path %s with style %v", path, node.Style)

	// For encryption, check if node has a multiline style or multiline content
	if operation == OperationEncrypt {
		// First check if the node already has a multiline style
		style := DetectMultilineStyle(node)
		isMultiline := style != NotMultiline

		// If not a multiline style, check the content
		if !isMultiline {
			isMultiline = IsMultilineContent(node.Value)

			// For special content types, we need to consider them multiline even if they don't have explicit newlines yet
			if !isMultiline {
				// Check for PEM-like content that might get expanded to multiline
				if strings.Contains(node.Value, "-----BEGIN") && strings.Contains(node.Value, "-----END") {
					isMultiline = true
					debugLog(debug, "Detected PEM content for multiline treatment at path %s", path)
					// Set literal style for PEM content
					node.Style = yaml.LiteralStyle
				}
			} else {
				// Content has newlines, set appropriate style
				node.Style = yaml.LiteralStyle
				debugLog(debug, "Setting literal style for content with newlines at path %s", path)
			}
		}

		// If multiline content or style is detected, encrypt it
		if isMultiline && !strings.HasPrefix(node.Value, AES) {
			debugLog(debug, "Processing multiline node for encryption at path %s with style %v", path, node.Style)
			if err := EncryptMultiline(node, key, debug); err != nil {
				return false, err
			}
			return true, nil // Processed
		}
	} else if operation == OperationDecrypt {
		// For decryption, check if the value starts with AES prefix
		if strings.HasPrefix(node.Value, AES) {
			debugLog(debug, "Processing encrypted node for decryption at path %s", path)

			// For decryption, we need to determine what style to use after decryption
			// Default to literal style for multiline, will be refined in DecryptMultiline
			var originalStyle yaml.Style = yaml.LiteralStyle

			// Try to restore the style based on current context
			if err := DecryptMultiline(node, key, originalStyle, debug); err != nil {
				return false, err
			}

			return true, nil // Processed
		}
	}

	return false, nil
}

// IsMultilineContent checks if a string is likely multiline content
func IsMultilineContent(content string) bool {
	return strings.Contains(content, "\n")
}
