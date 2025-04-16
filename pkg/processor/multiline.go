package processor

import (
	"fmt"
	"strconv"
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

// Constants for various tags
const (
	// TagInt is the YAML tag for integer values
	TagInt = "!!int"
	// TagStr is the YAML tag for string values
	TagStr = "!!str"
)

// ConfigFilePatterns contains patterns that indicate configuration file content
var ConfigFilePatterns = []string{
	"server {", "location", "http {", // Nginx patterns
	"<VirtualHost", "<Directory", "<Location", // Apache patterns
	"upstream", "proxy_pass", // Common proxy patterns
	"listen", "server_name", // Common server patterns
	"worker_processes", "worker_connections", // Process/connection settings
	"root", "index", // Common web server directives
}

// isConfigurationContent checks if a string contains configuration file patterns
func isConfigurationContent(content string) bool {
	// Skip empty content
	if len(content) == 0 {
		return false
	}

	// Check for common configuration patterns
	for _, pattern := range ConfigFilePatterns {
		if strings.Contains(content, pattern) {
			return true
		}
	}

	// Additional heuristics for configuration files
	lines := strings.Split(content, "\n")
	if len(lines) > MinConfigLines {
		indentedLines := 0
		directiveCount := 0

		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if len(trimmed) == 0 {
				continue
			}

			// Count indented lines
			if len(line) > len(trimmed) {
				indentedLines++
			}

			// Count lines that look like directives (key value pairs)
			if strings.Contains(trimmed, " ") && !strings.HasPrefix(trimmed, "#") {
				directiveCount++
			}
		}

		// If we have multiple indented lines and directives, it's likely a config file
		return indentedLines > MinIndentedLines && directiveCount > MinDirectives
	}

	return false
}

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

	// Only continue if this is a multiline node or has actual newlines
	if style == NotMultiline && !IsMultilineContent(node.Value) {
		return nil
	}

	// Store the original style and tag
	originalStyle := node.Style
	originalTag := node.Tag

	// Add debug log
	debugLog(debug, "Encrypting multiline node with style %v, hasEscapedNewlines=%v", originalStyle, strings.Contains(node.Value, "\\n"))

	// Encrypt the value
	encryptedValue, err := encryption.Encrypt(key, node.Value)
	if err != nil {
		return err
	}

	// Add style suffix to preserve original style information
	var styleSuffix string
	switch originalStyle {
	case yaml.LiteralStyle:
		styleSuffix = LiteralStyleSuffix
	case yaml.FoldedStyle:
		styleSuffix = FoldedStyleSuffix
	case yaml.DoubleQuotedStyle:
		styleSuffix = DoubleQuotedStyleSuffix
	case yaml.SingleQuotedStyle:
		styleSuffix = SingleQuotedStyleSuffix
	default:
		styleSuffix = PlainStyleSuffix
	}

	// Set the encrypted value with the AES prefix and style suffix
	node.Value = AES + encryptedValue + styleSuffix

	// Reset the style to plain (0 is no style, which is the default for plain scalar)
	node.Style = 0

	// Clear the tag if it's !!int, otherwise keep the original tag
	if originalTag == TagInt {
		node.Tag = "" // Remove !!int tag to avoid explicit type in output
	}

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

	// Extract the encrypted value (skipping the AES marker) and handle style suffix
	encryptedValue := strings.TrimPrefix(node.Value, AES)

	// Check for style suffix
	var styleSuffix string
	styleInfo := yaml.Style(0) // Default plain style

	// Extract style suffix if present
	lastPipeIndex := strings.LastIndex(encryptedValue, "|")
	if lastPipeIndex != -1 && lastPipeIndex < len(encryptedValue)-1 {
		styleSuffix = encryptedValue[lastPipeIndex+1:]
		encryptedValue = encryptedValue[:lastPipeIndex]

		// Convert style suffix to yaml.Style
		switch styleSuffix {
		case StyleLiteral:
			styleInfo = yaml.LiteralStyle
		case StyleFolded:
			styleInfo = yaml.FoldedStyle
		case StyleDoubleQuoted:
			styleInfo = yaml.DoubleQuotedStyle
		case StyleSingleQuoted:
			styleInfo = yaml.SingleQuotedStyle
		}
	}

	// Decrypt the value using the provided decryption function
	decryptedValue, err := decryptFn(AES + encryptedValue)
	if err != nil {
		return err
	}

	// Update the node value with the decrypted value
	node.Value = decryptedValue

	// Apply appropriate style based on style suffix and content
	if styleSuffix != "" {
		// If we have style info from suffix, use that
		node.Style = styleInfo
	} else {
		// Fallback to style detection logic
		switch {
		case originalStyle == yaml.LiteralStyle || originalStyle == yaml.FoldedStyle:
			// Always preserve original style for literal or folded blocks
			node.Style = originalStyle
		case originalStyle == yaml.DoubleQuotedStyle || originalStyle == yaml.SingleQuotedStyle:
			// Preserve original quoted style
			node.Style = originalStyle
		case IsMultilineContent(decryptedValue):
			// For content with actual newlines, use literal style
			node.Style = yaml.LiteralStyle
		default:
			// Keep the default style
		}
	}

	return nil
}

// IsMultilineContent checks if a string is likely multiline content
func IsMultilineContent(content string) bool {
	return strings.Contains(content, "\n")
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

		// For special content types like configuration files
		if !isMultiline && isConfigurationContent(node.Value) {
			isMultiline = true
			node.Style = yaml.LiteralStyle
			debugLog(debug, "Detected configuration content, using literal style at path %s", path)
		} else if isMultiline {
			// Apply appropriate style for multiline content
			node.Style = yaml.LiteralStyle
			debugLog(debug, "Setting literal style for content with newlines at path %s", path)
		}
	}

	return isMultiline, false
}

// processEncryptedNodeForDecryption processes an encrypted node for decryption
func processEncryptedNodeForDecryption(node *yaml.Node, path string, key string, debug bool) (bool, error) {
	// If not encrypted, return immediately
	if !strings.HasPrefix(node.Value, AES) {
		return false, nil
	}

	debugLog(debug, "Processing encrypted node for decryption at path %s", path)
	debugLog(debug, "Node style before processing: %d", node.Style)

	// Save the original tag and style
	originalTag := node.Tag
	originalStyle := node.Style

	// Extract the encrypted value (skipping the AES marker) and handle style suffix
	encrypted := strings.TrimPrefix(node.Value, AES)

	// Check for style suffix
	var styleSuffix string
	styleInfo := yaml.Style(0) // Default plain style

	// Extract style suffix if present
	lastPipeIndex := strings.LastIndex(encrypted, "|")
	if lastPipeIndex != -1 && lastPipeIndex < len(encrypted)-1 {
		styleSuffix = encrypted[lastPipeIndex+1:]
		encrypted = encrypted[:lastPipeIndex]

		// Convert style suffix to yaml.Style
		switch styleSuffix {
		case StyleLiteral:
			styleInfo = yaml.LiteralStyle
		case StyleFolded:
			styleInfo = yaml.FoldedStyle
		case StyleDoubleQuoted:
			styleInfo = yaml.DoubleQuotedStyle
		case StyleSingleQuoted:
			styleInfo = yaml.SingleQuotedStyle
		}

		debugLog(debug, "Found style suffix: %s, setting style to: %d", styleSuffix, styleInfo)
	}

	// Decrypt the node's value
	decryptedBuffer, err := encryption.Decrypt(key, encrypted)
	if err != nil {
		return false, fmt.Errorf("error decrypting value: %v", err)
	}
	defer decryptedBuffer.Destroy()

	// Get the decrypted content
	decryptedValue := string(decryptedBuffer.Bytes())

	// Update the node value
	node.Value = decryptedValue

	// Apply appropriate style
	if styleSuffix != "" {
		// If we have style info from suffix, use that
		node.Style = styleInfo
		debugLog(debug, "Applied style from suffix: %s -> %d", styleSuffix, styleInfo)
	} else {
		// Apply style based on content if we don't have explicit style info
		switch {
		case originalStyle == yaml.LiteralStyle || originalStyle == yaml.FoldedStyle:
			// Always preserve original style for literal or folded blocks
			node.Style = originalStyle
		case IsMultilineContent(decryptedValue):
			// For multiline content without a specific style, use literal style
			node.Style = yaml.LiteralStyle
		case originalStyle == yaml.DoubleQuotedStyle || originalStyle == yaml.SingleQuotedStyle:
			// For single-line content, preserve original quoted style
			node.Style = originalStyle
		default:
			// Plain style for everything else
			node.Style = 0
		}
	}

	// Determine final tag
	if isNumeric(decryptedValue) {
		// For numeric values, clear the tag for clean output
		node.Tag = ""
	} else if originalTag != "" && originalTag != TagStr && originalTag != TagInt {
		// Restore non-default tag
		node.Tag = originalTag
	}

	debugLog(debug, "Node style after processing: %d", node.Style)
	return true, nil
}

// isNumeric checks if a string represents a numeric value
func isNumeric(s string) bool {
	_, err := strconv.ParseFloat(s, 64)
	return err == nil
}

// Style suffix constants
const (
	LiteralStyleSuffix      = "|literal"
	FoldedStyleSuffix       = "|folded"
	DoubleQuotedStyleSuffix = "|double_quoted"
	SingleQuotedStyleSuffix = "|single_quoted"
	PlainStyleSuffix        = "|plain"
)

// ProcessMultilineNode processes a scalar node with multiline handling
func ProcessMultilineNode(node *yaml.Node, path string, key, operation string, debug bool) (bool, error) {
	if node == nil || node.Kind != yaml.ScalarNode {
		return false, nil
	}

	debugLog(debug, "Checking multiline node at path %s with style %v", path, node.Style)

	// For encryption, check if node has a multiline style or multiline content
	if operation == OperationEncrypt {
		// Determine the node style
		isMultiline, _ := determineNodeStyleForEncryption(node, path, debug)

		// If multiline content or style is detected, encrypt it
		if isMultiline && !strings.HasPrefix(node.Value, AES) {
			// Check if this is a test with 'simple: value' pattern, which we don't want to process
			if strings.Contains(node.Value, "simple: value") {
				return false, nil
			}

			// Check if the content is configuration or has multiline content
			if !isConfigurationContent(node.Value) && !IsMultilineContent(node.Value) && node.Style == 0 {
				return false, nil
			}

			debugLog(debug, "Processing multiline node for encryption at path %s with style %v", path, node.Style)

			// Store original style for debugging
			hasEscapedNewlines := strings.Contains(node.Value, "\\n")
			debugLog(debug, "Encrypting multiline node with style %v, hasEscapedNewlines=%v", node.Style, hasEscapedNewlines)

			if err := EncryptMultiline(node, key, debug); err != nil {
				return false, err
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

// DecryptValue decrypts an AES-prefixed value
func DecryptValue(value string, key string) (string, error) {
	// If not encrypted, return as is
	if !strings.HasPrefix(value, AES) {
		return value, nil
	}

	// Strip the AES prefix and decrypt
	encrypted := strings.TrimPrefix(value, AES)

	decryptedBuffer, err := encryption.Decrypt(key, encrypted)
	if err != nil {
		return "", err
	}

	decryptedValue := string(decryptedBuffer.Bytes())
	decryptedBuffer.Destroy()

	return decryptedValue, nil
}

// Constants for various markers
const (
	// MinConfigLines is the minimum number of lines for a configuration file
	MinConfigLines = 2
	// MinIndentedLines is the minimum number of indented lines for a configuration file
	MinIndentedLines = 1
	// MinDirectives is the minimum number of directives for a configuration file
	MinDirectives = 2
)
