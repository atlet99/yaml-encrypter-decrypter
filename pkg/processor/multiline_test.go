package processor

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

func TestDetectMultilineStyle(t *testing.T) {
	tests := []struct {
		name     string
		node     *yaml.Node
		expected MultilineStyle
	}{
		{
			name: "literal style",
			node: &yaml.Node{
				Kind:  yaml.ScalarNode,
				Style: yaml.LiteralStyle,
			},
			expected: LiteralStyle,
		},
		{
			name: "folded style",
			node: &yaml.Node{
				Kind:  yaml.ScalarNode,
				Style: yaml.FoldedStyle,
			},
			expected: FoldedStyle,
		},
		{
			name: "plain style",
			node: &yaml.Node{
				Kind:  yaml.ScalarNode,
				Style: 0,
			},
			expected: NotMultiline,
		},
		{
			name:     "nil node",
			node:     nil,
			expected: NotMultiline,
		},
		{
			name: "non-scalar node",
			node: &yaml.Node{
				Kind: yaml.MappingNode,
			},
			expected: NotMultiline,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DetectMultilineStyle(tt.node)
			if result != tt.expected {
				t.Errorf("DetectMultilineStyle() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestEncryptDecryptMultiline(t *testing.T) {
	// Test data
	testKey := "test-key-12345678901234567890"
	originalStyle := yaml.LiteralStyle
	originalText := "Line 1\nLine 2\nLine 3"

	// === Test direct encryption and decryption ===

	// Create test node for direct encrypt/decrypt test
	node := &yaml.Node{
		Kind:  yaml.ScalarNode,
		Style: originalStyle,
		Value: originalText,
	}

	// Test encryption
	err := EncryptMultiline(node, testKey, false)
	if err != nil {
		t.Fatalf("EncryptMultiline() error = %v", err)
	}

	// Verify encryption
	if !strings.HasPrefix(node.Value, AES) {
		t.Errorf("Encrypted value should start with %s", AES)
	}
	if node.Style != 0 {
		t.Errorf("Style after encryption should be 0 (plain), got %v", node.Style)
	}

	// Test decryption
	err = DecryptMultiline(node, testKey, originalStyle, false)
	if err != nil {
		t.Fatalf("DecryptMultiline() error = %v", err)
	}

	// Verify decryption
	if node.Value != originalText {
		t.Errorf("Decrypted value = %s, want %s", node.Value, originalText)
	}
	if node.Style != originalStyle {
		t.Errorf("Style after decryption = %v, want %v", node.Style, originalStyle)
	}

	// === Test ProcessMultilineNode separately for encryption and decryption ===

	// Create new test nodes for process test
	encNode := &yaml.Node{
		Kind:  yaml.ScalarNode,
		Style: originalStyle,
		Value: originalText,
	}

	// Test ProcessMultilineNode for encryption
	processed, err := ProcessMultilineNode(encNode, "test.path", testKey, OperationEncrypt, false)
	if err != nil {
		t.Fatalf("ProcessMultilineNode(encrypt) error = %v", err)
	}
	if !processed {
		t.Errorf("ProcessMultilineNode(encrypt) = false, want true")
	}
	if !strings.HasPrefix(encNode.Value, AES) {
		t.Errorf("Encrypted value should start with %s", AES)
	}

	// Save encrypted value for decryption test
	encryptedValue := encNode.Value

	// Create a new node for decryption to avoid any state issues
	decNode := &yaml.Node{
		Kind:  yaml.ScalarNode,
		Style: 0, // Plain style, as it would be after encryption
		Value: encryptedValue,
	}

	// Test ProcessMultilineNode for decryption
	processed, err = ProcessMultilineNode(decNode, "test.path", testKey, OperationDecrypt, false)
	if err != nil {
		t.Fatalf("ProcessMultilineNode(decrypt) error = %v", err)
	}
	if !processed {
		t.Errorf("ProcessMultilineNode(decrypt) = false, want true")
	}
	if decNode.Value != originalText {
		t.Errorf("Decrypted value = %s, want %s", decNode.Value, originalText)
	}
}

func TestIsMultilineContent(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected bool
	}{
		{
			name:     "multiline content",
			content:  "Line 1\nLine 2\nLine 3",
			expected: true,
		},
		{
			name:     "single line content",
			content:  "Line 1",
			expected: false,
		},
		{
			name:     "empty content",
			content:  "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsMultilineContent(tt.content)
			if result != tt.expected {
				t.Errorf("IsMultilineContent() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestDecryptMultilinePreservesPEMFormat(t *testing.T) {
	// Simulating a PEM key with escaped newlines (as it would appear in YAML)
	pemWithEscapedNewlines := "-----BEGIN RSA PRIVATE KEY-----\\nMIIEogIB...\\nAaAaAa==\\n-----END RSA PRIVATE KEY-----"

	// Create a node with this value
	node := &yaml.Node{
		Kind:  yaml.ScalarNode,
		Style: yaml.DoubleQuotedStyle,
		Value: pemWithEscapedNewlines,
	}

	// Encrypt the node
	err := EncryptMultiline(node, "testkey", true)
	assert.NoError(t, err)
	assert.True(t, strings.HasPrefix(node.Value, AES))

	// Save the original style
	originalStyle := node.Style

	// Decrypt the node
	err = DecryptMultiline(node, "testkey", originalStyle, true)
	assert.NoError(t, err)

	// Check that the format is preserved
	assert.Equal(t, pemWithEscapedNewlines, node.Value)
	assert.Equal(t, yaml.DoubleQuotedStyle, node.Style)
}
