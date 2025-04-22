package processor

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestCertificateFormatting is a comprehensive test for certificate handling
// with different YAML formatting styles
func TestCertificateFormatting(t *testing.T) {
	// Test key for encryption/decryption
	testKey := "test-certificate-key-12345678"

	// Sample certificate content
	sampleCert := `-----BEGIN CERTIFICATE-----
MIIDzTCCArWgAwIBAgIUJ2y8WMUzuLbLNJ5nrY6BQUuC9lAwDQYJKoZIhvcNAQEL
BQAwdjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCldhc2hpbmd0b24xEDAOBgNVBAcM
B1NlYXR0bGUxDzANBgNVBAoMBkFtYXpvbjEUMBIGA1UECwwLSUFNIENvbnNvbGUx
GTAXBgNVBAMMEHd3dy5leGFtcGxlLmNvbQ==
-----END CERTIFICATE-----`

	// Same certificate with escaped newlines for double-quoted style
	escapedCert := strings.ReplaceAll(sampleCert, "\n", "\\n")

	// Create a YAML node tree with different certificate formatting styles
	yamlData := map[string]interface{}{
		"certificates": map[string]interface{}{
			"literal_style": sampleCert,
			"quoted_style":  escapedCert,
			"nested": map[string]interface{}{
				"another_cert": sampleCert,
			},
		},
	}

	// Convert to YAML
	yamlBytes, err := yaml.Marshal(yamlData)
	if err != nil {
		t.Fatalf("Failed to marshal test data: %v", err)
	}

	// Parse YAML to get node tree for setting styles
	var root yaml.Node
	err = yaml.Unmarshal(yamlBytes, &root)
	if err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	// Apply different styles to certificate nodes
	// Navigate to the certificates mapping
	certsNode := root.Content[0].Content[1] // root -> document -> mapping -> "certificates" -> mapping

	// Find and set styles for certificate nodes
	for i := 0; i < len(certsNode.Content); i += 2 {
		keyNode := certsNode.Content[i]
		valueNode := certsNode.Content[i+1]

		if keyNode.Value == "literal_style" {
			valueNode.Style = yaml.LiteralStyle // |
		} else if keyNode.Value == "quoted_style" {
			valueNode.Style = yaml.DoubleQuotedStyle // "..."
		} else if keyNode.Value == "nested" {
			// Find the nested cert
			nestedMapping := valueNode
			for j := 0; j < len(nestedMapping.Content); j += 2 {
				if nestedMapping.Content[j].Value == "another_cert" {
					nestedMapping.Content[j+1].Style = yaml.FoldedStyle // >
				}
			}
		}
	}

	// Convert back to YAML bytes with styles
	styledBytes, err := yaml.Marshal(&root)
	if err != nil {
		t.Fatalf("Failed to marshal styled data: %v", err)
	}

	// Print the original YAML for debug
	t.Logf("Original YAML:\n%s", string(styledBytes))

	// Encrypt the content
	rules := []Rule{
		{
			Name:        "certs-rule",
			Block:       "certificates",
			Pattern:     "**",
			Description: "Encrypt all certificates",
		},
	}
	processedPaths := make(map[string]bool)
	debug := true

	// Encrypt
	encryptedNode, err := ProcessYAMLContent(styledBytes, testKey, OperationEncrypt, rules, processedPaths, debug)
	if err != nil {
		t.Fatalf("Error in encryption: %v", err)
	}

	// Get the encrypted YAML
	encryptedBytes, err := yaml.Marshal(encryptedNode)
	if err != nil {
		t.Fatalf("Failed to marshal encrypted data: %v", err)
	}

	t.Logf("Encrypted YAML:\n%s", string(encryptedBytes))

	// Now decrypt the content
	decryptedNode, err := ProcessYAMLContent(encryptedBytes, testKey, OperationDecrypt, rules, make(map[string]bool), debug)
	if err != nil {
		t.Fatalf("Error in decryption: %v", err)
	}

	// Get the decrypted YAML
	decryptedBytes, err := yaml.Marshal(decryptedNode)
	if err != nil {
		t.Fatalf("Failed to marshal decrypted data: %v", err)
	}

	t.Logf("Decrypted YAML:\n%s", string(decryptedBytes))

	// Compare original and decrypted bytes (ignoring whitespace differences)
	// We need to normalize both to compare them properly
	normalizedOriginal := normalizeYAML(string(styledBytes))
	normalizedDecrypted := normalizeYAML(string(decryptedBytes))

	if normalizedOriginal != normalizedDecrypted {
		t.Errorf("Decrypted content does not match original after formatting normalization")
		t.Logf("Original normalized:\n%s", normalizedOriginal)
		t.Logf("Decrypted normalized:\n%s", normalizedDecrypted)
	}

	// Also check if the styles were preserved
	var originalRoot yaml.Node
	var decryptedRoot yaml.Node

	err = yaml.Unmarshal(styledBytes, &originalRoot)
	if err != nil {
		t.Fatalf("Failed to unmarshal original for style check: %v", err)
	}

	err = yaml.Unmarshal(decryptedBytes, &decryptedRoot)
	if err != nil {
		t.Fatalf("Failed to unmarshal decrypted for style check: %v", err)
	}

	// Verify styles
	verifyNodeStyles(t, &originalRoot, &decryptedRoot)
}

// normalizeYAML normalizes YAML content for comparison
func normalizeYAML(content string) string {
	// Remove all whitespace for comparison
	return strings.Join(strings.Fields(content), "")
}

// verifyNodeStyles recursively checks if the styles of two node trees match
func verifyNodeStyles(t *testing.T, original, decrypted *yaml.Node) {
	if original == nil || decrypted == nil {
		return
	}

	// Check scalar node styles
	if original.Kind == yaml.ScalarNode && decrypted.Kind == yaml.ScalarNode {
		if original.Style != decrypted.Style {
			t.Errorf("Style mismatch for node '%s'. Original: %d, Decrypted: %d",
				original.Value, original.Style, decrypted.Style)
		}
	}

	// Skip if content lengths don't match (shouldn't happen in our case)
	minLen := len(original.Content)
	if len(decrypted.Content) < minLen {
		minLen = len(decrypted.Content)
	}

	// Recursively check all child nodes
	for i := 0; i < minLen; i++ {
		verifyNodeStyles(t, original.Content[i], decrypted.Content[i])
	}
}
