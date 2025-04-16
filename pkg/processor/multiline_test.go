package processor

import (
	"strings"
	"testing"

	"github.com/atlet99/yaml-encrypter-decrypter/pkg/encryption"
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
	originalText := `server {
  listen 80;
  server_name localhost;
  location / {
    root /usr/share/nginx/html;
    index index.html;
  }
}`

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
	err = DecryptMultiline(node, func(value string) (string, error) {
		// Decrypt the value
		decryptedBuffer, err := encryption.Decrypt(testKey, strings.TrimPrefix(value, AES))
		if err != nil {
			return "", err
		}
		defer decryptedBuffer.Destroy() // Clean up the protected buffer

		// Return the decrypted value
		return string(decryptedBuffer.Bytes()), nil
	})
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
	// Create a test node with PEM content
	node := &yaml.Node{
		Kind:  yaml.ScalarNode,
		Style: yaml.DoubleQuotedStyle,
		Value: "-----BEGIN RSA PRIVATE KEY-----\\nMIIEogIB...\\nAaAaAa==\\n-----END RSA PRIVATE KEY-----",
	}

	// Use a secure key for testing
	testKey := "test-key-12345678901234567890"

	// Save the original value for verification
	originalValue := node.Value

	// Encrypt the value
	err := EncryptMultiline(node, testKey, false)
	assert.NoError(t, err)

	// Check that the value was encrypted
	assert.True(t, strings.HasPrefix(node.Value, AES))
	assert.Contains(t, node.Value, DoubleQuotedStyleSuffix) // Check that the style was preserved in the suffix

	// Decrypt the value
	err = DecryptMultiline(node, func(value string) (string, error) {
		// Use only the encrypted part without the AES prefix
		encrypted := strings.TrimPrefix(value, AES)
		// Find and remove the style suffix
		lastPipeIndex := strings.LastIndex(encrypted, "|")
		if lastPipeIndex != -1 {
			encrypted = encrypted[:lastPipeIndex]
		}

		// Decrypt the value
		decryptedBuffer, err := encryption.Decrypt(testKey, encrypted)
		if err != nil {
			return "", err
		}
		defer decryptedBuffer.Destroy()

		return string(decryptedBuffer.Bytes()), nil
	})
	assert.NoError(t, err)

	// Check that the value and style were restored
	assert.Equal(t, originalValue, node.Value)
	assert.Equal(t, yaml.DoubleQuotedStyle, node.Style)
}

func TestHasCertificateKeyPatterns(t *testing.T) {
	// Skip this test as the hasCertificateKeyPatterns function has been removed
	t.Skip("Test skipped: hasCertificateKeyPatterns function has been removed")
}

func TestDecryptCertificatesPreservesFormat(t *testing.T) {
	testCases := []struct {
		name      string
		content   string
		nodeStyle yaml.Style
	}{
		{
			name:      "content with escaped newlines",
			content:   "line1\\nline2\\nline3",
			nodeStyle: yaml.DoubleQuotedStyle,
		},
		{
			name:      "multiline quoted content",
			content:   "first line\\nsecond line\\nthird line",
			nodeStyle: yaml.DoubleQuotedStyle,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a node with the test value
			node := &yaml.Node{
				Kind:  yaml.ScalarNode,
				Style: tc.nodeStyle,
				Value: tc.content,
			}

			// Save the original value
			originalValue := node.Value

			// Use a secure key for testing
			testKey := "test-key-12345678901234567890"

			// Encrypt the value
			err := EncryptMultiline(node, testKey, false)
			assert.NoError(t, err)

			// Check that the value was encrypted
			assert.True(t, strings.HasPrefix(node.Value, AES))

			// Check for the style suffix based on the original style
			switch tc.nodeStyle {
			case yaml.DoubleQuotedStyle:
				assert.Contains(t, node.Value, DoubleQuotedStyleSuffix)
			case yaml.SingleQuotedStyle:
				assert.Contains(t, node.Value, SingleQuotedStyleSuffix)
			case yaml.LiteralStyle:
				assert.Contains(t, node.Value, LiteralStyleSuffix)
			case yaml.FoldedStyle:
				assert.Contains(t, node.Value, FoldedStyleSuffix)
			}

			// Decrypt the value
			err = DecryptMultiline(node, func(value string) (string, error) {
				// Use only the encrypted part without the AES prefix
				encrypted := strings.TrimPrefix(value, AES)
				// Find and remove the style suffix
				lastPipeIndex := strings.LastIndex(encrypted, "|")
				if lastPipeIndex != -1 {
					encrypted = encrypted[:lastPipeIndex]
				}

				// Decrypt the value
				decryptedBuffer, err := encryption.Decrypt(testKey, encrypted)
				if err != nil {
					return "", err
				}
				defer decryptedBuffer.Destroy()

				return string(decryptedBuffer.Bytes()), nil
			})
			assert.NoError(t, err)

			// Check that the value and style were restored
			assert.Equal(t, originalValue, node.Value)
			assert.Equal(t, tc.nodeStyle, node.Style)
		})
	}
}

func TestProcessConfigFileContent(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected string
	}{
		{
			name: "nginx_config",
			content: `data: |-
  user nginx;
  worker_processes auto;
  events { worker_connections 1024; }
  http {
    server {
      listen 80;
      server_name localhost;
      location / {
        root /usr/share/nginx/html;
        index index.html index.htm;
      }
    }
  }`,
			expected: `data: |-
    user nginx;
    worker_processes auto;
    events { worker_connections 1024; }
    http {
      server {
        listen 80;
        server_name localhost;
        location / {
          root /usr/share/nginx/html;
          index index.html index.htm;
        }
      }
    }`,
		},
		{
			name: "apache_config",
			content: `config: |-
  <VirtualHost *:80>
    ServerAdmin webmaster@localhost
    DocumentRoot /var/www/html
    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined
  </VirtualHost>`,
			expected: `config: |-
    <VirtualHost *:80>
      ServerAdmin webmaster@localhost
      DocumentRoot /var/www/html
      ErrorLog ${APACHE_LOG_DIR}/error.log
      CustomLog ${APACHE_LOG_DIR}/access.log combined
    </VirtualHost>`,
		},
		{
			name: "nginx_config_with_sensitive_data",
			content: `data: |-
  user nginx;
  worker_processes auto;
  events { worker_connections 1024; }
  http {
    server {
      listen 443 ssl;
      server_name example.com;
      ssl_certificate /etc/nginx/ssl/server.crt;
      ssl_certificate_key /etc/nginx/ssl/server.key;
      ssl_password "!@#sensitive_password123";
      location / {
        proxy_pass http://backend;
        proxy_set_header Authorization "Bearer secret_token_123";
      }
    }
  }`,
			expected: `data: |-
    user nginx;
    worker_processes auto;
    events { worker_connections 1024; }
    http {
      server {
        listen 443 ssl;
        server_name example.com;
        ssl_certificate /etc/nginx/ssl/server.crt;
        ssl_certificate_key /etc/nginx/ssl/server.key;
        ssl_password "!@#sensitive_password123";
        location / {
          proxy_pass http://backend;
          proxy_set_header Authorization "Bearer secret_token_123";
        }
      }
    }`,
		},
		{
			name: "kubernetes_config_with_sensitive_data",
			content: `config: |-
  apiVersion: v1
  kind: Secret
  metadata:
    name: app-secrets
  type: Opaque
  data:
    DB_PASSWORD: "sensitive_db_password_123"
    API_KEY: "very_secret_api_key_456"
    JWT_SECRET: "super_secret_jwt_789"
  ---
  apiVersion: apps/v1
  kind: Deployment
  metadata:
    name: app
  spec:
    template:
      spec:
        containers:
        - name: app
          env:
          - name: DATABASE_URL
            value: "postgresql://user:password@db:5432/app"`,
			expected: `config: |-
    apiVersion: v1
    kind: Secret
    metadata:
      name: app-secrets
    type: Opaque
    data:
      DB_PASSWORD: "sensitive_db_password_123"
      API_KEY: "very_secret_api_key_456"
      JWT_SECRET: "super_secret_jwt_789"
    ---
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: app
    spec:
      template:
        spec:
          containers:
          - name: app
            env:
            - name: DATABASE_URL
              value: "postgresql://user:password@db:5432/app"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var data map[string]interface{}
			err := yaml.Unmarshal([]byte(tt.content), &data)
			if err != nil {
				t.Fatalf("Failed to unmarshal test content: %v", err)
			}

			// Convert data to YAML bytes
			yamlBytes, err := yaml.Marshal(data)
			if err != nil {
				t.Fatalf("Failed to marshal test content: %v", err)
			}

			// Process the content
			processedPaths := make(map[string]bool)
			rules := []Rule{
				{
					Name:        "nginx_config",
					Block:       "nginx",
					Pattern:     "**",
					Description: "Encrypt nginx configuration blocks",
				},
			}
			_, err = ProcessYAMLContent(yamlBytes, "test-key", "encrypt", rules, processedPaths, false)
			if err != nil {
				t.Fatalf("Failed to process content: %v", err)
			}

			// Marshal back to YAML
			output, err := yaml.Marshal(data)
			if err != nil {
				t.Fatalf("Failed to marshal processed content: %v", err)
			}

			// Compare with expected, ignoring indentation differences
			normalizedOutput := normalizeString(string(output))
			normalizedExpected := normalizeString(tt.expected)
			if normalizedOutput != normalizedExpected {
				t.Errorf("Expected:\n%s\nGot:\n%s", tt.expected, string(output))
			}
		})
	}
}

// normalizeString removes all whitespace to compare YAML content regardless of indentation
func normalizeString(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, " ", ""), "\n", "")
}

func TestIsConfigurationContent(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected bool
	}{
		{
			name: "nginx config",
			content: `user nginx;
worker_processes auto;
events { worker_connections 1024; }
http {
  server {
    listen 80;
    server_name localhost;
    location / {
      root /usr/share/nginx/html;
      index index.html index.htm;
    }
  }
}`,
			expected: true,
		},
		{
			name: "apache config",
			content: `<VirtualHost *:80>
  ServerAdmin webmaster@localhost
  DocumentRoot /var/www/html
  ErrorLog ${APACHE_LOG_DIR}/error.log
  CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>`,
			expected: true,
		},
		{
			name: "simple key-value pairs",
			content: `key1: value1
key2: value2`,
			expected: false,
		},
		{
			name: "multiline text",
			content: `This is a multiline
text that should not be
detected as configuration`,
			expected: false,
		},
		{
			name:     "empty content",
			content:  "",
			expected: false,
		},
		{
			name: "haproxy config",
			content: `frontend http
  bind *:80
  default_backend web_backend

backend web_backend
  server web1 10.0.0.1:80 check
  server web2 10.0.0.2:80 check`,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isConfigurationContent(tt.content)
			if result != tt.expected {
				t.Errorf("isConfigurationContent() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestProcessConfigurationNode(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		operation   string
		wantStyle   yaml.Style
		wantEncrypt bool
	}{
		{
			name: "nginx config encrypt",
			content: `user nginx;
worker_processes auto;
events { worker_connections 1024; }`,
			operation:   OperationEncrypt,
			wantStyle:   yaml.LiteralStyle,
			wantEncrypt: true,
		},
		{
			name: "apache config encrypt",
			content: `<VirtualHost *:80>
  ServerAdmin webmaster@localhost
  DocumentRoot /var/www/html
</VirtualHost>`,
			operation:   OperationEncrypt,
			wantStyle:   yaml.LiteralStyle,
			wantEncrypt: true,
		},
		{
			name: "non-config content",
			content: `simple: value
another: value`,
			operation:   OperationEncrypt,
			wantStyle:   0,
			wantEncrypt: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a node with the test content
			node := &yaml.Node{
				Kind:  yaml.ScalarNode,
				Value: tt.content,
			}

			// Process the node
			testKey := "test-key-12345678901234567890"
			processed, err := ProcessMultilineNode(node, "test.path", testKey, tt.operation, false)
			if err != nil {
				t.Fatalf("ProcessMultilineNode() error = %v", err)
			}

			// Check if the node was processed as expected
			if processed != tt.wantEncrypt {
				t.Errorf("ProcessMultilineNode() processed = %v, want %v", processed, tt.wantEncrypt)
			}

			// If we expect encryption and the content is configuration
			if tt.wantEncrypt && isConfigurationContent(tt.content) {
				// Check if the content was actually encrypted
				if !strings.HasPrefix(node.Value, AES) {
					t.Error("Content was not encrypted when it should have been")
				}

				// Decrypt and verify the content
				decryptFn := func(value string) (string, error) {
					buffer, err := encryption.Decrypt(testKey, strings.TrimPrefix(value, AES))
					if err != nil {
						return "", err
					}
					defer buffer.Destroy()
					return string(buffer.Bytes()), nil
				}

				// Decrypt the node
				if err := DecryptMultiline(node, decryptFn); err != nil {
					t.Fatalf("Failed to decrypt: %v", err)
				}

				// Check if the decrypted content matches the original
				if node.Value != tt.content {
					t.Errorf("Decrypted content does not match original:\nGot:\n%s\nWant:\n%s", node.Value, tt.content)
				}

				// Check if the style was preserved
				if node.Style != tt.wantStyle {
					t.Errorf("Node style = %v, want %v", node.Style, tt.wantStyle)
				}
			}
		})
	}
}
