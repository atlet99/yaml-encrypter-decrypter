package tests

import (
	"os"
	"strings"
	"testing"

	"yaml-encrypter-decrypter/pkg/processor"

	"gopkg.in/yaml.v3"
)

func TestProcessFile(t *testing.T) {
	// Create temporary config file
	configContent := `encryption:
  env_blocks:
    - "** if len(value) > 0"`
	err := os.WriteFile(".yed_config.yml", []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create config file: %v", err)
	}
	defer os.Remove(".yed_config.yml")

	tests := []struct {
		name          string
		content       string
		key           string
		operation     string
		dryRun        bool
		debug         bool
		wantError     bool
		errorContains string
	}{
		{
			name:      "encrypt file",
			content:   "password: secret123\napi_key: abc123",
			key:       "test-key-123",
			operation: "encrypt",
			dryRun:    false,
			debug:     false,
			wantError: false,
		},
		{
			name:          "decrypt file",
			content:       "password: AES256:test123\napi_key: AES256:abc123",
			key:           "test-key-123",
			operation:     "decrypt",
			dryRun:        false,
			debug:         false,
			wantError:     true,
			errorContains: "failed to decrypt value",
		},
		{
			name:      "dry run",
			content:   "password: secret123\napi_key: abc123",
			key:       "test-key-123",
			operation: "encrypt",
			dryRun:    true,
			debug:     false,
			wantError: false,
		},
		{
			name:      "debug mode",
			content:   "password: secret123\napi_key: abc123",
			key:       "test-key-123",
			operation: "encrypt",
			dryRun:    false,
			debug:     true,
			wantError: false,
		},
		{
			name:          "invalid operation",
			content:       "password: secret123\napi_key: abc123",
			key:           "test-key-123",
			operation:     "invalid",
			dryRun:        false,
			debug:         false,
			wantError:     true,
			errorContains: "invalid operation",
		},
		{
			name:          "non-existent file",
			content:       "password: secret123\napi_key: abc123",
			key:           "test-key-123",
			operation:     "encrypt",
			dryRun:        false,
			debug:         false,
			wantError:     true,
			errorContains: "no such file or directory",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary test file
			tmpfile, err := os.CreateTemp("", "test-*.yml")
			if err != nil {
				t.Fatalf("Failed to create temp file: %v", err)
			}
			defer os.Remove(tmpfile.Name())

			if _, err := tmpfile.Write([]byte(tt.content)); err != nil {
				t.Fatalf("Failed to write to temp file: %v", err)
			}

			err = processor.ProcessFile(tmpfile.Name(), tt.key, tt.operation, tt.dryRun, tt.debug)
			if tt.wantError {
				if err == nil {
					t.Error("ProcessFile() error = nil, wantError true")
				} else if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("ProcessFile() error = %v, wantError containing %v", err, tt.errorContains)
				}
				return
			}

			if err != nil {
				t.Errorf("ProcessFile() error = %v, wantError false", err)
				return
			}

			// Read the processed file
			processedContent, err := os.ReadFile(tmpfile.Name())
			if err != nil {
				t.Fatalf("Failed to read processed file: %v", err)
			}

			if tt.operation == "encrypt" {
				if !strings.Contains(string(processedContent), "AES256:") {
					t.Error("File content was not encrypted")
				}
				// Check if encrypted content is valid base64
				for _, line := range strings.Split(string(processedContent), "\n") {
					if strings.Contains(line, "AES256:") {
						parts := strings.SplitN(line, ":", 2)
						if len(parts) != 2 {
							continue
						}
						encrypted := strings.TrimSpace(parts[1])
						if !isValidBase64(encrypted) {
							t.Errorf("Encrypted content is not valid base64: %s", encrypted)
						}
					}
				}
			} else if tt.operation == "decrypt" {
				if strings.Contains(string(processedContent), "AES256:") {
					t.Error("File content was not decrypted")
				}
			}
		})
	}
}

func TestEvaluateCondition(t *testing.T) {
	tests := []struct {
		name      string
		key       string
		value     string
		condition string
		want      bool
	}{
		{
			name:      "simple condition",
			key:       "test",
			value:     "test123",
			condition: "len(value) > 5",
			want:      true,
		},
		{
			name:      "contains condition",
			key:       "test",
			value:     "test!123",
			condition: "value contains '!'",
			want:      true,
		},
		{
			name:      "empty condition",
			key:       "test",
			value:     "test123",
			condition: "",
			want:      true,
		},
		{
			name:      "complex condition",
			key:       "test",
			value:     "test!123",
			condition: "len(value) >= 8 && value contains '!'",
			want:      true,
		},
		{
			name:      "invalid condition",
			key:       "test",
			value:     "test123",
			condition: "invalid syntax",
			want:      false,
		},
		{
			name:      "false condition",
			key:       "test",
			value:     "test",
			condition: "len(value) > 10",
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := processor.EvaluateCondition(tt.key, tt.value, tt.condition)
			if got != tt.want {
				t.Errorf("EvaluateCondition() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProcessNode(t *testing.T) {
	tests := []struct {
		name          string
		node          *yaml.Node
		path          string
		key           string
		operation     string
		wantError     bool
		errorContains string
	}{
		{
			name: "process scalar node",
			node: &yaml.Node{
				Kind:  yaml.ScalarNode,
				Value: "test-value",
			},
			path:      "test.path",
			key:       "test-key-123",
			operation: "encrypt",
			wantError: false,
		},
		{
			name: "process sequence node",
			node: &yaml.Node{
				Kind: yaml.SequenceNode,
				Content: []*yaml.Node{
					{Kind: yaml.ScalarNode, Value: "value1"},
					{Kind: yaml.ScalarNode, Value: "value2"},
				},
			},
			path:      "test.path",
			key:       "test-key-123",
			operation: "encrypt",
			wantError: false,
		},
		{
			name: "process mapping node",
			node: &yaml.Node{
				Kind: yaml.MappingNode,
				Content: []*yaml.Node{
					{Kind: yaml.ScalarNode, Value: "key1"},
					{Kind: yaml.ScalarNode, Value: "value1"},
				},
			},
			path:      "test.path",
			key:       "test-key-123",
			operation: "encrypt",
			wantError: false,
		},
		{
			name: "invalid operation",
			node: &yaml.Node{
				Kind:  yaml.ScalarNode,
				Value: "test-value",
			},
			path:          "test.path",
			key:           "test-key-123",
			operation:     "invalid",
			wantError:     true,
			errorContains: "invalid operation",
		},
		{
			name:          "nil node",
			node:          nil,
			path:          "test.path",
			key:           "test-key-123",
			operation:     "encrypt",
			wantError:     true,
			errorContains: "node is nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a copy of the node for testing
			var nodeCopy *yaml.Node
			if tt.node != nil {
				nodeCopy = &yaml.Node{
					Kind:  tt.node.Kind,
					Value: tt.node.Value,
				}
				if tt.node.Content != nil {
					nodeCopy.Content = make([]*yaml.Node, len(tt.node.Content))
					for i, child := range tt.node.Content {
						nodeCopy.Content[i] = &yaml.Node{
							Kind:  child.Kind,
							Value: child.Value,
						}
					}
				}
			}

			err := processor.ProcessNode(nodeCopy, tt.path, tt.key, tt.operation)
			if tt.wantError {
				if err == nil {
					t.Error("ProcessNode() error = nil, wantError true")
				} else if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error to contain '%s', got '%v'", tt.errorContains, err)
				}
				return
			}

			if err != nil {
				t.Errorf("ProcessNode() error = %v, wantError false", err)
				return
			}

			if nodeCopy != nil {
				// For encryption, verify the value is encrypted
				if tt.operation == "encrypt" {
					if nodeCopy.Kind == yaml.ScalarNode {
						if !strings.HasPrefix(nodeCopy.Value, "AES256:") {
							t.Error("Node value was not encrypted")
						}
						encrypted := strings.TrimSpace(strings.TrimPrefix(nodeCopy.Value, "AES256:"))
						if !isValidBase64(encrypted) {
							t.Errorf("Encrypted value is not valid base64: %s", encrypted)
						}
					} else if nodeCopy.Kind == yaml.SequenceNode {
						for _, child := range nodeCopy.Content {
							if !strings.HasPrefix(child.Value, "AES256:") {
								t.Error("Sequence value was not encrypted")
							}
							encrypted := strings.TrimSpace(strings.TrimPrefix(child.Value, "AES256:"))
							if !isValidBase64(encrypted) {
								t.Errorf("Encrypted sequence value is not valid base64: %s", encrypted)
							}
						}
					}
				}

				// For decryption, verify the value matches original
				if tt.operation == "decrypt" {
					if nodeCopy.Kind == yaml.ScalarNode {
						if strings.HasPrefix(nodeCopy.Value, "AES256:") {
							t.Error("Node value was not decrypted")
						}
					}
				}
			}
		})
	}
}

// Helper function to check if a string is valid base64
func isValidBase64(s string) bool {
	// Remove any whitespace
	s = strings.TrimSpace(s)
	// Check if the string is empty
	if s == "" {
		return false
	}
	// Check if the string contains only base64 characters
	for _, c := range s {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=') {
			return false
		}
	}
	// Check if the string length is a multiple of 4
	if len(s)%4 != 0 {
		return false
	}
	return true
}
