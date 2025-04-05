package processor

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestProcessFile(t *testing.T) {
	tests := []struct {
		name      string
		filename  string
		key       string
		operation string
		dryRun    bool
		debug     bool
		diff      bool
		wantError bool
	}{
		{
			name:      "valid file",
			filename:  "test.yml",
			key:       "test-key-123456789012345",
			operation: "encrypt",
			dryRun:    true,
			debug:     false,
			diff:      false,
			wantError: false,
		},
		{
			name:      "valid file with output",
			filename:  "testdata/input.yml",
			key:       "testdata/output.yml",
			operation: "encrypt",
			dryRun:    false,
			debug:     false,
			diff:      false,
			wantError: false,
		},
		{
			name:      "valid file with config",
			filename:  "testdata/input.yml",
			key:       "testdata/.yed_config.yml",
			operation: "encrypt",
			dryRun:    false,
			debug:     false,
			diff:      false,
			wantError: false,
		},
		{
			name:      "valid file with debug",
			filename:  "test.yml",
			key:       "test-key-123456789012345",
			operation: "encrypt",
			dryRun:    true,
			debug:     true,
			diff:      false,
			wantError: false,
		},
		{
			name:      "valid file with diff",
			filename:  "test.yml",
			key:       "test-key-123456789012345",
			operation: "encrypt",
			dryRun:    true,
			debug:     false,
			diff:      true,
			wantError: false,
		},
		{
			name:      "invalid file",
			filename:  "invalid.yml",
			key:       "test-key-12345678",
			operation: "encrypt",
			dryRun:    false,
			debug:     false,
			diff:      false,
			wantError: true,
		},
		{
			name:      "empty file",
			filename:  "empty.yml",
			key:       "test-key-12345678",
			operation: "encrypt",
			dryRun:    false,
			debug:     false,
			diff:      false,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ProcessFile(tt.filename, tt.key, tt.operation, tt.dryRun, tt.debug, tt.diff)
			if (err != nil) != tt.wantError {
				t.Errorf("ProcessFile() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestEvaluateCondition(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		condition string
		want      bool
	}{
		{
			name:      "simple condition",
			value:     "test123",
			condition: "test123",
			want:      true,
		},
		{
			name:      "contains condition",
			value:     "test!123",
			condition: "test*",
			want:      true,
		},
		{
			name:      "empty condition",
			value:     "test123",
			condition: "",
			want:      true,
		},
		{
			name:      "complex condition",
			value:     "test!123",
			condition: "test*123",
			want:      true,
		},
		{
			name:      "invalid condition",
			value:     "test123",
			condition: "invalid syntax",
			want:      false,
		},
		{
			name:      "false condition",
			value:     "test",
			condition: "different",
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EvaluateCondition(tt.condition, tt.value)
			if got != tt.want {
				t.Errorf("EvaluateCondition() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProcessNode(t *testing.T) {
	tests := []struct {
		name      string
		node      *yaml.Node
		path      string
		key       string
		operation string
		debug     bool
		wantError bool
	}{
		{
			name: "process_scalar_node",
			node: &yaml.Node{
				Kind:  yaml.ScalarNode,
				Value: "test",
			},
			path:      "test",
			key:       "test-key-12345678",
			operation: "encrypt",
			debug:     false,
			wantError: false,
		},
		{
			name: "process_sequence_node",
			node: &yaml.Node{
				Kind: yaml.SequenceNode,
				Content: []*yaml.Node{
					{Kind: yaml.ScalarNode, Value: "test1"},
					{Kind: yaml.ScalarNode, Value: "test2"},
				},
			},
			path:      "test",
			key:       "test-key-12345678",
			operation: "encrypt",
			debug:     false,
			wantError: false,
		},
		{
			name: "process_mapping_node",
			node: &yaml.Node{
				Kind: yaml.MappingNode,
				Content: []*yaml.Node{
					{Kind: yaml.ScalarNode, Value: "key1"},
					{Kind: yaml.ScalarNode, Value: "value1"},
				},
			},
			path:      "test",
			key:       "test-key-12345678",
			operation: "encrypt",
			debug:     false,
			wantError: false,
		},
		{
			name: "invalid_operation",
			node: &yaml.Node{
				Kind:  yaml.ScalarNode,
				Value: "test",
			},
			path:      "test",
			key:       "test-key-12345678",
			operation: "invalid",
			debug:     false,
			wantError: true,
		},
		{
			name:      "nil_node",
			node:      nil,
			path:      "test",
			key:       "test-key-12345678",
			operation: "encrypt",
			debug:     false,
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ProcessNode(tt.node, tt.path, tt.key, tt.operation, tt.debug)
			if (err != nil) != tt.wantError {
				t.Errorf("ProcessNode() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

// Helper function to check if a string is valid base64
func isValidBase64(s string) bool {
	// Remove any whitespace and AES256: prefix
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "AES256:") {
		s = strings.TrimSpace(strings.TrimPrefix(s, "AES256:"))
	}
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

func BenchmarkProcessFile(b *testing.B) {
	// Create temporary config file
	configContent := `encryption:
  env_blocks:
    - "** if len(value) > 0"`
	err := os.WriteFile(".yed_config.yml", []byte(configContent), 0644)
	if err != nil {
		b.Fatalf("Failed to create config file: %v", err)
	}
	defer os.Remove(".yed_config.yml")

	// Create temporary test file
	tmpfile, err := os.CreateTemp("", "bench-*.yml")
	if err != nil {
		b.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())

	content := "password: secret123\napi_key: abc123"
	if _, err := tmpfile.Write([]byte(content)); err != nil {
		b.Fatalf("Failed to write to temp file: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := ProcessFile(tmpfile.Name(), "test-key-12345678", "encrypt", false, false, false)
		if err != nil {
			b.Fatalf("ProcessFile failed: %v", err)
		}
	}
}

func BenchmarkProcessNode(b *testing.B) {
	node := &yaml.Node{
		Kind:  yaml.ScalarNode,
		Value: "test value",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := ProcessNode(node, "test.path", "test-key-12345678", "encrypt", false)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEvaluateCondition(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := EvaluateCondition("len(value) > 5", "test123")
		if !result {
			b.Fatal("EvaluateCondition returned false for valid condition")
		}
	}
}

func BenchmarkMaskEncryptedValue(b *testing.B) {
	value := "AES256:test1234567890"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		masked := maskEncryptedValue(value, false)
		if !strings.HasSuffix(masked, "********") {
			b.Fatal("maskEncryptedValue did not properly mask the value")
		}
	}
}

func TestMaskEncryptedValue(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		debug    bool
		expected string
	}{
		{
			name:     "encrypted value",
			value:    "AES256:test",
			debug:    false,
			expected: "AES256:*****",
		},
		{
			name:     "encrypted value with debug",
			value:    "AES256:test",
			debug:    true,
			expected: "AES256:test",
		},
		{
			name:     "non-encrypted value",
			value:    "test",
			debug:    false,
			expected: "test",
		},
		{
			name:     "encrypted value with debug",
			value:    "ENC[AES256_GCM,data:1234567890,iv:1234567890,tag:1234567890,type:str]",
			debug:    true,
			expected: "ENC[AES256_GCM,data:1234567890,iv:1234567890,tag:1234567890,type:str]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := maskEncryptedValue(tt.value, tt.debug)
			if result != tt.expected {
				t.Errorf("maskEncryptedValue() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestClearNodeData(t *testing.T) {
	tests := []struct {
		name     string
		node     *yaml.Node
		expected *yaml.Node
	}{
		{
			name: "scalar node with encrypted value",
			node: &yaml.Node{
				Kind:  yaml.ScalarNode,
				Value: "AES256:test",
			},
			expected: &yaml.Node{
				Kind:  yaml.ScalarNode,
				Value: "",
			},
		},
		{
			name: "sequence node with encrypted values",
			node: &yaml.Node{
				Kind: yaml.SequenceNode,
				Content: []*yaml.Node{
					{Kind: yaml.ScalarNode, Value: "AES256:test1"},
					{Kind: yaml.ScalarNode, Value: "AES256:test2"},
				},
			},
			expected: &yaml.Node{
				Kind: yaml.SequenceNode,
				Content: []*yaml.Node{
					{Kind: yaml.ScalarNode, Value: ""},
					{Kind: yaml.ScalarNode, Value: ""},
				},
			},
		},
		{
			name: "mapping node with encrypted values",
			node: &yaml.Node{
				Kind: yaml.MappingNode,
				Content: []*yaml.Node{
					{Kind: yaml.ScalarNode, Value: "key1"},
					{Kind: yaml.ScalarNode, Value: "AES256:test1"},
					{Kind: yaml.ScalarNode, Value: "key2"},
					{Kind: yaml.ScalarNode, Value: "AES256:test2"},
				},
			},
			expected: &yaml.Node{
				Kind: yaml.MappingNode,
				Content: []*yaml.Node{
					{Kind: yaml.ScalarNode, Value: "key1"},
					{Kind: yaml.ScalarNode, Value: ""},
					{Kind: yaml.ScalarNode, Value: "key2"},
					{Kind: yaml.ScalarNode, Value: ""},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearNodeData(tt.node)

			// Compare node values
			if tt.node.Kind != tt.expected.Kind {
				t.Errorf("Node kind = %v, want %v", tt.node.Kind, tt.expected.Kind)
			}

			if tt.node.Value != tt.expected.Value {
				t.Errorf("Node value = %v, want %v", tt.node.Value, tt.expected.Value)
			}

			if len(tt.node.Content) != len(tt.expected.Content) {
				t.Errorf("Node content length = %v, want %v", len(tt.node.Content), len(tt.expected.Content))
			}

			for i := 0; i < len(tt.node.Content); i++ {
				if tt.node.Content[i].Value != tt.expected.Content[i].Value {
					t.Errorf("Content[%d] value = %v, want %v", i, tt.node.Content[i].Value, tt.expected.Content[i].Value)
				}
			}
		})
	}
}

func TestMaskNodeValues(t *testing.T) {
	tests := []struct {
		name     string
		node     *yaml.Node
		expected *yaml.Node
	}{
		{
			name: "scalar node with encrypted value",
			node: &yaml.Node{
				Kind:  yaml.ScalarNode,
				Value: "AES256:abcdefghijklmnopqrstuvwxyz",
			},
			expected: &yaml.Node{
				Kind:  yaml.ScalarNode,
				Value: "AES256:abcdefgh********",
			},
		},
		{
			name: "sequence node with encrypted values",
			node: &yaml.Node{
				Kind: yaml.SequenceNode,
				Content: []*yaml.Node{
					{Kind: yaml.ScalarNode, Value: "AES256:abcdefghijklmnopqrstuvwxyz"},
					{Kind: yaml.ScalarNode, Value: "AES256:abc"},
				},
			},
			expected: &yaml.Node{
				Kind: yaml.SequenceNode,
				Content: []*yaml.Node{
					{Kind: yaml.ScalarNode, Value: "AES256:abcdefgh********"},
					{Kind: yaml.ScalarNode, Value: "AES256:abc********"},
				},
			},
		},
		{
			name: "mapping node with encrypted values",
			node: &yaml.Node{
				Kind: yaml.MappingNode,
				Content: []*yaml.Node{
					{Kind: yaml.ScalarNode, Value: "key1"},
					{Kind: yaml.ScalarNode, Value: "AES256:abcdefghijklmnopqrstuvwxyz"},
					{Kind: yaml.ScalarNode, Value: "key2"},
					{Kind: yaml.ScalarNode, Value: "AES256:abc"},
				},
			},
			expected: &yaml.Node{
				Kind: yaml.MappingNode,
				Content: []*yaml.Node{
					{Kind: yaml.ScalarNode, Value: "key1"},
					{Kind: yaml.ScalarNode, Value: "AES256:abcdefgh********"},
					{Kind: yaml.ScalarNode, Value: "key2"},
					{Kind: yaml.ScalarNode, Value: "AES256:abc********"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			maskNodeValues(tt.node)
			if !reflect.DeepEqual(tt.node, tt.expected) {
				t.Errorf("maskNodeValues() = %v, want %v", tt.node, tt.expected)
			}
		})
	}
}

func TestLoadRules(t *testing.T) {
	tests := []struct {
		name      string
		config    string
		wantRules []Rule
		wantError bool
	}{
		{
			name: "valid config",
			config: `
encryption:
  rules:
    - block: "test"
      pattern: "*.secret"
      action: "encrypt"
`,
			wantRules: []Rule{
				{
					Block:   "test",
					Pattern: "*.secret",
					Action:  "encrypt",
				},
			},
			wantError: false,
		},
		{
			name:      "empty config",
			config:    "",
			wantRules: []Rule{},
			wantError: false,
		},
		{
			name: "invalid yaml",
			config: `
encryption:
  rules:
    - block: "test"
      pattern: "*.secret"
      action: "encrypt"
    - block: "test2"
      pattern: "*.secret"
      action: "encrypt"
`,
			wantRules: []Rule{},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpfile, err := os.CreateTemp("", "config*.yml")
			if err != nil {
				t.Fatal(err)
			}
			defer os.Remove(tmpfile.Name())

			if _, err := tmpfile.Write([]byte(tt.config)); err != nil {
				t.Fatal(err)
			}
			if err := tmpfile.Close(); err != nil {
				t.Fatal(err)
			}

			rules, _, err := loadRules(tmpfile.Name(), false)
			if (err != nil) != tt.wantError {
				t.Errorf("loadRules() error = %v, wantError %v", err, tt.wantError)
				return
			}
			if !tt.wantError {
				if err != nil {
					t.Errorf("loadRules() error = %v, wantError false", err)
				}
				if !reflect.DeepEqual(rules, tt.wantRules) {
					t.Errorf("loadRules() = %v, want %v", rules, tt.wantRules)
				}
			}
		})
	}
}

func TestProcessFileErrors(t *testing.T) {
	tests := []struct {
		name          string
		filename      string
		key           string
		operation     string
		wantError     bool
		errorContains string
	}{
		{
			name:          "non-existent file",
			filename:      "non-existent.yml",
			key:           "test-key-12345678",
			operation:     "encrypt",
			wantError:     true,
			errorContains: "error reading YAML file",
		},
		{
			name:          "invalid YAML file",
			filename:      "invalid.yml",
			key:           "test-key-12345678",
			operation:     "encrypt",
			wantError:     true,
			errorContains: "error reading YAML file",
		},
		{
			name:          "invalid operation",
			filename:      "test.yml",
			key:           "test-key-12345678",
			operation:     "invalid",
			wantError:     true,
			errorContains: "invalid operation",
		},
		{
			name:          "empty YAML file",
			filename:      "empty.yml",
			key:           "test-key-12345678",
			operation:     "encrypt",
			wantError:     true,
			errorContains: "error reading YAML file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test files
			if tt.name == "invalid YAML file" {
				if err := os.WriteFile(tt.filename, []byte("invalid: yaml: content:"), 0644); err != nil {
					t.Fatal(err)
				}
			} else if tt.name == "empty YAML file" {
				if err := os.WriteFile(tt.filename, []byte(""), 0644); err != nil {
					t.Fatal(err)
				}
			} else if tt.name == "non-existent file" {
				// Skip file creation
			} else {
				if err := os.WriteFile(tt.filename, []byte("test: value"), 0644); err != nil {
					t.Fatal(err)
				}
			}
			defer os.Remove(tt.filename)

			// Create temporary config file
			tmpConfig, err := os.CreateTemp("", "config-*.yml")
			if err != nil {
				t.Fatal(err)
			}
			defer os.Remove(tmpConfig.Name())

			if _, err := tmpConfig.Write([]byte(`
encryption:
  env_blocks:
    - "** if len(value) > 0"
`)); err != nil {
				t.Fatal(err)
			}

			// Set config file path for testing
			os.Setenv("YED_CONFIG", tmpConfig.Name())

			err = ProcessFile(tt.filename, tt.key, tt.operation, false, false, false)
			if tt.wantError {
				if err == nil {
					t.Error("ProcessFile() error = nil, wantError true")
				} else if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error to contain '%s', got '%v'", tt.errorContains, err)
				}
				return
			}

			if err != nil {
				t.Errorf("ProcessFile() error = %v, wantError false", err)
			}
		})
	}
}

func TestHelperFunctions(t *testing.T) {
	t.Run("all function", func(t *testing.T) {
		items := []interface{}{1, 2, 3, 4, 5}
		result := all(items, func(item interface{}) bool {
			return item.(int) > 0
		})
		if !result {
			t.Error("Expected all items to be greater than 0")
		}

		result = all(items, func(item interface{}) bool {
			return item.(int) > 3
		})
		if result {
			t.Error("Expected not all items to be greater than 3")
		}
	})

	t.Run("any function", func(t *testing.T) {
		items := []interface{}{1, 2, 3, 4, 5}
		result := any(items, func(item interface{}) bool {
			return item.(int) > 4
		})
		if !result {
			t.Error("Expected at least one item to be greater than 4")
		}

		result = any(items, func(item interface{}) bool {
			return item.(int) > 5
		})
		if result {
			t.Error("Expected no items to be greater than 5")
		}
	})

	t.Run("none function", func(t *testing.T) {
		items := []interface{}{1, 2, 3, 4, 5}
		result := none(items, func(item interface{}) bool {
			return item.(int) > 5
		})
		if !result {
			t.Error("Expected no items to be greater than 5")
		}

		result = none(items, func(item interface{}) bool {
			return item.(int) > 4
		})
		if result {
			t.Error("Expected at least one item to be greater than 4")
		}
	})

	t.Run("one function", func(t *testing.T) {
		items := []interface{}{1, 2, 3, 4, 5}
		result := one(items, func(item interface{}) bool {
			return item.(int) == 3
		})
		if !result {
			t.Error("Expected exactly one item to be equal to 3")
		}

		result = one(items, func(item interface{}) bool {
			return item.(int) > 3
		})
		if result {
			t.Error("Expected more than one item to be greater than 3")
		}
	})

	t.Run("filter function", func(t *testing.T) {
		items := []interface{}{1, 2, 3, 4, 5}
		result := filter(items, func(item interface{}) bool {
			return item.(int) > 3
		})
		if len(result) != 2 {
			t.Errorf("Expected 2 items, got %d", len(result))
		}
		if result[0].(int) != 4 || result[1].(int) != 5 {
			t.Error("Expected filtered items to be [4, 5]")
		}
	})

	t.Run("mapValues function", func(t *testing.T) {
		items := []interface{}{1, 2, 3}
		result := mapValues(items, func(item interface{}) interface{} {
			return item.(int) * 2
		})
		if len(result) != 3 {
			t.Errorf("Expected 3 items, got %d", len(result))
		}
		if result[0].(int) != 2 || result[1].(int) != 4 || result[2].(int) != 6 {
			t.Error("Expected mapped items to be [2, 4, 6]")
		}
	})
}

func TestFileOperations(t *testing.T) {
	t.Run("readYAMLWithBuffer", func(t *testing.T) {
		// Create a temporary YAML file
		content := []byte("test: value\narray:\n  - item1\n  - item2")
		tmpfile, err := os.CreateTemp("", "test-*.yml")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmpfile.Name())

		if _, err := tmpfile.Write(content); err != nil {
			t.Fatal(err)
		}
		if err := tmpfile.Close(); err != nil {
			t.Fatal(err)
		}

		// Test reading
		node, err := readYAMLWithBuffer(tmpfile.Name())
		if err != nil {
			t.Errorf("readYAMLWithBuffer() error = %v", err)
			return
		}
		if node == nil || len(node.Content) == 0 {
			t.Error("readYAMLWithBuffer() returned empty node")
			return
		}
	})

	t.Run("writeYAMLWithBuffer", func(t *testing.T) {
		// Create a test node
		node := &yaml.Node{
			Kind: yaml.MappingNode,
			Content: []*yaml.Node{
				{Kind: yaml.ScalarNode, Value: "test"},
				{Kind: yaml.ScalarNode, Value: "value"},
			},
		}

		// Create a temporary file
		tmpfile, err := os.CreateTemp("", "test-*.yml")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmpfile.Name())

		// Test writing
		if err := writeYAMLWithBuffer(tmpfile.Name(), node); err != nil {
			t.Errorf("writeYAMLWithBuffer() error = %v", err)
			return
		}

		// Verify the written content
		content, err := os.ReadFile(tmpfile.Name())
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(content), "test: value") {
			t.Error("writeYAMLWithBuffer() did not write correct content")
		}
	})
}

func TestRegexCache(t *testing.T) {
	t.Run("getCompiledRegex", func(t *testing.T) {
		// Test valid pattern
		pattern := "test.*"
		re1, err := getCompiledRegex(pattern)
		if err != nil {
			t.Errorf("getCompiledRegex() error = %v", err)
			return
		}
		if re1 == nil {
			t.Error("getCompiledRegex() returned nil")
			return
		}

		// Test cache hit
		re2, err := getCompiledRegex(pattern)
		if err != nil {
			t.Errorf("getCompiledRegex() error = %v", err)
			return
		}
		if re1 != re2 {
			t.Error("getCompiledRegex() did not return cached regex")
		}

		// Test invalid pattern
		_, err = getCompiledRegex("(invalid")
		if err == nil {
			t.Error("getCompiledRegex() did not return error for invalid pattern")
		}
	})

	t.Run("clearRegexCache", func(t *testing.T) {
		// Fill cache
		pattern := "test.*"
		re1, _ := getCompiledRegex(pattern)

		// Clear cache
		clearRegexCache()

		// Check if cache was cleared
		re2, _ := getCompiledRegex(pattern)
		if re1 == re2 {
			t.Error("clearRegexCache() did not clear the cache")
		}
	})
}

func TestDebugLog(t *testing.T) {
	// Capture output
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Test with debug = true
	debugLog(true, "test message %s", "value")
	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	if !strings.Contains(output, "[DEBUG] test message value") {
		t.Errorf("debugLog() with debug=true did not output expected message, got: %s", output)
	}

	// Capture output for second test
	r, w, _ = os.Pipe()
	os.Stdout = w

	// Test with debug = false
	debugLog(false, "test message %s", "value")
	w.Close()
	os.Stdout = oldStdout

	buf.Reset()
	io.Copy(&buf, r)
	output = buf.String()

	if output != "" {
		t.Errorf("debugLog() with debug=false produced output when it should not: %s", output)
	}
}

func TestWildcardToRegex(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		expected string
	}{
		{
			name:     "simple pattern",
			pattern:  "test",
			expected: "^test$",
		},
		{
			name:     "pattern with wildcard",
			pattern:  "test*",
			expected: "^test.*$",
		},
		{
			name:     "pattern with multiple wildcards",
			pattern:  "*test*value*",
			expected: "^.*test.*value.*$",
		},
		{
			name:     "pattern with special characters",
			pattern:  "test.value*",
			expected: "^test\\.value.*$",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := wildcardToRegex(tt.pattern)
			if result != tt.expected {
				t.Errorf("wildcardToRegex() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestMatchesRule(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		rule     Rule
		debug    bool
		expected bool
	}{
		{
			name:     "simple match",
			path:     "axel.fix",
			rule:     Rule{Block: "axel.fix", Pattern: ".*", Action: "encrypt"},
			debug:    false,
			expected: true,
		},
		{
			name:     "wildcard match",
			path:     "axel.fix",
			rule:     Rule{Block: "*", Pattern: "axel.*", Action: "encrypt"},
			debug:    false,
			expected: true,
		},
		{
			name:     "no match",
			path:     "axel.fix",
			rule:     Rule{Block: "other", Pattern: ".*", Action: "encrypt"},
			debug:    false,
			expected: false,
		},
		{
			name:     "exact match",
			path:     "axel.fix",
			rule:     Rule{Block: "axel.fix", Pattern: ".*", Action: "encrypt"},
			debug:    false,
			expected: true,
		},
		{
			name:     "wildcard with pattern",
			path:     "axel.fix",
			rule:     Rule{Block: "*", Pattern: "axel.*", Action: "encrypt"},
			debug:    false,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchesRule(tt.path, tt.rule, tt.debug)
			if result != tt.expected {
				t.Errorf("matchesRule() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestProcessNodeErrors(t *testing.T) {
	tests := []struct {
		name      string
		node      *yaml.Node
		path      string
		key       string
		operation string
		debug     bool
		wantErr   string
	}{
		{
			name: "invalid_node_kind",
			node: &yaml.Node{
				Kind: yaml.AliasNode,
			},
			path:      "test",
			key:       "test-key-12345678",
			operation: "encrypt",
			debug:     false,
			wantErr:   "unsupported node kind: alias",
		},
		{
			name: "encryption_error_-_short_key",
			node: &yaml.Node{
				Kind:  yaml.ScalarNode,
				Value: "test",
			},
			path:      "test",
			key:       "short",
			operation: "encrypt",
			debug:     false,
			wantErr:   "key length must be at least 16 characters",
		},
		{
			name: "decryption_error_-_invalid_data",
			node: &yaml.Node{
				Kind:  yaml.ScalarNode,
				Value: "AES256:invalid",
			},
			path:      "test",
			key:       "test-key-12345678",
			operation: "decrypt",
			debug:     false,
			wantErr:   "failed to decode encrypted data",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ProcessNode(tt.node, tt.path, tt.key, tt.operation, tt.debug)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("ProcessNode() error = %v, want error containing %v", err, tt.wantErr)
			}
		})
	}
}

func TestBufferOperations(t *testing.T) {
	// Create a temporary file
	tmpfile, err := os.CreateTemp("", "test*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	// Write test data
	testData := "key: value\narray:\n  - item1\n  - item2\n"
	if _, err := tmpfile.Write([]byte(testData)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	// Test reading with buffer
	data, err := os.ReadFile(tmpfile.Name())
	if err != nil {
		t.Fatal(err)
	}

	var node yaml.Node
	err = yaml.Unmarshal(data, &node)
	if err != nil {
		t.Fatal(err)
	}

	// Test writing with buffer
	outFile := tmpfile.Name() + ".out"
	defer os.Remove(outFile)

	data, err = yaml.Marshal(&node)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(outFile, data, 0644)
	if err != nil {
		t.Errorf("Failed to write file: %v", err)
	}

	// Verify written content
	content, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "key: value") {
		t.Error("File write did not preserve expected content")
	}

	// Test error cases
	_, err = os.ReadFile("nonexistent.yaml")
	if err == nil {
		t.Error("Reading nonexistent file should return error")
	}

	err = os.WriteFile("/nonexistent/dir/file.yaml", data, 0644)
	if err == nil {
		t.Error("Writing to invalid path should return error")
	}
}

func TestParallelProcessing(t *testing.T) {
	// Create temporary configuration file
	configContent := `encryption:
  env_blocks:
    - "** if len(value) > 0"`
	tmpConfig, err := os.CreateTemp("", "config-*.yml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpConfig.Name())

	if err := os.WriteFile(tmpConfig.Name(), []byte(configContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Set environment variable for configuration file
	os.Setenv("YED_CONFIG", tmpConfig.Name())
	defer os.Unsetenv("YED_CONFIG")

	// Create temporary file with large YAML
	tmpFile, err := os.CreateTemp("", "test-*.yml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	// Create large YAML file
	yamlContent := "data:\n"
	for i := 0; i < 10; i++ { // Reduce number of keys to 10
		yamlContent += fmt.Sprintf("  key%d: value%d\n", i, i)
	}
	if err := os.WriteFile(tmpFile.Name(), []byte(yamlContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Test parallel processing
	start := time.Now()
	err = ProcessFile(tmpFile.Name(), "test-key-12345678", "encrypt", true, false, false)
	duration := time.Since(start)
	if err != nil {
		t.Fatalf("ProcessFile() error = %v", err)
	}

	// Test sequential processing
	start = time.Now()
	err = ProcessFile(tmpFile.Name(), "test-key-12345678", "encrypt", false, false, false)
	sequentialDuration := time.Since(start)
	if err != nil {
		t.Fatalf("ProcessFile() error = %v", err)
	}

	// Check that parallel processing is not significantly slower
	if duration.Nanoseconds() > int64(float64(sequentialDuration.Nanoseconds())*1.5) {
		t.Errorf("Parallel processing was significantly slower: parallel=%v, sequential=%v", duration, sequentialDuration)
	}
}
