package processor

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/atlet99/yaml-encrypter-decrypter/pkg/encryption"

	"gopkg.in/yaml.v3"
)

const (
	AES              = "AES256:" // Prefix for encrypted values
	OperationEncrypt = "encrypt"
	OperationDecrypt = "decrypt"

	// Buffer and processing constants
	DefaultBufferSize  = 1024
	DefaultIndent      = 2
	LargeFileThreshold = 1000
	MaxParts           = 2
	MaskLength         = 8
	MinKeyLength       = 16 // Minimum length for encryption key
)

type Rule struct {
	Path      string
	Condition string
}

// Helper functions for expr environment
func all(items []interface{}, predicate func(interface{}) bool) bool {
	for _, item := range items {
		if !predicate(item) {
			return false
		}
	}
	return true
}

func any(items []interface{}, predicate func(interface{}) bool) bool {
	for _, item := range items {
		if predicate(item) {
			return true
		}
	}
	return false
}

func none(items []interface{}, predicate func(interface{}) bool) bool {
	return !any(items, predicate)
}

func one(items []interface{}, predicate func(interface{}) bool) bool {
	count := 0
	for _, item := range items {
		if predicate(item) {
			count++
		}
	}
	return count == 1
}

func filter(items []interface{}, predicate func(interface{}) bool) []interface{} {
	result := make([]interface{}, 0)
	for _, item := range items {
		if predicate(item) {
			result = append(result, item)
		}
	}
	return result
}

func mapValues(items []interface{}, mapper func(interface{}) interface{}) []interface{} {
	result := make([]interface{}, len(items))
	for i, item := range items {
		result[i] = mapper(item)
	}
	return result
}

func debugLog(debug bool, format string, v ...interface{}) {
	if debug {
		log.Printf("[DEBUG] "+format, v...)
	}
}

// maskEncryptedValue masks the encrypted value, leaving only the first 8 characters
func maskEncryptedValue(value string) string {
	if !strings.HasPrefix(value, AES) {
		return value
	}
	encrypted := strings.TrimPrefix(value, AES)
	// Remove base64 padding before masking
	encrypted = strings.TrimRight(encrypted, "=")
	// Always return MaskLength characters + MaskLength asterisks for consistency
	if len(encrypted) <= MaskLength {
		return AES + encrypted + strings.Repeat("*", MaskLength)
	}
	return AES + encrypted[:MaskLength] + strings.Repeat("*", MaskLength)
}

// regexCache stores compiled regular expressions
var regexCache = struct {
	sync.RWMutex
	cache map[string]*regexp.Regexp
}{
	cache: make(map[string]*regexp.Regexp),
}

// getCompiledRegex returns a compiled regex from cache or compiles a new one
func getCompiledRegex(pattern string) (*regexp.Regexp, error) {
	regexCache.RLock()
	if re, ok := regexCache.cache[pattern]; ok {
		regexCache.RUnlock()
		return re, nil
	}
	regexCache.RUnlock()

	regexCache.Lock()
	defer regexCache.Unlock()

	// Double check after acquiring write lock
	if re, ok := regexCache.cache[pattern]; ok {
		return re, nil
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	regexCache.cache[pattern] = re
	return re, nil
}

// clearRegexCache clears the regex cache
func clearRegexCache() {
	regexCache.Lock()
	defer regexCache.Unlock()
	regexCache.cache = make(map[string]*regexp.Regexp)
}

// ProcessFile processes a YAML file with security considerations
func ProcessFile(filename, key, operation string, dryRun, debug bool) error {
	if operation != OperationEncrypt && operation != OperationDecrypt {
		return fmt.Errorf("invalid operation: %s", operation)
	}

	// Load encryption rules
	rules, err := loadRules(".yed_config.yml")
	if err != nil {
		return fmt.Errorf("error loading rules: %w", err)
	}

	// Read YAML file with buffering
	data, err := readYAMLWithBuffer(filename)
	if err != nil {
		return fmt.Errorf("error reading YAML file: %w", err)
	}

	if data == nil || len(data.Content) == 0 {
		return fmt.Errorf("invalid YAML structure: empty document")
	}

	// Create temporary buffer for operations
	tempBuffer := make([]byte, 0, DefaultBufferSize)
	defer secureClear(tempBuffer)

	// Process YAML file
	start := time.Now()
	processedPaths := make(map[string]bool)

	// Process rules in parallel for large files
	if len(data.Content) > LargeFileThreshold {
		errChan := make(chan error, len(rules))
		var wg sync.WaitGroup
		wg.Add(len(rules))

		for _, rule := range rules {
			go func(r Rule) {
				defer wg.Done()
				debugLog(debug, "Applying rule: Path='%s', Condition='%s'", r.Path, r.Condition)
				err := processYAML(data.Content[0], key, operation, r, "", processedPaths, debug)
				if err != nil {
					errChan <- fmt.Errorf("error processing YAML with rule %v: %w", r, err)
				}
			}(rule)
		}

		wg.Wait()
		close(errChan)

		// Collect errors
		var errors []string
		for err := range errChan {
			errors = append(errors, err.Error())
		}

		if len(errors) > 0 {
			return fmt.Errorf("errors during parallel processing: %s", strings.Join(errors, "; "))
		}
	} else {
		// Sequential processing for small files
		for _, rule := range rules {
			debugLog(debug, "Applying rule: Path='%s', Condition='%s'", rule.Path, rule.Condition)
			err := processYAML(data.Content[0], key, operation, rule, "", processedPaths, debug)
			if err != nil {
				return fmt.Errorf("error processing YAML with rule %v: %w", rule, err)
			}
		}
	}

	// Output results
	elapsed := time.Since(start)
	fmt.Printf("YAML processing completed in %v\n", elapsed)

	if dryRun {
		// Dry-run mode: output YAML with masked values
		fmt.Println("Dry-run mode: The following changes would be applied:")
		output := &strings.Builder{}
		encoder := yaml.NewEncoder(output)
		encoder.SetIndent(DefaultIndent)

		// Create a copy of data for masking
		maskedData := *data
		if len(maskedData.Content) > 0 {
			maskNodeValues(maskedData.Content[0])
		}

		if err := encoder.Encode(&maskedData); err != nil {
			return fmt.Errorf("error encoding YAML: %w", err)
		}
		fmt.Println(output.String())
	} else {
		// Write updated YAML back to file with buffering
		if err := writeYAMLWithBuffer(filename, data); err != nil {
			return fmt.Errorf("error writing YAML file: %w", err)
		}
		fmt.Printf("File %s updated successfully.\n", filename)
	}

	// Clear sensitive data
	if len(data.Content) > 0 {
		clearNodeData(data.Content[0])
	}

	// Clear regex cache after processing
	clearRegexCache()

	return nil
}

// readYAMLWithBuffer reads YAML file with buffering
func readYAMLWithBuffer(filename string) (*yaml.Node, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Create buffered reader
	reader := bufio.NewReader(file)
	decoder := yaml.NewDecoder(reader)
	var data yaml.Node
	if err := decoder.Decode(&data); err != nil {
		return nil, err
	}
	return &data, nil
}

// writeYAMLWithBuffer writes YAML file with buffering
func writeYAMLWithBuffer(filename string, data *yaml.Node) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	// Create buffered writer
	writer := bufio.NewWriter(file)
	defer writer.Flush()

	encoder := yaml.NewEncoder(writer)
	encoder.SetIndent(DefaultIndent)
	return encoder.Encode(data)
}

// clearNodeData recursively clears sensitive data from the node
func clearNodeData(node *yaml.Node) {
	if node == nil {
		return
	}

	switch node.Kind {
	case yaml.ScalarNode:
		if strings.HasPrefix(node.Value, AES) {
			node.Value = ""
		}
	case yaml.SequenceNode, yaml.MappingNode:
		for _, child := range node.Content {
			clearNodeData(child)
		}
	}
}

// maskNodeValues recursively masks encrypted values in YAML nodes
func maskNodeValues(node *yaml.Node) {
	if node == nil {
		return
	}

	switch node.Kind {
	case yaml.ScalarNode:
		if strings.HasPrefix(node.Value, AES) {
			node.Value = maskEncryptedValue(node.Value)
		}
	case yaml.SequenceNode:
		for _, child := range node.Content {
			maskNodeValues(child)
		}
	case yaml.MappingNode:
		for i := 0; i < len(node.Content); i += 2 {
			if i+1 < len(node.Content) {
				maskNodeValues(node.Content[i+1])
			}
		}
	}
}

func loadRules(configFile string) ([]Rule, error) {
	// Use environment variable if set
	if envConfig := os.Getenv("YED_CONFIG"); envConfig != "" {
		configFile = envConfig
	}

	// If config file is not specified, use default path
	if configFile == "" {
		configFile = ".yed_config.yml"
	}

	file, err := os.Open(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file: %w", err)
	}
	defer file.Close()

	var config struct {
		Encryption struct {
			EnvBlocks []string `yaml:"env_blocks"`
		} `yaml:"encryption"`
	}

	decoder := yaml.NewDecoder(file)
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("failed to decode YAML: %w", err)
	}

	var rules []Rule
	for _, block := range config.Encryption.EnvBlocks {
		parts := strings.SplitN(block, " if ", MaxParts)
		rule := Rule{
			Path:      parts[0],
			Condition: "",
		}
		if len(parts) == MaxParts {
			rule.Condition = parts[1]
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func processMappingNodeContent(node *yaml.Node, key, operation string, rule Rule, currentPath string, processedPaths map[string]bool, debug bool) error {
	for i := 0; i < len(node.Content); i += 2 {
		keyNode := node.Content[i]
		valueNode := node.Content[i+1]
		keyPath := currentPath + "." + keyNode.Value

		if processedPaths[keyPath] {
			continue
		}

		if matchesRule(keyPath, rule) {
			processedPaths[keyPath] = true
			if err := processYAML(valueNode, key, operation, rule, keyPath, processedPaths, debug); err != nil {
				return err
			}
		}
	}
	return nil
}

func processSequenceNodeContent(node *yaml.Node, key, operation string, rule Rule, currentPath string, processedPaths map[string]bool, debug bool) error {
	for i, item := range node.Content {
		itemPath := fmt.Sprintf("%s[%d]", currentPath, i)
		if processedPaths[itemPath] {
			continue
		}

		if matchesRule(itemPath, rule) {
			processedPaths[itemPath] = true
			if err := processYAML(item, key, operation, rule, itemPath, processedPaths, debug); err != nil {
				return err
			}
		}
	}
	return nil
}

func processYAML(node *yaml.Node, key, operation string, rule Rule, currentPath string, processedPaths map[string]bool, debug bool) error {
	if node == nil {
		return fmt.Errorf("nil node encountered at path: %s", currentPath)
	}

	switch node.Kind {
	case yaml.MappingNode:
		if len(node.Content)%2 != 0 {
			return fmt.Errorf("invalid mapping node at path: %s", currentPath)
		}
		return processMappingNodeContent(node, key, operation, rule, currentPath, processedPaths, debug)

	case yaml.SequenceNode:
		return processSequenceNodeContent(node, key, operation, rule, currentPath, processedPaths, debug)

	case yaml.ScalarNode:
		if matchesRule(currentPath, rule) {
			processedPaths[currentPath] = true
			return processScalarNode(node, currentPath, key, operation)
		}
		return nil

	default:
		return fmt.Errorf("unsupported node kind: %v at path: %s", node.Kind, currentPath)
	}
}

func matchesRule(path string, rule Rule) bool {
	pattern := wildcardToRegex(rule.Path)
	matched, err := regexp.MatchString(pattern, path)
	if err != nil {
		return false
	}
	return matched
}

// secureClear clears sensitive data from memory
func secureClear(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ProcessNode processes a YAML node with the given operation
func ProcessNode(node *yaml.Node, path, key, operation string) error {
	// Validate operation
	if operation != "encrypt" && operation != "decrypt" {
		return fmt.Errorf("invalid operation: %s", operation)
	}

	// Handle nil node
	if node == nil {
		return nil
	}

	// Process based on node kind
	switch node.Kind {
	case yaml.ScalarNode:
		return processScalarNode(node, path, key, operation)
	case yaml.SequenceNode:
		return processSequenceNode(node, path, key, operation)
	case yaml.MappingNode:
		return processMappingNode(node, path, key, operation)
	case yaml.AliasNode:
		return fmt.Errorf("unsupported node kind: alias")
	default:
		return fmt.Errorf("unsupported node kind: %v", node.Kind)
	}
}

// processScalarNode processes a scalar node
func processScalarNode(node *yaml.Node, path, key, operation string) error {
	if operation == OperationEncrypt && !strings.HasPrefix(node.Value, AES) {
		if len(key) < MinKeyLength {
			return fmt.Errorf("key length must be at least %d characters", MinKeyLength)
		}
		encryptedValue, err := encryption.Encrypt(key, node.Value)
		if err != nil {
			return fmt.Errorf("failed to encrypt value at path '%s': %w", path, err)
		}
		node.Value = AES + encryptedValue
		node.Tag = "!!str"
	} else if operation == OperationDecrypt && strings.HasPrefix(node.Value, AES) {
		decryptedValue, err := encryption.Decrypt(key, strings.TrimPrefix(node.Value, AES))
		if err != nil {
			return fmt.Errorf("failed to decode encrypted data")
		}
		node.Value = decryptedValue
		node.Tag = "!!str"
	}
	return nil
}

// processSequenceNode processes a sequence node
func processSequenceNode(node *yaml.Node, path, key, operation string) error {
	for i, item := range node.Content {
		if err := ProcessNode(item, fmt.Sprintf("%s[%d]", path, i), key, operation); err != nil {
			return fmt.Errorf("error processing sequence item %d: %w", i, err)
		}
	}
	return nil
}

// processMappingNode processes a mapping node
func processMappingNode(node *yaml.Node, path, key, operation string) error {
	for i := 0; i < len(node.Content); i += 2 {
		if i+1 >= len(node.Content) {
			return fmt.Errorf("invalid mapping node: odd number of items")
		}
		keyNode := node.Content[i]
		valueNode := node.Content[i+1]
		if err := ProcessNode(valueNode, fmt.Sprintf("%s.%s", path, keyNode.Value), key, operation); err != nil {
			return fmt.Errorf("error processing mapping value for key %s: %w", keyNode.Value, err)
		}
	}
	return nil
}

// EvaluateCondition evaluates a condition with caching
func EvaluateCondition(condition string, value interface{}) bool {
	if condition == "" {
		return true
	}

	// Check if condition is a wildcard pattern
	if strings.Contains(condition, "*") {
		re, err := getCompiledRegex(wildcardToRegex(condition))
		if err != nil {
			return false
		}
		return re.MatchString(fmt.Sprintf("%v", value))
	}

	// Direct comparison for non-wildcard conditions
	return fmt.Sprintf("%v", value) == condition
}

// wildcardToRegex converts a wildcard pattern to a regular expression
func wildcardToRegex(pattern string) string {
	// Escape special regex characters
	pattern = regexp.QuoteMeta(pattern)
	// Convert wildcard * to regex .*
	pattern = strings.ReplaceAll(pattern, "\\*", ".*")
	return "^" + pattern + "$"
}
