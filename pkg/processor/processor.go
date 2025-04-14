package processor

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/atlet99/yaml-encrypter-decrypter/pkg/encryption"

	"gopkg.in/yaml.v3"
)

// File contains constants and variables for YAML file processing
const (
	// Operations
	AES              = "AES256:"
	OperationEncrypt = "encrypt"
	OperationDecrypt = "decrypt"

	// Buffer and processing constants
	DefaultBufferSize  = 1024
	DefaultIndent      = 2
	LargeFileThreshold = 1000
	MaxParts           = 2
	MaskLength         = 6
	MinKeyLength       = 16 // Minimum length for encryption key

	// Action types
	ActionNone = "none"

	// Magic numbers
	MinEncryptedLength = 6
	KeyValuePairSize   = 2

	// File permissions
	SecureFileMode = 0600 // Secure file permissions (owner read/write only)

	// Masked value for sensitive information
	MaskedValue = "********"

	// EncryptedPrefix is the prefix for encrypted values
	EncryptedPrefix = "AES256:"

	// AlgorithmIndicatorLength is the length of the algorithm indicator
	AlgorithmIndicatorLength = 16
)

// CurrentKeyDerivationAlgorithm is the algorithm to use for encryption
var CurrentKeyDerivationAlgorithm encryption.KeyDerivationAlgorithm

type Rule struct {
	Name        string `yaml:"name"`
	Block       string `yaml:"block"`   // Block to which the rule applies (e.g., "smart_config" or "*")
	Pattern     string `yaml:"pattern"` // Pattern for searching fields within the block (e.g., "**" or "pass*")
	Exclude     string `yaml:"exclude,omitempty"`
	Action      string `yaml:"action,omitempty"` // Default will be "encrypt"
	Description string `yaml:"description"`
}

// Config contains settings for YAML processing
type Config struct {
	Encryption struct {
		Rules        []Rule `yaml:"rules"`
		UnsecureDiff bool   `yaml:"unsecure_diff"`
	} `yaml:"encryption"`
	Key          string
	Operation    string
	Debug        bool
	UnsecureDiff bool
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

// debugLog outputs debug messages only if debug mode is enabled
func debugLog(debug bool, format string, args ...interface{}) {
	if debug {
		fmt.Printf("[DEBUG] "+format+"\n", args...)
	}
}

// maskEncryptedValue masks the encrypted value
func maskEncryptedValue(value string, debug bool, fieldPath ...string) string {
	if !strings.HasPrefix(value, AES) {
		return value
	}

	encrypted := strings.TrimPrefix(value, AES)

	// Add context information if field path is provided
	contextInfo := ""
	if len(fieldPath) > 0 && fieldPath[0] != "" {
		contextInfo = fmt.Sprintf(" for field '%s'", fieldPath[0])
	}

	// The debug parameter is now only used for logging, not for masking decision
	debugLog(debug, "Masking encrypted value%s (algo: %s)",
		contextInfo,
		detectAlgorithm(value),
	)

	// In all modes we shorten the value when masking is requested
	if len(encrypted) <= MinEncryptedLength {
		return AES + encrypted
	}

	// Keep first 3 characters, add *** and last 3 characters
	return AES + encrypted[:3] + "***" + encrypted[len(encrypted)-3:]
}

// detectAlgorithm tries to identify the algorithm used in the encrypted value
func detectAlgorithm(encryptedValue string) string {
	if !strings.HasPrefix(encryptedValue, AES) {
		return "unknown"
	}

	data := strings.TrimPrefix(encryptedValue, AES)
	if len(data) < AlgorithmIndicatorLength {
		return "unknown (too short)"
	}

	// Try to decode the base64
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "unknown (invalid base64)"
	}

	// Extract algorithm indicator (first 16 bytes)
	if len(decoded) < AlgorithmIndicatorLength {
		return "unknown (decoded too short)"
	}

	// Convert the algorithm bytes to string and trim nulls
	algoBytes := decoded[:AlgorithmIndicatorLength]
	algoStr := strings.TrimRight(string(algoBytes), "\x00")

	// Use switch instead of if-else
	switch {
	case strings.HasPrefix(algoStr, "argon2id"):
		return "argon2id"
	case strings.HasPrefix(algoStr, "pbkdf2-sha256"):
		return "pbkdf2-sha256"
	case strings.HasPrefix(algoStr, "pbkdf2-sha512"):
		return "pbkdf2-sha512"
	default:
		return "unknown algorithm"
	}
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

// matchesRule checks if a path matches a rule
func matchesRule(path string, rule Rule, debug bool) bool {
	debugLog(debug, "Checking if path '%s' matches rule '%s'", path, rule.Name)

	// Split path into parts
	parts := strings.Split(path, ".")

	// Check if path starts with the block
	if rule.Block != "*" && rule.Block != "**" {
		if !strings.HasPrefix(path, rule.Block) {
			debugLog(debug, "Path '%s' does not start with block '%s'", path, rule.Block)
			return false
		}
	}

	// For pattern matching, we should check the last part of the path
	lastPart := parts[len(parts)-1]

	// Handle special case for double asterisk pattern
	if rule.Pattern == "**" {
		debugLog(debug, "Pattern '**' matches everything")
		return true
	}

	// Check if last part matches pattern
	if !matchesPattern(lastPart, rule.Pattern, debug) {
		debugLog(debug, "Last part '%s' does not match pattern '%s'", lastPart, rule.Pattern)
		return false
	}

	// Check exclude pattern if present
	if rule.Exclude != "" {
		if matchesPattern(lastPart, rule.Exclude, debug) {
			debugLog(debug, "Path '%s' matches exclude pattern '%s'", path, rule.Exclude)
			return false
		}
	}

	debugLog(debug, "Path '%s' matches rule '%s'", path, rule.Name)
	return true
}

// matchesPattern checks if a path matches a pattern
func matchesPattern(path, pattern string, debug bool) bool {
	if pattern == "" {
		debugLog(debug, "Pattern is empty, returning true")
		return true
	}

	// Handle special case for double asterisk
	if pattern == "**" {
		debugLog(debug, "Double asterisk pattern matches everything")
		return true
	}

	// Check if pattern is a wildcard pattern
	if strings.Contains(pattern, "*") {
		re, err := getCompiledRegex(wildcardToRegex(pattern))
		if err != nil {
			debugLog(debug, "Error compiling regex for pattern '%s': %v", pattern, err)
			return false
		}
		matches := re.MatchString(path)
		matchStatus := "does not match"
		if matches {
			matchStatus = "matches"
		}
		debugLog(debug, "Path '%s' %s wildcard pattern '%s'", path, matchStatus, pattern)
		return matches
	}

	// Direct comparison for non-wildcard patterns
	matches := path == pattern
	matchStatus := "does not match"
	if matches {
		matchStatus = "matches"
	}
	debugLog(debug, "Path '%s' %s pattern '%s'", path, matchStatus, pattern)
	return matches
}

// wildcardToRegex converts a wildcard pattern to a regex pattern
func wildcardToRegex(pattern string) string {
	// Escape special regex characters
	pattern = regexp.QuoteMeta(pattern)

	// Replace ** with .* for recursive search
	pattern = strings.ReplaceAll(pattern, "\\*\\*", ".*")

	// Replace * with [^.]* for single level search
	pattern = strings.ReplaceAll(pattern, "\\*", "[^.]*")

	// Add start and end of string
	return "^" + pattern + "$"
}

// processYAMLContent processes YAML content with the given rules
func processYAMLContent(content []byte, key, operation string, rules []Rule, processedPaths map[string]bool, debug bool) (*yaml.Node, error) {
	debugLog(debug, "Processing YAML content with %d rules", len(rules))

	// Parse YAML content
	var node yaml.Node
	if err := yaml.Unmarshal(content, &node); err != nil {
		debugLog(debug, "Error parsing YAML content: %v", err)
		return nil, fmt.Errorf("error parsing YAML content: %w", err)
	}

	if node.Kind != yaml.DocumentNode || len(node.Content) == 0 {
		debugLog(debug, "Invalid YAML document structure")
		return nil, fmt.Errorf("invalid YAML document structure")
	}

	// Process the root node
	rootNode := node.Content[0]
	if err := processNode(rootNode, "", key, operation, rules, processedPaths, debug); err != nil {
		return nil, err
	}

	return &node, nil
}

func processNode(node *yaml.Node, path string, key, operation string, rules []Rule, processedPaths map[string]bool, debug bool) error {
	if node == nil {
		return nil
	}

	switch node.Kind {
	case yaml.MappingNode:
		return processMappingNode(node, path, key, operation, rules, processedPaths, debug)
	case yaml.SequenceNode:
		return processSequenceNode(node, path, key, operation, rules, processedPaths, debug)
	case yaml.ScalarNode:
		return processScalarNode(node, path, key, operation, rules, processedPaths, debug)
	default:
		return nil
	}
}

func processMappingNode(node *yaml.Node, path string, key, operation string, rules []Rule, processedPaths map[string]bool, debug bool) error {
	if len(node.Content)%2 != 0 {
		return fmt.Errorf("invalid mapping node")
	}

	for i := 0; i < len(node.Content); i += 2 {
		keyNode := node.Content[i]
		valueNode := node.Content[i+1]

		if keyNode.Kind != yaml.ScalarNode {
			continue
		}

		var newPath string
		if path == "" {
			newPath = keyNode.Value
		} else {
			newPath = path + "." + keyNode.Value
		}

		if err := processNode(valueNode, newPath, key, operation, rules, processedPaths, debug); err != nil {
			return err
		}
	}

	return nil
}

func processSequenceNode(node *yaml.Node, path string, key, operation string, rules []Rule, processedPaths map[string]bool, debug bool) error {
	for i, item := range node.Content {
		newPath := fmt.Sprintf("%s[%d]", path, i)
		if err := processNode(item, newPath, key, operation, rules, processedPaths, debug); err != nil {
			return err
		}
	}
	return nil
}

func processScalarNode(node *yaml.Node, path string, key, operation string, rules []Rule, processedPaths map[string]bool, debug bool) error {
	if processedPaths[path] {
		return nil
	}

	ruleName, shouldProcess := processRules(path, rules, debug)
	if !shouldProcess {
		debugLog(debug, "Skipping path %s due to rules", path)
		return nil
	}

	// Process multiline nodes first
	processed, err := ProcessMultilineNode(node, path, key, operation, debug)
	if err != nil {
		return fmt.Errorf("failed to process multiline node at path %s: %w", path, err)
	}

	// If the node was processed as multiline, mark it and return
	if processed {
		processedPaths[path] = true
		debugLog(debug, "Successfully processed multiline node at path %s with rule %s", path, ruleName)
		return nil
	}

	// Standard processing for non-multiline nodes
	if shouldProcess {
		debugLog(debug, "Processing path %s with rule %s", path, ruleName)
		processedPaths[path] = true

		switch operation {
		case OperationEncrypt:
			if !strings.HasPrefix(node.Value, AES) {
				encrypted, err := encryption.Encrypt(key, node.Value)
				if err != nil {
					return fmt.Errorf("failed to encrypt value at path %s: %w", path, err)
				}
				node.Value = AES + encrypted
			}
		case OperationDecrypt:
			if strings.HasPrefix(node.Value, AES) {
				debugLog(debug, "Processing encrypted node with value: %s", maskEncryptedValue(node.Value, debug, path))

				// Decrypt value
				decryptedBuffer, err := encryption.Decrypt(key, strings.TrimPrefix(node.Value, AES))
				if err != nil {
					debugLog(debug, "Error decrypting value: %v", err)
					return err
				}
				defer decryptedBuffer.Destroy() // Clean up the protected buffer

				// Set decrypted value
				decrypted := string(decryptedBuffer.Bytes())
				debugLog(debug, "Decrypted value: %s", decrypted)
				node.Value = decrypted

				// Mark path as processed
				if processedPaths != nil {
					processedPaths[path] = true
				}
			}
		}
	}

	return nil
}

// ProcessFile processes a YAML file with encryption or decryption
func ProcessFile(filePath, key, operation string, debug bool) error {
	debugLog(debug, "Processing file: %s", filePath)

	// Read file content
	content, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("error reading file: %w", err)
	}

	// Load rules from config file
	rules, _, err := loadRules(".yed_config.yml", debug)
	if err != nil {
		return fmt.Errorf("error loading rules: %w", err)
	}

	// Create a map to track processed paths
	processedPaths := make(map[string]bool)

	// Process YAML content
	node, err := processYAMLContent(content, key, operation, rules, processedPaths, debug)
	if err != nil {
		return fmt.Errorf("error processing YAML content: %w", err)
	}

	// Create a backup of the original file
	backupPath := filePath + ".bak"
	if err := os.WriteFile(backupPath, content, SecureFileMode); err != nil {
		return fmt.Errorf("error creating backup file: %w", err)
	}

	// Marshal the processed YAML back to bytes
	var buf bytes.Buffer
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(DefaultIndent)
	if err := encoder.Encode(node); err != nil {
		return fmt.Errorf("error encoding YAML: %w", err)
	}

	// Write the processed content back to the file
	if err := os.WriteFile(filePath, buf.Bytes(), SecureFileMode); err != nil {
		return fmt.Errorf("error writing file: %w", err)
	}

	return nil
}

// ShowDiff shows the difference between original and processed YAML
func ShowDiff(filePath, key, operation string, debug bool) error {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("error reading file: %w", err)
	}

	// Parse YAML content
	var node yaml.Node
	if err := yaml.Unmarshal(content, &node); err != nil {
		return fmt.Errorf("error parsing YAML: %w", err)
	}

	_, config, err := loadRules(".yed_config.yml", debug)
	if err != nil {
		return fmt.Errorf("error loading rules: %w", err)
	}

	// Log unsecureDiff value for debugging purposes
	debugLog(debug, "Loaded unsecureDiff value from config: %v", config.Encryption.UnsecureDiff)

	showDiff(&node, key, operation, config.Encryption.UnsecureDiff, debug)
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
func maskNodeValues(node *yaml.Node, debug bool) *yaml.Node {
	if node == nil {
		return nil
	}

	switch node.Kind {
	case yaml.ScalarNode:
		if strings.HasPrefix(node.Value, AES) {
			node.Value = maskEncryptedValue(node.Value, debug)
		}
		return node
	case yaml.SequenceNode:
		for _, child := range node.Content {
			maskNodeValues(child, debug)
		}
	case yaml.MappingNode:
		for i := 0; i < len(node.Content); i += 2 {
			if i+1 < len(node.Content) {
				maskNodeValues(node.Content[i+1], debug)
			}
		}
	}
	return node
}

// loadRules loads encryption rules from a config file
func loadRules(configFile string, debug bool) ([]Rule, *Config, error) {
	debugLog(debug, "Loading rules from config file: %s", configFile)

	// Read config file
	content, err := os.ReadFile(configFile)
	if err != nil {
		return nil, nil, fmt.Errorf("error reading config file: %w", err)
	}

	// Parse config
	var config Config
	if err := yaml.Unmarshal(content, &config); err != nil {
		return nil, nil, fmt.Errorf("error parsing config file: %w", err)
	}

	// Validate rules
	for _, rule := range config.Encryption.Rules {
		if rule.Block == "" {
			return nil, nil, fmt.Errorf("rule '%s' is missing block", rule.Name)
		}
		if rule.Pattern == "" {
			return nil, nil, fmt.Errorf("rule '%s' is missing pattern", rule.Name)
		}
	}

	return config.Encryption.Rules, &config, nil
}

// processRules processes rules in order of priority
func processRules(path string, rules []Rule, debug bool) (string, bool) {
	debugLog(debug, "Processing rules for path: %s", path)

	// First check for 'none' action rules
	for _, rule := range rules {
		if rule.Action == ActionNone && matchesRule(path, rule, debug) {
			debugLog(debug, "Path %s matches 'none' action rule %s", path, rule.Name)
			return "", false
		}
	}

	// Then check other rules
	for _, rule := range rules {
		if rule.Action != ActionNone && matchesRule(path, rule, debug) {
			debugLog(debug, "Path %s matches rule %s for encryption", path, rule.Name)
			return rule.Name, true
		}
	}

	debugLog(debug, "No matching rules found for path: %s", path)
	return "", false
}

// ProcessNode processes a YAML node
func ProcessNode(node *yaml.Node, path, key, operation string, rules []Rule, processedPaths map[string]bool, debug bool) error {
	if node == nil {
		return nil
	}

	switch node.Kind {
	case yaml.MappingNode:
		return processMappingNode(node, path, key, operation, rules, processedPaths, debug)
	case yaml.SequenceNode:
		return processSequenceNode(node, path, key, operation, rules, processedPaths, debug)
	case yaml.ScalarNode:
		return processScalarNode(node, path, key, operation, rules, processedPaths, debug)
	default:
		return nil
	}
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

// deepCopyNode creates a deep copy of a YAML node
func deepCopyNode(node *yaml.Node) *yaml.Node {
	if node == nil {
		return nil
	}

	newNode := &yaml.Node{
		Kind:        node.Kind,
		Style:       node.Style,
		Tag:         node.Tag,
		Value:       node.Value,
		Anchor:      node.Anchor,
		Alias:       deepCopyNode(node.Alias),
		Content:     make([]*yaml.Node, len(node.Content)),
		HeadComment: node.HeadComment,
		LineComment: node.LineComment,
		FootComment: node.FootComment,
		Line:        node.Line,
		Column:      node.Column,
	}

	for i, child := range node.Content {
		newNode.Content[i] = deepCopyNode(child)
	}

	return newNode
}

// showDiff displays differences between original and encrypted values
func showDiff(data *yaml.Node, key, operation string, unsecureDiff bool, debug bool) {
	if data == nil || len(data.Content) == 0 {
		debugLog(debug, "showDiff: data is nil or empty")
		return
	}

	// Setting global variable for masking in logs
	unsecureDiffLog = unsecureDiff

	debugLog(debug, "Starting showDiff with operation: %s, unsecureDiff: %v", operation, unsecureDiff)
	debugLog(debug, "Initial data content length: %d", len(data.Content))

	// Create deep copies of data for comparison
	originalData := deepCopyNode(data)
	encryptedData := deepCopyNode(data)

	debugLog(debug, "Original data content length: %d", len(originalData.Content))
	debugLog(debug, "Encrypted data content length: %d", len(encryptedData.Content))

	// Load rules
	rules, _, err := loadRules(".yed_config.yml", debug)
	if err != nil {
		debugLog(debug, "Error loading rules: %v", err)
		return
	}

	if len(rules) == 0 {
		debugLog(debug, "No rules defined, no encryption will be performed")
		fmt.Println("No rules defined in .yed_config.yml, no encryption will be performed.")
		return
	}

	// Process original data
	debugLog(debug, "Processing original data")
	processNodeForDiff(originalData.Content[0], key, operation, true, debug)

	// Process encrypted data
	debugLog(debug, "Processing encrypted data")

	// Create a map to track paths that should be excluded from processing
	excludedPaths := make(map[string]bool)

	// First, identify all paths that should be excluded based on action: none rules
	for _, rule := range rules {
		if rule.Action == ActionNone {
			debugLog(debug, "Marking paths for exclusion based on rule: %s", rule.Name)
			if err := markExcludedPaths(encryptedData.Content[0], rule, "", excludedPaths, debug); err != nil {
				debugLog(debug, "Error marking excluded paths: %v", err)
			}
		}
	}

	// Then process all rules, skipping excluded paths
	for _, rule := range rules {
		if rule.Action != ActionNone {
			debugLog(debug, "Processing rule: %s", rule.Name)
			if err := processYAMLWithExclusions(encryptedData.Content[0], key, operation, rule, "", make(map[string]bool), excludedPaths, debug); err != nil {
				debugLog(debug, "Error processing YAML: %v", err)
			}
		}
	}

	// Output differences
	debugLog(debug, "Printing differences")
	printDiff(originalData.Content[0], encryptedData.Content[0], debug, unsecureDiff, "")
	debugLog(debug, "Finished showDiff")
}

// processScalarNodeForDiff processes a scalar node for displaying differences
func processScalarNodeForDiff(node *yaml.Node, key, operation string, isOriginal bool, debug bool) {
	// Mask value for debug output, but keep original value for processing
	displayValue := node.Value
	if isSensitiveValue(displayValue) {
		displayValue = MaskedValue
	}

	debugLog(debug, "processNodeForDiff: Processing scalar node with value: '%s'", displayValue)

	if !isOriginal {
		// For encrypted data, apply the operation
		switch {
		case operation == OperationEncrypt && !strings.HasPrefix(node.Value, AES):
			debugLog(debug, "processNodeForDiff: Encrypting value")
			encryptedValue, err := encryption.Encrypt(key, node.Value)
			if err == nil {
				node.Value = AES + encryptedValue
				debugLog(debug, "processNodeForDiff: Value encrypted successfully")
			} else {
				debugLog(debug, "processNodeForDiff: Encryption error: %v", err)
			}
		case operation == OperationDecrypt && strings.HasPrefix(node.Value, AES):
			debugLog(debug, "processNodeForDiff: Decrypting value")
			decryptedBuffer, err := encryption.Decrypt(key, strings.TrimPrefix(node.Value, AES))
			if err == nil {
				node.Value = string(decryptedBuffer.Bytes())
				debugLog(debug, "processNodeForDiff: Value decrypted successfully")
			} else {
				debugLog(debug, "processNodeForDiff: Decryption error: %v", err)
			}
		default:
			debugLog(debug, "processNodeForDiff: No operation needed for value")
		}
	} else {
		debugLog(debug, "processNodeForDiff: Original data, no operation needed")
	}
}

// isSensitiveValue determines if a value is sensitive
// We consider sensitive all strings that are not AES256 labels and longer than 6 characters
// If unsecureDiff == true, then we don't consider values as sensitive
var unsecureDiffLog bool = false // Global variable to store unsecureDiff value

func isSensitiveValue(value string) bool {
	if unsecureDiffLog {
		return false // Don't mask anything if unsecureDiffLog is true
	}
	return !strings.HasPrefix(value, AES) && len(value) > MinEncryptedLength
}

// processSequenceNodeForDiff processes a sequence node for displaying differences
func processSequenceNodeForDiff(node *yaml.Node, key, operation string, isOriginal bool, debug bool) {
	debugLog(debug, "processNodeForDiff: Processing sequence node with %d items", len(node.Content))
	for i, child := range node.Content {
		debugLog(debug, "processNodeForDiff: Processing sequence item %d", i)
		processNodeForDiff(child, key, operation, isOriginal, debug)
	}
}

// processMappingNodeForDiff processes a mapping node for displaying differences
func processMappingNodeForDiff(node *yaml.Node, key, operation string, isOriginal bool, debug bool) {
	debugLog(debug, "processNodeForDiff: Processing mapping node with %d pairs", len(node.Content)/KeyValuePairSize)
	for i := 0; i < len(node.Content); i += 2 {
		if i+1 < len(node.Content) {
			keyNode := node.Content[i]
			valueNode := node.Content[i+1]
			debugLog(debug, "processNodeForDiff: Processing mapping pair with key: '%s'", keyNode.Value)
			processNodeForDiff(valueNode, key, operation, isOriginal, debug)
		}
	}
}

// processNodeForDiff processes a node for displaying differences
func processNodeForDiff(node *yaml.Node, key, operation string, isOriginal bool, debug bool) {
	if node == nil {
		debugLog(debug, "processNodeForDiff: received nil node")
		return
	}

	debugLog(debug, "processNodeForDiff: Processing node of kind: %v", node.Kind)

	switch node.Kind {
	case yaml.ScalarNode:
		processScalarNodeForDiff(node, key, operation, isOriginal, debug)
	case yaml.SequenceNode:
		processSequenceNodeForDiff(node, key, operation, isOriginal, debug)
	case yaml.MappingNode:
		processMappingNodeForDiff(node, key, operation, isOriginal, debug)
	default:
		debugLog(debug, "processNodeForDiff: Unsupported node kind: %v", node.Kind)
	}
}

// printDiff prints the differences between two YAML nodes
func printDiff(original, processed *yaml.Node, debug bool, unsecureDiff bool, path string) {
	if original == nil || processed == nil {
		return
	}

	switch original.Kind {
	case yaml.MappingNode:
		printMappingDiff(original, processed, debug, unsecureDiff, path)
	case yaml.SequenceNode:
		printSequenceDiff(original, processed, debug, unsecureDiff, path)
	case yaml.ScalarNode:
		printScalarDiff(original, processed, debug, unsecureDiff, path)
	}
}

func printMappingDiff(original, processed *yaml.Node, debug bool, unsecureDiff bool, path string) {
	for i := 0; i < len(original.Content); i += 2 {
		if i+1 >= len(original.Content) || i+1 >= len(processed.Content) {
			continue
		}

		keyNode := original.Content[i]
		originalValue := original.Content[i+1]
		processedValue := processed.Content[i+1]

		var newPath string
		if path == "" {
			newPath = keyNode.Value
		} else {
			newPath = path + "." + keyNode.Value
		}

		printDiff(originalValue, processedValue, debug, unsecureDiff, newPath)
	}
}

func printSequenceDiff(original, processed *yaml.Node, debug bool, unsecureDiff bool, path string) {
	for i := 0; i < len(original.Content); i++ {
		if i >= len(processed.Content) {
			break
		}

		newPath := fmt.Sprintf("%s[%d]", path, i)
		printDiff(original.Content[i], processed.Content[i], debug, unsecureDiff, newPath)
	}
}

func printScalarDiff(original, processed *yaml.Node, debug bool, unsecureDiff bool, path string) {
	if original.Value != processed.Value {
		originalValue := original.Value
		processedValue := processed.Value
		operation := ""

		// Determine the operation (encryption or decryption)
		if strings.HasPrefix(processedValue, AES) && !strings.HasPrefix(originalValue, AES) {
			operation = OperationEncrypt
		} else if !strings.HasPrefix(processedValue, AES) && strings.HasPrefix(originalValue, AES) {
			operation = OperationDecrypt
		}

		// Mask values if unsecureDiff is disabled
		if !unsecureDiff {
			if operation == OperationEncrypt {
				// Mask original value during encryption completely
				originalValue = MaskedValue

				// Mask encrypted value
				if strings.HasPrefix(processedValue, AES) {
					processedValue = maskEncryptedValue(processedValue, debug, path)
				}
			} else if operation == OperationDecrypt {
				// Mask decrypted value during decryption completely
				processedValue = MaskedValue

				// Keep encrypted value masked
				if strings.HasPrefix(originalValue, AES) {
					originalValue = maskEncryptedValue(originalValue, debug, path)
				}
			}
		}

		// Display with line numbers
		fmt.Printf("%s:\n  [%d] - %s\n  [%d] + %s\n", path, original.Line, originalValue, processed.Line, processedValue)
	}
}

// processDiff processes YAML content and shows differences
func processDiff(content []byte, config Config) error {
	debugLog(config.Debug, "Processing diff")

	// Parse original YAML
	var originalData yaml.Node
	if err := yaml.Unmarshal(content, &originalData); err != nil {
		return fmt.Errorf("error parsing original YAML: %w", err)
	}

	// Create a deep copy for encryption
	encryptedData := deepCopyNode(&originalData)

	// Process the encrypted copy
	processedPaths := make(map[string]bool)
	if _, err := processYAMLContent(content, config.Key, OperationEncrypt, config.Encryption.Rules, processedPaths, config.Debug); err != nil {
		return fmt.Errorf("error processing YAML content: %w", err)
	}

	// Output differences
	debugLog(config.Debug, "Printing differences")
	printDiff(originalData.Content[0], encryptedData.Content[0], config.Debug, config.Encryption.UnsecureDiff, "")
	debugLog(config.Debug, "Finished showDiff")

	return nil
}

// markExcludedPaths marks paths that should be excluded based on rules
func markExcludedPaths(node *yaml.Node, rule Rule, currentPath string, excludedPaths map[string]bool, debug bool) error {
	if node == nil {
		return nil
	}

	switch node.Kind {
	case yaml.MappingNode:
		return markExcludedPathsMapping(node, rule, currentPath, excludedPaths, debug)
	case yaml.SequenceNode:
		return markExcludedPathsSequence(node, rule, currentPath, excludedPaths, debug)
	}

	return nil
}

func markExcludedPathsMapping(node *yaml.Node, rule Rule, currentPath string, excludedPaths map[string]bool, debug bool) error {
	for i := 0; i < len(node.Content); i += 2 {
		if i+1 >= len(node.Content) {
			continue
		}

		keyNode := node.Content[i]
		valueNode := node.Content[i+1]

		var newPath string
		if currentPath == "" {
			newPath = keyNode.Value
		} else {
			newPath = currentPath + "." + keyNode.Value
		}

		if matchesRule(newPath, rule, debug) {
			debugLog(debug, "Marking path for exclusion: %s", newPath)
			excludedPaths[newPath] = true
		}

		if err := markExcludedPaths(valueNode, rule, newPath, excludedPaths, debug); err != nil {
			return err
		}
	}
	return nil
}

func markExcludedPathsSequence(node *yaml.Node, rule Rule, currentPath string, excludedPaths map[string]bool, debug bool) error {
	for i, item := range node.Content {
		newPath := fmt.Sprintf("%s[%d]", currentPath, i)
		if err := markExcludedPaths(item, rule, newPath, excludedPaths, debug); err != nil {
			return err
		}
	}
	return nil
}

// processYAMLWithExclusions processes YAML content while respecting excluded paths
func processYAMLWithExclusions(node *yaml.Node, key, operation string, rule Rule, currentPath string, processedPaths, excludedPaths map[string]bool, debug bool) error {
	if node == nil {
		return nil
	}

	// Skip if path is excluded
	if excludedPaths[currentPath] {
		debugLog(debug, "Skipping excluded path: %s", currentPath)
		return nil
	}

	switch node.Kind {
	case yaml.MappingNode:
		return processMappingNodeWithExclusions(node, key, operation, rule, currentPath, processedPaths, excludedPaths, debug)
	case yaml.SequenceNode:
		return processSequenceNodeWithExclusions(node, key, operation, rule, currentPath, processedPaths, excludedPaths, debug)
	case yaml.ScalarNode:
		return processScalarNodeWithExclusions(node, key, operation, rule, currentPath, processedPaths, excludedPaths, debug)
	}

	return nil
}

func processMappingNodeWithExclusions(node *yaml.Node, key, operation string, rule Rule, currentPath string, processedPaths, excludedPaths map[string]bool, debug bool) error {
	for i := 0; i < len(node.Content); i += 2 {
		if i+1 >= len(node.Content) {
			continue
		}

		keyNode := node.Content[i]
		valueNode := node.Content[i+1]

		var newPath string
		if currentPath == "" {
			newPath = keyNode.Value
		} else {
			newPath = currentPath + "." + keyNode.Value
		}

		if err := processYAMLWithExclusions(valueNode, key, operation, rule, newPath, processedPaths, excludedPaths, debug); err != nil {
			return err
		}
	}
	return nil
}

func processSequenceNodeWithExclusions(node *yaml.Node, key, operation string, rule Rule, currentPath string, processedPaths, excludedPaths map[string]bool, debug bool) error {
	for i, item := range node.Content {
		newPath := fmt.Sprintf("%s[%d]", currentPath, i)
		if err := processYAMLWithExclusions(item, key, operation, rule, newPath, processedPaths, excludedPaths, debug); err != nil {
			return err
		}
	}
	return nil
}

func processScalarNodeWithExclusions(node *yaml.Node, key, operation string, rule Rule, currentPath string, processedPaths, excludedPaths map[string]bool, debug bool) error {
	if !excludedPaths[currentPath] && matchesRule(currentPath, rule, debug) {
		debugLog(debug, "Processing scalar node at path: %s", currentPath)

		// Process multiline nodes first
		processed, err := ProcessMultilineNode(node, currentPath, key, operation, debug)
		if err != nil {
			return fmt.Errorf("failed to process multiline node at path %s: %w", currentPath, err)
		}

		// If the node was processed as multiline, mark it and return
		if processed {
			processedPaths[currentPath] = true
			debugLog(debug, "Successfully processed multiline node at path %s", currentPath)
			return nil
		}

		// Standard processing for regular nodes
		processedPaths[currentPath] = true

		switch operation {
		case OperationEncrypt:
			if !strings.HasPrefix(node.Value, AES) {
				encrypted, err := encryption.Encrypt(key, node.Value)
				if err != nil {
					return fmt.Errorf("failed to encrypt value at path %s: %w", currentPath, err)
				}
				node.Value = AES + encrypted
			}
		case OperationDecrypt:
			if strings.HasPrefix(node.Value, AES) {
				debugLog(debug, "Processing encrypted node with value: %s", maskEncryptedValue(node.Value, debug, currentPath))

				// Decrypt value
				decryptedBuffer, err := encryption.Decrypt(key, strings.TrimPrefix(node.Value, AES))
				if err != nil {
					debugLog(debug, "Error decrypting value: %v", err)
					return err
				}
				defer decryptedBuffer.Destroy() // Clean up the protected buffer

				// Set decrypted value
				decrypted := string(decryptedBuffer.Bytes())
				debugLog(debug, "Decrypted value: %s", decrypted)
				node.Value = decrypted

				// Mark path as processed
				if processedPaths != nil {
					processedPaths[currentPath] = true
				}
			}
		}
	}
	return nil
}

// LoadRules loads encryption rules from a config file
func LoadRules(configFile string, debug bool) ([]Rule, *Config, error) {
	debugLog(debug, "Loading rules from config file: %s", configFile)

	// Read config file
	content, err := os.ReadFile(configFile)
	if err != nil {
		return nil, nil, fmt.Errorf("error reading config file: %w", err)
	}

	// Parse config
	var config Config
	if err := yaml.Unmarshal(content, &config); err != nil {
		return nil, nil, fmt.Errorf("error parsing config file: %w", err)
	}

	// Validate rules
	for _, rule := range config.Encryption.Rules {
		if rule.Block == "" {
			return nil, nil, fmt.Errorf("rule '%s' is missing block", rule.Name)
		}
		if rule.Pattern == "" {
			return nil, nil, fmt.Errorf("rule '%s' is missing pattern", rule.Name)
		}
	}

	return config.Encryption.Rules, &config, nil
}

// ProcessYAMLContent processes YAML content with the given rules
func ProcessYAMLContent(content []byte, key, operation string, rules []Rule, processedPaths map[string]bool, debug bool) (*yaml.Node, error) {
	debugLog(debug, "Processing YAML content with %d rules", len(rules))

	// Parse YAML content
	var node yaml.Node
	if err := yaml.Unmarshal(content, &node); err != nil {
		debugLog(debug, "Error parsing YAML content: %v", err)
		return nil, fmt.Errorf("error parsing YAML content: %w", err)
	}

	if node.Kind != yaml.DocumentNode || len(node.Content) == 0 {
		debugLog(debug, "Invalid YAML document structure")
		return nil, fmt.Errorf("invalid YAML document structure")
	}

	// Process the root node
	rootNode := node.Content[0]
	if err := processNode(rootNode, "", key, operation, rules, processedPaths, debug); err != nil {
		return nil, err
	}

	return &node, nil
}

// ProcessDiff processes a file and shows differences between original and processed content
func ProcessDiff(filePath, key, operation string, debug bool) error {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("error reading file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(content, &config); err != nil {
		return fmt.Errorf("error parsing config: %w", err)
	}

	return processDiff(content, config)
}

// SetKeyDerivationAlgorithm sets the algorithm to use for encryption
func SetKeyDerivationAlgorithm(algorithm encryption.KeyDerivationAlgorithm) {
	CurrentKeyDerivationAlgorithm = algorithm
}
