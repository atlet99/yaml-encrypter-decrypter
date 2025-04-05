package processor

import (
	"bufio"
	"fmt"
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
func maskEncryptedValue(value string, debug bool) string {
	if !strings.HasPrefix(value, AES) {
		return value
	}

	encrypted := strings.TrimPrefix(value, AES)

	// In debug mode we show the full value
	if debug {
		return AES + encrypted
	}

	// In other modes we shorten the value
	if len(encrypted) <= 6 {
		return AES + encrypted
	}

	// Keep first 3 characters, add *** and last 3 characters
	return AES + encrypted[:3] + "***" + encrypted[len(encrypted)-3:]
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
func ProcessFile(filename, key, operation string, dryRun, debug, diff bool) error {
	if operation != OperationEncrypt && operation != OperationDecrypt {
		return fmt.Errorf("invalid operation: %s", operation)
	}

	debugLog(debug, "Processing file: %s with operation: %s", filename, operation)
	debugLog(debug, "Options: dryRun=%v, debug=%v, diff=%v", dryRun, debug, diff)

	// Load encryption rules
	rules, config, err := loadRules(".yed_config.yml", debug)
	if err != nil {
		debugLog(debug, "Error loading rules: %v", err)
		return fmt.Errorf("error loading rules: %w", err)
	}

	if len(rules) == 0 {
		debugLog(debug, "No rules defined, no encryption will be performed")
		if dryRun {
			fmt.Println("No rules defined in .yed_config.yml, no encryption will be performed.")
			return nil
		}
	}

	// Read YAML file with buffering
	data, err := readYAMLWithBuffer(filename)
	if err != nil {
		debugLog(debug, "Error reading YAML file: %v", err)
		return fmt.Errorf("error reading YAML file: %w", err)
	}

	if data == nil || len(data.Content) == 0 {
		debugLog(debug, "Invalid YAML structure: empty document")
		return fmt.Errorf("invalid YAML structure: empty document")
	}

	debugLog(debug, "Successfully read YAML file: %s", filename)

	// Create temporary buffer for operations
	tempBuffer := make([]byte, 0, DefaultBufferSize)
	defer secureClear(tempBuffer)

	// Process YAML file
	start := time.Now()
	processedPaths := make(map[string]bool)

	if dryRun && diff {
		// In diff mode we don't process the original data
		fmt.Println("Dry-run mode: The following changes would be applied:")
		fmt.Println("Diff mode: Showing changes between original and encrypted values:")

		if config.Encryption.UnsecureDiff {
			fmt.Println("WARNING: unsecure_diff is enabled. This is not secure as it shows actual encrypted values.")
		}

		showDiff(data, key, operation, config.Encryption.UnsecureDiff, debug)
	} else {
		// Process rules in parallel for large files
		if len(data.Content) > LargeFileThreshold {
			debugLog(debug, "Large file detected, processing rules in parallel")
			errChan := make(chan error, len(rules))
			var wg sync.WaitGroup
			wg.Add(len(rules))

			for _, rule := range rules {
				go func(r Rule) {
					defer wg.Done()
					debugLog(debug, "Applying rule: Block='%s', Pattern='%s', Action='%s'", r.Block, r.Pattern, r.Action)
					err := processYAML(data.Content[0], key, operation, r, "", processedPaths, debug)
					if err != nil {
						errChan <- fmt.Errorf("error processing YAML: %v", err)
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
				debugLog(debug, "Errors during parallel processing: %s", strings.Join(errors, "; "))
				return fmt.Errorf("errors during parallel processing: %s", strings.Join(errors, "; "))
			}
		} else {
			// Sequential processing for small files
			debugLog(debug, "Small file detected, processing rules sequentially")

			// First apply rules with action: none
			for _, rule := range rules {
				if rule.Action == "none" {
					debugLog(debug, "Applying rule with action=none: Block='%s', Pattern='%s'", rule.Block, rule.Pattern)
					err := processYAML(data.Content[0], key, operation, rule, "", processedPaths, debug)
					if err != nil {
						debugLog(debug, "Error processing YAML: %v", err)
						return fmt.Errorf("error processing YAML: %v", err)
					}
				}
			}

			// Then apply the remaining rules
			for _, rule := range rules {
				if rule.Action != "none" {
					debugLog(debug, "Applying rule: Block='%s', Pattern='%s', Action='%s'", rule.Block, rule.Pattern, rule.Action)
					err := processYAML(data.Content[0], key, operation, rule, "", processedPaths, debug)
					if err != nil {
						debugLog(debug, "Error processing YAML: %v", err)
						return fmt.Errorf("error processing YAML: %v", err)
					}
				}
			}
		}

		// Output results
		elapsed := time.Since(start)
		debugLog(debug, "YAML processing completed in %v", elapsed)
		fmt.Printf("YAML processing completed in %v\n", elapsed)

		if dryRun {
			// Regular dry-run mode: output YAML with masked values
			debugLog(debug, "Dry-run mode: outputting YAML with masked values")
			output := &strings.Builder{}
			encoder := yaml.NewEncoder(output)
			encoder.SetIndent(DefaultIndent)

			// Create a copy of data for masking
			maskedData := *data
			if len(maskedData.Content) > 0 {
				maskNodeValues(maskedData.Content[0])
			}

			if err := encoder.Encode(&maskedData); err != nil {
				debugLog(debug, "Error encoding YAML: %v", err)
				return fmt.Errorf("error encoding YAML: %w", err)
			}
			fmt.Println(output.String())
		} else {
			// Write updated YAML back to file with buffering
			debugLog(debug, "Writing updated YAML back to file: %s", filename)
			if err := writeYAMLWithBuffer(filename, data); err != nil {
				debugLog(debug, "Error writing YAML file: %v", err)
				return fmt.Errorf("error writing YAML file: %w", err)
			}
			fmt.Printf("File %s updated successfully.\n", filename)
		}
	}

	// Clear sensitive data
	if len(data.Content) > 0 {
		debugLog(debug, "Clearing sensitive data")
		clearNodeData(data.Content[0])
	}

	// Clear regex cache after processing
	debugLog(debug, "Clearing regex cache")
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
			node.Value = maskEncryptedValue(node.Value, false)
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

func loadRules(configFile string, debug bool) ([]Rule, *Config, error) {
	debugLog(debug, "Loading rules from config file: %s", configFile)

	// Check if config file exists
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		debugLog(debug, "Config file %s does not exist, no rules will be applied", configFile)
		return []Rule{}, &Config{}, nil
	}

	// Read config file
	data, err := os.ReadFile(configFile)
	if err != nil {
		debugLog(debug, "Error reading config file: %v", err)
		return nil, nil, fmt.Errorf("error reading config file: %w", err)
	}

	// Parse config
	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		debugLog(debug, "Error parsing config file: %v", err)
		return nil, nil, fmt.Errorf("error parsing config file: %w", err)
	}

	// Validate rules
	if len(config.Encryption.Rules) == 0 {
		debugLog(debug, "No rules defined in config file")
		return []Rule{}, &config, nil
	}

	debugLog(debug, "Loaded %d rules from config file", len(config.Encryption.Rules))
	for i, rule := range config.Encryption.Rules {
		debugLog(debug, "Rule %d: Block='%s', Pattern='%s', Action='%s'", i+1, rule.Block, rule.Pattern, rule.Action)
	}

	return config.Encryption.Rules, &config, nil
}

func processYAML(node *yaml.Node, key, operation string, rule Rule, currentPath string, processedPaths map[string]bool, debug bool) error {
	if node == nil {
		return fmt.Errorf("nil node encountered at path: %s", currentPath)
	}

	debugLog(debug, "Processing node at path: %s with rule: %s (Block='%s', Pattern='%s', Action='%s')",
		currentPath, rule.Name, rule.Block, rule.Pattern, rule.Action)

	switch node.Kind {
	case yaml.MappingNode:
		if len(node.Content)%2 != 0 {
			return fmt.Errorf("invalid mapping node at path: %s", currentPath)
		}
		return processMappingNodeContent(node, key, operation, rule, currentPath, processedPaths, debug)

	case yaml.SequenceNode:
		return processSequenceNodeContent(node, key, operation, rule, currentPath, processedPaths, debug)

	case yaml.ScalarNode:
		// Check if the path matches the rule
		if matchesRule(currentPath, rule, debug) {
			debugLog(debug, "Path '%s' matches rule '%s'", currentPath, rule.Name)

			// Check exclusions
			if rule.Exclude != "" {
				excludePattern := rule.Exclude

				// Replace ** with .* for recursive search
				excludePattern = strings.ReplaceAll(excludePattern, "**", ".*")

				// Replace single * with [^.]* for single level search
				excludePattern = strings.ReplaceAll(excludePattern, "*", "[^.]*")

				// Add start and end of string
				excludePattern = "^" + excludePattern + "$"

				// Compile regular expression
				re, err := regexp.Compile(excludePattern)
				if err == nil && re.MatchString(currentPath) {
					debugLog(debug, "Path '%s' matches exclude pattern '%s', skipping", currentPath, rule.Exclude)
					return nil
				}
			}

			// If action: none, mark the path as processed and skip
			if rule.Action == "none" {
				debugLog(debug, "Rule '%s' has action='none', skipping path '%s'", rule.Name, currentPath)
				processedPaths[currentPath] = true
				return nil
			}

			processedPaths[currentPath] = true
			return processScalarNode(node, currentPath, key, operation, debug)
		} else {
			debugLog(debug, "Path '%s' does not match rule '%s'", currentPath, rule.Name)
		}
		return nil

	default:
		return fmt.Errorf("unsupported node kind: %v at path: %s", node.Kind, currentPath)
	}
}

func processMappingNodeContent(node *yaml.Node, key, operation string, rule Rule, currentPath string, processedPaths map[string]bool, debug bool) error {
	for i := 0; i < len(node.Content); i += 2 {
		keyNode := node.Content[i]
		valueNode := node.Content[i+1]
		keyPath := currentPath
		if keyPath != "" {
			keyPath += "."
		}
		keyPath += keyNode.Value

		debugLog(debug, "Processing mapping key: '%s' at path: '%s'", keyNode.Value, keyPath)

		if processedPaths[keyPath] {
			debugLog(debug, "Path '%s' already processed, skipping", keyPath)
			continue
		}

		// Check if the path matches the rule
		if matchesRule(keyPath, rule, debug) {
			debugLog(debug, "Path '%s' matches rule '%s'", keyPath, rule.Name)

			// Check exclusions
			if rule.Exclude != "" {
				excludePattern := rule.Exclude

				// Replace ** with .* for recursive search
				excludePattern = strings.ReplaceAll(excludePattern, "**", ".*")

				// Replace single * with [^.]* for single level search
				excludePattern = strings.ReplaceAll(excludePattern, "*", "[^.]*")

				// Add start and end of string
				excludePattern = "^" + excludePattern + "$"

				// Compile regular expression
				re, err := regexp.Compile(excludePattern)
				if err == nil && re.MatchString(keyPath) {
					debugLog(debug, "Path '%s' matches exclude pattern '%s', skipping", keyPath, rule.Exclude)
					continue
				}
			}

			// If action: none, mark the path and all its nested paths as processed
			if rule.Action == "none" {
				debugLog(debug, "Rule '%s' has action='none', marking path '%s' and all nested paths as processed", rule.Name, keyPath)
				processedPaths[keyPath] = true
				// Recursively mark all nested paths as processed
				markNestedPathsAsProcessed(valueNode, keyPath, processedPaths, debug)
				continue
			}

			processedPaths[keyPath] = true
			if err := processYAML(valueNode, key, operation, rule, keyPath, processedPaths, debug); err != nil {
				return err
			}
		} else {
			debugLog(debug, "Path '%s' does not match rule '%s'", keyPath, rule.Name)
			// Process nested paths only if the path hasn't been processed
			if !processedPaths[keyPath] {
				if err := processYAML(valueNode, key, operation, rule, keyPath, processedPaths, debug); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// markNestedPathsAsProcessed recursively marks all nested paths as processed
func markNestedPathsAsProcessed(node *yaml.Node, currentPath string, processedPaths map[string]bool, debug bool) {
	if node == nil {
		return
	}

	switch node.Kind {
	case yaml.MappingNode:
		for i := 0; i < len(node.Content); i += 2 {
			if i+1 < len(node.Content) {
				keyNode := node.Content[i]
				valueNode := node.Content[i+1]
				keyPath := currentPath
				if keyPath != "" {
					keyPath += "."
				}
				keyPath += keyNode.Value
				processedPaths[keyPath] = true
				markNestedPathsAsProcessed(valueNode, keyPath, processedPaths, debug)
			}
		}
	case yaml.SequenceNode:
		for i, item := range node.Content {
			itemPath := fmt.Sprintf("%s[%d]", currentPath, i)
			processedPaths[itemPath] = true
			markNestedPathsAsProcessed(item, itemPath, processedPaths, debug)
		}
	case yaml.ScalarNode:
		processedPaths[currentPath] = true
	}
}

func processSequenceNodeContent(node *yaml.Node, key, operation string, rule Rule, currentPath string, processedPaths map[string]bool, debug bool) error {
	for i, item := range node.Content {
		itemPath := fmt.Sprintf("%s[%d]", currentPath, i)

		debugLog(debug, "Processing sequence item %d at path: '%s'", i, itemPath)

		if processedPaths[itemPath] {
			debugLog(debug, "Path '%s' already processed, skipping", itemPath)
			continue
		}

		// Check if the path matches the rule
		if matchesRule(itemPath, rule, debug) {
			debugLog(debug, "Path '%s' matches rule '%s'", itemPath, rule.Name)

			// Check exclusions
			if rule.Exclude != "" {
				excludePattern := rule.Exclude

				// Replace ** with .* for recursive search
				excludePattern = strings.ReplaceAll(excludePattern, "**", ".*")

				// Replace single * with [^.]* for single level search
				excludePattern = strings.ReplaceAll(excludePattern, "*", "[^.]*")

				// Add start and end of string
				excludePattern = "^" + excludePattern + "$"

				// Compile regular expression
				re, err := regexp.Compile(excludePattern)
				if err == nil && re.MatchString(itemPath) {
					debugLog(debug, "Path '%s' matches exclude pattern '%s', skipping", itemPath, rule.Exclude)
					continue
				}
			}

			// If action: none, mark the path and all its nested paths as processed
			if rule.Action == "none" {
				debugLog(debug, "Rule '%s' has action='none', marking path '%s' and all nested paths as processed", rule.Name, itemPath)
				processedPaths[itemPath] = true
				// Recursively mark all nested paths as processed
				markNestedPathsAsProcessed(item, itemPath, processedPaths, debug)
				continue
			}

			processedPaths[itemPath] = true
			if err := processYAML(item, key, operation, rule, itemPath, processedPaths, debug); err != nil {
				return err
			}
		} else {
			debugLog(debug, "Path '%s' does not match rule '%s'", itemPath, rule.Name)
			// Process nested paths only if the path hasn't been processed
			if !processedPaths[itemPath] {
				if err := processYAML(item, key, operation, rule, itemPath, processedPaths, debug); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// matchesRule checks if a path matches a rule
func matchesRule(path string, rule Rule, debug bool) bool {
	debugLog(debug, "Checking if path '%s' matches rule '%s'", path, rule.Name)

	// Split path into parts
	parts := strings.Split(path, ".")

	// Check if path starts with the block
	if rule.Block != "*" {
		if !strings.HasPrefix(path, rule.Block) {
			debugLog(debug, "Path '%s' does not start with block '%s'", path, rule.Block)
			return false
		}
	}

	// For pattern matching, we should check the last part of the path
	lastPart := parts[len(parts)-1]

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

// secureClear clears sensitive data from memory
func secureClear(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ProcessNode processes a YAML node
func ProcessNode(node *yaml.Node, path, key, operation string, debug bool) error {
	// Handle nil node
	if node == nil {
		return nil
	}

	// Process based on node kind
	switch node.Kind {
	case yaml.ScalarNode:
		return processScalarNode(node, path, key, operation, debug)
	case yaml.SequenceNode:
		return processSequenceNode(node, path, key, operation, debug)
	case yaml.MappingNode:
		return processMappingNode(node, path, key, operation, debug)
	case yaml.AliasNode:
		return fmt.Errorf("unsupported node kind: alias")
	default:
		return fmt.Errorf("unsupported node kind: %v", node.Kind)
	}
}

// processScalarNode processes a scalar node
func processScalarNode(node *yaml.Node, path, key, operation string, debug bool) error {
	if node == nil {
		return fmt.Errorf("nil node encountered at path: %s", path)
	}

	debugLog(debug, "Processing scalar node at path: %s", path)

	// Skip already encrypted values
	if strings.HasPrefix(node.Value, AES) {
		debugLog(debug, "Node at path '%s' is already encrypted, skipping", path)
		return nil
	}

	value := node.Value
	var err error

	switch operation {
	case OperationEncrypt:
		debugLog(debug, "Encrypting value at path '%s'", path)
		value, err = encryptValue(value, key)
	case OperationDecrypt:
		debugLog(debug, "Decrypting value at path '%s'", path)
		value, err = decryptValue(value, key)
	default:
		return fmt.Errorf("unsupported operation: %s", operation)
	}

	if err != nil {
		debugLog(debug, "Error processing value at path '%s': %v", path, err)
		return fmt.Errorf("error processing value at path %s: %v", path, err)
	}

	debugLog(debug, "Successfully processed value at path '%s'", path)
	node.Value = value
	return nil
}

// processSequenceNode processes a sequence node
func processSequenceNode(node *yaml.Node, path, key, operation string, debug bool) error {
	for i, item := range node.Content {
		if err := ProcessNode(item, fmt.Sprintf("%s[%d]", path, i), key, operation, debug); err != nil {
			return fmt.Errorf("error processing sequence item %d: %w", i, err)
		}
	}
	return nil
}

// processMappingNode processes a mapping node
func processMappingNode(node *yaml.Node, path, key, operation string, debug bool) error {
	for i := 0; i < len(node.Content); i += 2 {
		if i+1 >= len(node.Content) {
			return fmt.Errorf("invalid mapping node: odd number of items")
		}
		keyNode := node.Content[i]
		valueNode := node.Content[i+1]
		if err := ProcessNode(valueNode, fmt.Sprintf("%s.%s", path, keyNode.Value), key, operation, debug); err != nil {
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
	processedPaths := make(map[string]bool)
	for _, rule := range rules {
		debugLog(debug, "Applying rule: Block='%s', Pattern='%s', Action='%s'", rule.Block, rule.Pattern, rule.Action)
		err := processYAML(encryptedData.Content[0], key, operation, rule, "", processedPaths, debug)
		if err != nil {
			debugLog(debug, "Error processing YAML: %v", err)
		}
	}

	// Output differences
	debugLog(debug, "Printing differences")
	printDiff(originalData.Content[0], encryptedData.Content[0], unsecureDiff, debug, operation)
	debugLog(debug, "Finished showDiff")
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
		debugLog(debug, "processNodeForDiff: Processing scalar node with value: '%s'", node.Value)
		if !isOriginal {
			// For encrypted data apply the operation
			if operation == OperationEncrypt && !strings.HasPrefix(node.Value, AES) {
				debugLog(debug, "processNodeForDiff: Encrypting value")
				encryptedValue, err := encryption.Encrypt(key, node.Value)
				if err == nil {
					node.Value = AES + encryptedValue
					debugLog(debug, "processNodeForDiff: Value encrypted successfully")
				} else {
					debugLog(debug, "processNodeForDiff: Encryption error: %v", err)
				}
			} else if operation == OperationDecrypt && strings.HasPrefix(node.Value, AES) {
				debugLog(debug, "processNodeForDiff: Decrypting value")
				decryptedValue, err := encryption.Decrypt(key, strings.TrimPrefix(node.Value, AES))
				if err == nil {
					node.Value = decryptedValue
					debugLog(debug, "processNodeForDiff: Value decrypted successfully")
				} else {
					debugLog(debug, "processNodeForDiff: Decryption error: %v", err)
				}
			} else {
				debugLog(debug, "processNodeForDiff: No operation needed for value")
			}
		} else {
			debugLog(debug, "processNodeForDiff: Original data, no operation needed")
		}
	case yaml.SequenceNode:
		debugLog(debug, "processNodeForDiff: Processing sequence node with %d items", len(node.Content))
		for i, child := range node.Content {
			debugLog(debug, "processNodeForDiff: Processing sequence item %d", i)
			processNodeForDiff(child, key, operation, isOriginal, debug)
		}
	case yaml.MappingNode:
		debugLog(debug, "processNodeForDiff: Processing mapping node with %d pairs", len(node.Content)/2)
		for i := 0; i < len(node.Content); i += 2 {
			if i+1 < len(node.Content) {
				keyNode := node.Content[i]
				valueNode := node.Content[i+1]
				debugLog(debug, "processNodeForDiff: Processing mapping pair with key: '%s'", keyNode.Value)
				processNodeForDiff(valueNode, key, operation, isOriginal, debug)
			}
		}
	default:
		debugLog(debug, "processNodeForDiff: Unsupported node kind: %v", node.Kind)
	}
}

// printDiffNode recursively outputs differences between nodes
func printDiffNode(original, encrypted *yaml.Node, path string, unsecureDiff bool, debug bool, operation string) {
	if original == nil || encrypted == nil {
		debugLog(debug, "printDiffNode: Nil node encountered at path: %s", path)
		return
	}

	debugLog(debug, "printDiffNode: Processing path: %s", path)
	debugLog(debug, "printDiffNode: Original node kind: %v, Encrypted node kind: %v", original.Kind, encrypted.Kind)

	switch original.Kind {
	case yaml.ScalarNode:
		if encrypted.Kind == yaml.ScalarNode {
			// In debug mode don't show actual values in logs
			if debug {
				debugLog(debug, "printDiffNode: Comparing values at path %s: [MASKED] vs [MASKED]", path)
			} else {
				debugLog(debug, "printDiffNode: Comparing values at path %s: '%s' vs '%s'", path, original.Value, encrypted.Value)
			}

			if original.Value != encrypted.Value {
				debugLog(debug, "printDiffNode: Values differ at path %s", path)
				fmt.Printf("%s:\n", path)

				// Mask values depending on operation and unsecureDiff
				if operation == OperationEncrypt {
					// When encrypting mask the original value if unsecureDiff = false
					if unsecureDiff {
						fmt.Printf("  - %s\n", original.Value)
					} else {
						fmt.Printf("  - %s\n", strings.Repeat("*", 6))
					}

					// Always show encrypted value
					if strings.HasPrefix(encrypted.Value, AES) {
						fmt.Printf("  + %s\n", maskEncryptedValue(encrypted.Value, debug))
					} else {
						fmt.Printf("  + %s\n", encrypted.Value)
					}
				} else if operation == OperationDecrypt {
					// When decrypting show the original value
					if strings.HasPrefix(original.Value, AES) {
						fmt.Printf("  - %s\n", maskEncryptedValue(original.Value, debug))
					} else {
						fmt.Printf("  - %s\n", original.Value)
					}

					// Mask decrypted value if unsecureDiff = false
					if unsecureDiff {
						fmt.Printf("  + %s\n", encrypted.Value)
					} else {
						fmt.Printf("  + %s\n", strings.Repeat("*", 6))
					}
				}
			} else {
				debugLog(debug, "printDiffNode: Values are identical at path %s", path)
			}
		}
	case yaml.SequenceNode:
		if encrypted.Kind == yaml.SequenceNode {
			debugLog(debug, "printDiffNode: Processing sequence with %d items at path %s", len(original.Content), path)
			for i, child := range original.Content {
				if i < len(encrypted.Content) {
					childPath := fmt.Sprintf("%s[%d]", path, i)
					printDiffNode(child, encrypted.Content[i], childPath, unsecureDiff, debug, operation)
				} else {
					debugLog(debug, "printDiffNode: Encrypted sequence has fewer items than original at path %s", path)
				}
			}
		} else {
			debugLog(debug, "printDiffNode: Node kinds don't match at path %s: original=%v, encrypted=%v", path, original.Kind, encrypted.Kind)
		}
	case yaml.MappingNode:
		if encrypted.Kind == yaml.MappingNode {
			debugLog(debug, "printDiffNode: Processing mapping with %d pairs at path %s", len(original.Content)/2, path)
			for i := 0; i < len(original.Content); i += 2 {
				if i+1 < len(original.Content) && i+1 < len(encrypted.Content) {
					keyNode := original.Content[i]
					valueNode := original.Content[i+1]
					encryptedValueNode := encrypted.Content[i+1]

					childPath := path
					if path != "" {
						childPath += "."
					}
					childPath += keyNode.Value

					printDiffNode(valueNode, encryptedValueNode, childPath, unsecureDiff, debug, operation)
				} else {
					debugLog(debug, "printDiffNode: Encrypted mapping has fewer pairs than original at path %s", path)
				}
			}
		} else {
			debugLog(debug, "printDiffNode: Node kinds don't match at path %s: original=%v, encrypted=%v", path, original.Kind, encrypted.Kind)
		}
	default:
		debugLog(debug, "printDiffNode: Unsupported node kind: %v at path: %s", original.Kind, path)
	}
}

// printDiff outputs differences between original and encrypted data
func printDiff(original, encrypted *yaml.Node, unsecureDiff bool, debug bool, operation string) {
	if original == nil || encrypted == nil {
		debugLog(debug, "printDiff: received nil node")
		return
	}

	debugLog(debug, "printDiff: Starting comparison with operation: %s, unsecureDiff: %v", operation, unsecureDiff)
	printDiffNode(original, encrypted, "", unsecureDiff, debug, operation)
	debugLog(debug, "printDiff: Finished comparison")
}

func encryptValue(value, key string) (string, error) {
	if len(key) < MinKeyLength {
		return "", fmt.Errorf("key length must be at least %d characters", MinKeyLength)
	}
	encryptedValue, err := encryption.Encrypt(key, value)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt value: %w", err)
	}
	return AES + encryptedValue, nil
}

func decryptValue(value, key string) (string, error) {
	if !strings.HasPrefix(value, AES) {
		return "", fmt.Errorf("value is not encrypted")
	}
	decryptedValue, err := encryption.Decrypt(key, strings.TrimPrefix(value, AES))
	if err != nil {
		return "", fmt.Errorf("failed to decrypt value: %w", err)
	}
	return decryptedValue, nil
}
