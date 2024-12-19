package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"time"
	"yaml-encrypter-decrypter/pkg/encryption"

	"github.com/awnumar/memguard"
	"gopkg.in/yaml.v3"
)

const AES = "AES256:"

// Config structure for YAML parsing
type Config struct {
	Encryption struct {
		Key       string   `yaml:"key"`
		EnvBlocks []string `yaml:"env_blocks"`
	} `yaml:"encryption"`
	Logging struct {
		Level string `yaml:"level"`
	} `yaml:"logging"`
}

// Version is set during build time using -ldflags
var Version = "dev"

// Global debug flag
var debug bool

func init() {
	flag.BoolVar(&debug, "debug", false, "Enable debug mode")
	memguard.CatchInterrupt() // Handle interrupt signals securely
}

// debugLog logs messages only when debug mode is enabled
func debugLog(format string, v ...interface{}) {
	if debug {
		log.Printf("[DEBUG] "+format, v...)
	}
}

func main() {
	defer memguard.Purge() // Purge sensitive data when the program exits

	displayVersion := strings.ReplaceAll(Version, "_", " ")

	// Define command-line flags
	flagVersion := flag.Bool("version", false, "Show the version and exit")
	flagDryRun := flag.Bool("dry-run", false, "Output only, no file changes")
	flagFile := flag.String("filename", "", "File to encode/decode")
	var flagEnvBlocks []string
	flag.Func("env-blocks", "Comma-separated YAML blocks to encode/decode", func(s string) error {
		flagEnvBlocks = strings.Split(s, ",")
		return nil
	})
	flagValue := flag.String("value", "", "Single value for encryption/decryption")
	flagOperation := flag.String("operation", "", "Available operations: encrypt, decrypt")

	flag.Usage = func() {
		fmt.Printf("yed version: %s\nUsage:\n", displayVersion)
		flag.PrintDefaults()
	}

	flag.Parse()

	if *flagVersion {
		fmt.Printf("yed version: %s\n", displayVersion)
		return
	}

	log.SetFlags(0)

	// Load configuration
	config, err := loadConfig(".yed_config.yml")
	if err != nil {
		log.Fatalf("Error loading configuration: %v\n", err)
	}

	// Load encryption key securely
	encryptionKey := loadEncryptionKey(config)
	defer encryptionKey.Destroy() // Ensure the key is destroyed after use

	// Single value encryption/decryption
	if *flagValue != "" {
		handleValueWithTiming(encryptionKey, flagOperation, flagValue)
		return
	}

	if *flagOperation == "" {
		log.Fatal("Please specify operation: encrypt or decrypt")
	}

	if len(flagEnvBlocks) == 0 {
		flagEnvBlocks = config.Encryption.EnvBlocks
	}

	processYamlFile(*flagFile, flagEnvBlocks, encryptionKey, *flagOperation, *flagDryRun)
}

// loadConfig loads configuration from .yed_config.yml
func loadConfig(configFile string) (*Config, error) {
	var config Config

	file, err := os.Open(configFile)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("config file %s not found", configFile)
	} else if err != nil {
		return nil, fmt.Errorf("could not open config file: %v", err)
	}
	defer file.Close()

	debugLog("Loading configuration from %s", configFile)
	decoder := yaml.NewDecoder(file)
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("could not decode config YAML: %v", err)
	}

	debugLog("Loaded configuration: %+v", config)
	return &config, nil
}

// loadEncryptionKey securely loads the encryption key
func loadEncryptionKey(config *Config) *memguard.LockedBuffer {
	key := os.Getenv("YED_ENCRYPTION_KEY")
	if key == "" {
		key = config.Encryption.Key
	}
	if key == "" {
		log.Fatal("Missing encryption key. Set YED_ENCRYPTION_KEY or specify 'key' in .yed_config.yml")
	}

	return memguard.NewBufferFromBytes([]byte(key))
}

// handleValueWithTiming processes a single value for encryption/decryption
func handleValueWithTiming(key *memguard.LockedBuffer, flagOperation, flagValue *string) {
	start := time.Now()

	if *flagOperation == "decrypt" && strings.HasPrefix(*flagValue, AES) {
		decryptedValue, err := encryption.Decrypt(string(key.Bytes()), strings.TrimPrefix(*flagValue, AES))
		elapsed := time.Since(start)
		if err != nil {
			log.Fatalf("Error decrypting value: %v (Time taken: %v)", err, elapsed)
		}
		fmt.Printf("Decrypted value: %s\nTime taken: %v\n", decryptedValue, elapsed)
	} else if *flagOperation == "encrypt" {
		encryptedValue, err := encryption.Encrypt(string(key.Bytes()), *flagValue)
		elapsed := time.Since(start)
		if err != nil {
			log.Fatalf("Error encrypting value: %v (Time taken: %v)", err, elapsed)
		}
		fmt.Printf("Encrypted value: %s%s\nTime taken: %v\n", AES, encryptedValue, elapsed)
	} else {
		log.Fatal("Invalid operation. Use 'encrypt' or 'decrypt'.")
	}
}

// processYamlFile processes a YAML file for encryption/decryption
func processYamlFile(filename string, envBlocks []string, key *memguard.LockedBuffer, operation string, dryRun bool) {
	start := time.Now()

	// Read all lines from the file
	lines, err := readFile(filename)
	if err != nil {
		log.Fatalf("Error reading file: %v", err)
	}

	// Extract the key bytes from the locked buffer and convert to a string
	keyString := string(key.Bytes())

	var updatedLines []string
	var currentBlock []string
	var processingBlock bool

	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)

		// Detect the start of a new block
		if strings.HasSuffix(trimmedLine, "{") {
			if processingBlock {
				// Process the current block
				updatedBlock := processBlock(currentBlock, envBlocks, keyString, operation, dryRun)
				updatedLines = append(updatedLines, updatedBlock...)
			}

			processingBlock = true
			currentBlock = []string{line}
			continue
		}

		// Detect the end of a block
		if processingBlock && trimmedLine == "}" {
			currentBlock = append(currentBlock, line)
			// Process the current block
			updatedBlock := processBlock(currentBlock, envBlocks, keyString, operation, dryRun)
			updatedLines = append(updatedLines, updatedBlock...)
			processingBlock = false
			continue
		}

		// Add lines to the current block
		if processingBlock {
			currentBlock = append(currentBlock, line)
		} else {
			// Add lines outside the block
			updatedLines = append(updatedLines, line)
		}
	}

	elapsed := time.Since(start)
	fmt.Printf("YAML processing completed in %v\n", elapsed)

	if dryRun {
		// Dry-run mode: show changes without applying them
		fmt.Println("Dry-run mode enabled. The following changes would be applied:")
		for i := range lines { // Use index instead of line
			if i < len(updatedLines) && lines[i] != updatedLines[i] {
				fmt.Printf("- [%d]: %s\n+ [%d]: %s\n", i+1, strings.TrimSpace(lines[i]), i+1, strings.TrimSpace(updatedLines[i]))
			}
		}
	} else {
		// Write changes back to the file
		err := writeFile(filename, updatedLines)
		if err != nil {
			log.Fatalf("Error writing to file: %v", err)
		}
		fmt.Printf("File %s updated successfully.\n", filename)
	}
}

// processBlock handles encryption/decryption for a block
func processBlock(block []string, envBlocks []string, key, operation string, dryRun bool) []string {
	blockContent := parseBlockContent(block)

	debugLog("Processing block: %+v", blockContent)

	updatedBlock := make([]string, len(block))
	copy(updatedBlock, block)

	for _, envBlock := range envBlocks {
		pattern, condition := parseEnvBlock(envBlock)
		debugLog("Checking pattern: %s with condition: %s", pattern, condition)

		matched, targetKey := matchesPattern(blockContent, pattern)
		if matched && evaluateCondition(blockContent, condition) {
			debugLog("Pattern matched, processing key: %s", targetKey)
			for i, line := range updatedBlock {
				if strings.Contains(line, targetKey) {
					if isJSON(line) {
						updatedBlock[i] = processJSON(line, key, operation, dryRun)
					} else {
						updatedValue := processKey(block, blockContent, targetKey, key, operation, dryRun)
						if updatedValue != "" {
							updatedBlock[i] = updatedValue
						}
					}
					break
				}
			}
		} else {
			debugLog("Pattern did not match or condition not met for: %s", pattern)
		}
	}

	return updatedBlock
}

// isJSON checks if the line contains a JSON-like structure
func isJSON(line string) bool {
	return strings.Contains(line, "{") && strings.Contains(line, "}")
}

// processJSON encrypts/decrypts all values in a JSON structure
func processJSON(line, key, operation string, dryRun bool) string {
	// Extract JSON content from the line
	startIndex := strings.Index(line, "{")
	endIndex := strings.LastIndex(line, "}")
	if startIndex == -1 || endIndex == -1 {
		return line
	}

	jsonContent := line[startIndex : endIndex+1]
	var jsonMap map[string]string

	// Parse JSON-like structure
	err := json.Unmarshal([]byte(jsonContent), &jsonMap)
	if err != nil {
		debugLog("Failed to parse JSON content: %v", err)
		return line
	}

	// Process all values in the map
	for k, v := range jsonMap {
		if operation == "encrypt" {
			encryptedValue, err := encryption.Encrypt(key, v)
			if err == nil {
				jsonMap[k] = AES + encryptedValue
			}
		} else if operation == "decrypt" {
			if strings.HasPrefix(v, AES) {
				decryptedValue, err := encryption.Decrypt(key, strings.TrimPrefix(v, AES))
				if err == nil {
					jsonMap[k] = decryptedValue
				}
			}
		}
	}

	// Convert back to JSON
	updatedJSON, err := json.MarshalIndent(jsonMap, "", "  ")
	if err != nil {
		debugLog("Failed to marshal updated JSON: %v", err)
		return line
	}

	// Replace the original JSON content in the line
	return line[:startIndex] + string(updatedJSON) + line[endIndex+1:]
}

// processJSONStructure applies encryption/decryption to JSON-like structures recursively
func processJSONStructure(data interface{}, key, operation string, dryRun bool) interface{} {
	switch v := data.(type) {
	case map[string]interface{}:
		for k, val := range v {
			v[k] = processJSONStructure(val, key, operation, dryRun)
		}
		return v
	case []interface{}:
		for i, val := range v {
			v[i] = processJSONStructure(val, key, operation, dryRun)
		}
		return v
	case string:
		// Encrypt or decrypt string values
		if operation == "encrypt" {
			encryptedValue, err := encryption.Encrypt(key, v)
			if err != nil {
				log.Printf("Error encrypting value: %v", err)
				return v
			}
			return AES + encryptedValue
		} else if operation == "decrypt" && strings.HasPrefix(v, AES) {
			decryptedValue, err := encryption.Decrypt(key, strings.TrimPrefix(v, AES))
			if err != nil {
				log.Printf("Error decrypting value: %v", err)
				return v
			}
			return decryptedValue
		}
	}
	return data
}

// replaceValueInLine replaces the value of a key in a line while preserving formatting
func replaceValueInLine(line, key, newValue string) string {
	// Find the start of the value and replace it
	regex := regexp.MustCompile(fmt.Sprintf(`%s\s*=\s*.*`, key))
	return regex.ReplaceAllString(line, fmt.Sprintf("%s = %s", key, newValue))
}

// processKey encrypts/decrypts a specific key in the block
func processKey(block []string, blockContent map[string]string, targetKey, key, operation string, dryRun bool) string {
	value, exists := blockContent[targetKey]
	if !exists {
		debugLog("Target key %s not found in blockContent", targetKey)
		return ""
	}

	originalValue := value
	value = strings.Trim(value, `"'`)

	// Ignore empty values
	if value == "" {
		debugLog("Ignoring empty value for key: %s", targetKey)
		return ""
	}

	var processedValue string
	if operation == "encrypt" {
		encryptedValue, err := encryption.Encrypt(key, value)
		if err != nil {
			log.Fatalf("Error encrypting value: %v", err)
		}
		processedValue = AES + encryptedValue
	} else if operation == "decrypt" {
		if strings.HasPrefix(value, AES) {
			decryptedValue, err := encryption.Decrypt(key, strings.TrimPrefix(value, AES))
			if err != nil {
				log.Fatalf("Error decrypting value: %v", err)
			}
			processedValue = decryptedValue
		} else {
			log.Printf("Skipping decryption, value is not encrypted: %s", value)
			return ""
		}
	} else {
		log.Fatalf("Invalid operation: %v", operation)
	}

	// Preserve quotes if present in the original value
	if strings.HasPrefix(originalValue, `"`) || strings.HasPrefix(originalValue, `'`) {
		processedValue = fmt.Sprintf(`"%s"`, processedValue)
	}

	// Preserve original indentation and formatting
	for _, line := range block {
		if strings.Contains(line, targetKey) {
			indent := line[:strings.Index(line, targetKey)]
			return fmt.Sprintf("%s%s = %s", indent, targetKey, processedValue)
		}
	}

	return ""
}

// parseBlockContent parses the content of a block into a key-value map, supporting nested structures
func parseBlockContent(block []string) map[string]string {
	blockContent := make(map[string]string)
	currentKey := ""
	var nestedContent []string
	inNestedBlock := false

	for _, line := range block {
		trimmedLine := strings.TrimSpace(line)

		// Skip empty lines
		if trimmedLine == "" {
			continue
		}

		// Handle start of nested block
		if strings.HasSuffix(trimmedLine, "{") {
			inNestedBlock = true
			currentKey = strings.TrimSpace(strings.TrimSuffix(trimmedLine, "{"))
			nestedContent = []string{}
			continue
		}

		// Handle end of nested block
		if inNestedBlock && trimmedLine == "}" {
			inNestedBlock = false
			// Process the nested block recursively
			innerContent := parseBlockContent(nestedContent)
			for k, v := range innerContent {
				blockContent[fmt.Sprintf("%s.%s", currentKey, k)] = v
			}
			currentKey = ""
			continue
		}

		// Collect lines for the nested block
		if inNestedBlock {
			nestedContent = append(nestedContent, trimmedLine)
			continue
		}

		// Handle key=value pairs
		if strings.Contains(trimmedLine, "=") {
			parts := strings.SplitN(trimmedLine, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				blockContent[key] = value
			}
		}
	}

	return blockContent
}

// parseEnvBlock splits env_blocks into path and condition
func parseEnvBlock(envBlock string) (string, string) {
	parts := strings.SplitN(envBlock, " if ", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return envBlock, ""
}

// matchesPattern checks if any key in blockContent matches the given pattern.
// It dynamically matches normalized keys with the provided pattern.
func matchesPattern(blockContent map[string]string, pattern string) (bool, string) {
	debugLog("Matching pattern: %s against blockContent: %+v", pattern, blockContent)

	// Regular expression to extract the normalized key, e.g., "variable.key" -> "key"
	regex := regexp.MustCompile(`\b(\w+\.\w+)$`)

	// Iterate over all keys in blockContent
	for fullKey := range blockContent {
		// Normalize the key to extract only the "type.key" or "key" part
		normalizedKey := fullKey
		if matches := regex.FindStringSubmatch(fullKey); len(matches) == 2 {
			normalizedKey = matches[1] // Extract the last "type.key" format
		}

		// Compare the normalized key with the provided pattern
		if normalizedKey == pattern || strings.HasSuffix(normalizedKey, pattern) {
			debugLog("Pattern matched: %s -> key: %s", pattern, fullKey)
			return true, fullKey
		}
	}

	// Log if no matches were found
	debugLog("Pattern did not match for: %s", pattern)
	return false, ""
}

// evaluateCondition checks if the condition is met
func evaluateCondition(blockContent map[string]string, condition string) bool {
	if condition == "" {
		return true
	}

	parts := strings.SplitN(condition, "=", 2)
	if len(parts) != 2 {
		return false
	}

	key := strings.TrimSpace(parts[0])
	value := strings.TrimSpace(parts[1])

	if val, exists := blockContent[key]; exists {
		return val == value
	}

	return false
}

// readFile reads a file into a slice of strings
func readFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	var text []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		text = append(text, scanner.Text())
	}
	return text, scanner.Err()
}

// writeFile writes a slice of strings back to the file
func writeFile(filename string, lines []string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %v", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, line := range lines {
		_, err := writer.WriteString(line + "\n")
		if err != nil {
			return fmt.Errorf("failed to write to file: %v", err)
		}
	}
	return writer.Flush()
}
