package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"yaml-encrypter-decrypter/pkg/encryption"

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
}

// debugLog logs messages only when debug mode is enabled
func debugLog(format string, v ...interface{}) {
	if debug {
		log.Printf("[DEBUG] "+format, v...)
	}
}

func main() {
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

	// Load configuration and determine encryption key
	config, err := loadConfig(".yed_config.yml")
	if err != nil {
		log.Fatalf("Error loading configuration: %v\nPlease create a .yed_config.yml file with proper settings.", err)
	}

	// Priority: Check YED_ENCRYPTION_KEY from the environment first
	encryptionKey := os.Getenv("YED_ENCRYPTION_KEY")
	if encryptionKey == "" {
		// Fallback to encryption.key in the config file
		encryptionKey = config.Encryption.Key
		if encryptionKey == "" {
			log.Fatal("Missing encryption key. Set the environment variable YED_ENCRYPTION_KEY or specify 'key' in .yed_config.yml")
		}
	}

	debugLog("Using encryption key: %s", encryptionKey)

	// Single value encryption/decryption
	if *flagValue != "" {
		handleValue(&encryptionKey, flagOperation, flagValue)
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

// handleValue processes a single value for encryption/decryption
func handleValue(key *string, flagOperation, flagValue *string) {
	if strings.HasPrefix(*flagValue, AES) {
		decryptedValue, err := encryption.Decrypt(*key, strings.TrimPrefix(*flagValue, AES))
		if err != nil {
			log.Fatalf("Error decrypting value: %v", err)
		}
		fmt.Println(decryptedValue)
	} else {
		encryptedValue, err := encryption.Encrypt(*key, *flagValue)
		if err != nil {
			log.Fatalf("Error encrypting value: %v", err)
		}
		fmt.Println(AES + encryptedValue)
	}
}

// processYamlFile processes a YAML file based on the specified env_blocks
func processYamlFile(filename string, envBlocks []string, key, operation string, dryRun bool) {
	lines, err := readFile(filename)
	if err != nil {
		log.Fatalf("Error reading file: %v", err)
	}

	var updatedLines []string
	var currentBlock []string
	var processingBlock bool

	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)

		// Detect the start of a new block
		if strings.HasSuffix(trimmedLine, "{") {
			if processingBlock {
				updatedLines = append(updatedLines, processBlock(currentBlock, envBlocks, key, operation, dryRun)...)
			}

			processingBlock = true
			currentBlock = []string{line}
			continue
		}

		// Detect the end of a block
		if processingBlock && trimmedLine == "}" {
			currentBlock = append(currentBlock, line)
			updatedLines = append(updatedLines, processBlock(currentBlock, envBlocks, key, operation, dryRun)...)
			processingBlock = false
			continue
		}

		// Add lines to the current block
		if processingBlock {
			currentBlock = append(currentBlock, line)
		} else {
			// Process non-block lines
			updatedLines = append(updatedLines, line)
		}
	}

	// If not dry-run, write the updated lines back to the file
	if !dryRun {
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
					updatedValue := processKey(block, blockContent, targetKey, key, operation, dryRun)
					if updatedValue != "" {
						updatedBlock[i] = updatedValue
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

// parseBlockContent parses the content of a block into a key-value map
func parseBlockContent(block []string) map[string]string {
	blockContent := make(map[string]string)
	for _, line := range block {
		trimmedLine := strings.TrimSpace(line)
		if strings.Contains(trimmedLine, "=") {
			parts := strings.SplitN(trimmedLine, "=", 2)
			if len(parts) == 2 {
				blockContent[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
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

// matchesPattern checks if the block matches the pattern
func matchesPattern(blockContent map[string]string, pattern string) (bool, string) {
	debugLog("Matching pattern: %s against blockContent: %+v", pattern, blockContent)

	regex := regexp.MustCompile(`([a-zA-Z0-9_]+)\.(.+)`)
	matches := regex.FindStringSubmatch(pattern)
	if len(matches) == 3 {
		blockType := matches[1]
		targetKey := matches[2]

		debugLog("Parsed pattern - blockType: %s, targetKey: %s", blockType, targetKey)

		if blockType == "*" || blockContent["type"] == blockType {
			return true, targetKey
		}

		// Allow matching blocks without an explicit type if blockType is "variable"
		if blockType == "variable" {
			return true, targetKey
		}
	}

	debugLog("Pattern did not match")
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
