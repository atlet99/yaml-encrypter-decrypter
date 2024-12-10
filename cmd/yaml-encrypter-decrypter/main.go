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

// Default configuration for the app
var defaultConfig = &Config{
	Encryption: struct {
		Key       string   `yaml:"key"`
		EnvBlocks []string `yaml:"env_blocks"`
	}{
		Key:       "",
		EnvBlocks: []string{"variable.default if sensitive = true"},
	},
	Logging: struct {
		Level string `yaml:"level"`
	}{
		Level: "DEBUG",
	},
}

// Version is set during build time using -ldflags
var Version = "dev"

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
		log.Printf("Warning: %v", err)
		config = defaultConfig // Use default configuration if .yed_config.yml is missing
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
		log.Printf("Config file %s not found, using default configuration...", configFile)
		return defaultConfig, nil
	} else if err != nil {
		return nil, fmt.Errorf("could not open config file: %v", err)
	}
	defer file.Close()

	decoder := yaml.NewDecoder(file)
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("could not decode config YAML: %v", err)
	}

	// Warn if the key is stored in the config file
	if config.Encryption.Key != "" {
		log.Println("Warning: Storing the encryption key in the config file is insecure. Use the YED_ENCRYPTION_KEY environment variable instead.")
	}

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

	var currentBlock []string
	var processingBlock bool

	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)

		// Detect the start of a new block
		if strings.HasSuffix(trimmedLine, "{") {
			if processingBlock {
				processBlock(currentBlock, envBlocks, key, operation, dryRun)
			}

			processingBlock = true
			currentBlock = []string{line}
			continue
		}

		// Detect the end of a block
		if processingBlock && trimmedLine == "}" {
			currentBlock = append(currentBlock, line)
			processBlock(currentBlock, envBlocks, key, operation, dryRun)
			processingBlock = false
			continue
		}

		// Add lines to the current block
		if processingBlock {
			currentBlock = append(currentBlock, line)
		} else {
			// Process non-block lines
			if dryRun {
				fmt.Println(line)
			} else {
				fmt.Println("Unprocessed:", line)
			}
		}
	}
}

// processBlock handles encryption/decryption for a block
func processBlock(block []string, envBlocks []string, key, operation string, dryRun bool) {
	blockContent := parseBlockContent(block)

	for _, envBlock := range envBlocks {
		pattern, condition := parseEnvBlock(envBlock)
		matched, targetKey := matchesPattern(blockContent, pattern)
		if matched && evaluateCondition(blockContent, condition) {
			processKey(block, blockContent, targetKey, key, operation, dryRun)
		}
	}
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
	parts := strings.Split(envBlock, " if ")
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return envBlock, ""
}

// matchesPattern checks if the block matches the pattern
func matchesPattern(blockContent map[string]string, pattern string) (bool, string) {
	regex := regexp.MustCompile(`([a-zA-Z0-9_]+)\.(.+)`)
	matches := regex.FindStringSubmatch(pattern)
	if len(matches) == 3 {
		blockType := matches[1]
		targetKey := matches[2]

		if blockType == "*" || blockContent["block_type"] == blockType {
			return true, targetKey
		}
	}
	return false, ""
}

// evaluateCondition checks if the condition is met
func evaluateCondition(blockContent map[string]string, condition string) bool {
	if condition == "" {
		return true
	}
	parts := strings.Split(condition, "=")
	if len(parts) == 2 {
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if val, exists := blockContent[key]; exists {
			return val == value
		}
	}
	return false
}

// processKey encrypts/decrypts a specific key in the block
func processKey(block []string, blockContent map[string]string, targetKey, key, operation string, dryRun bool) {
	value, exists := blockContent[targetKey]
	if !exists {
		return
	}

	// Trim quotes around the value if present
	value = strings.Trim(value, `"'`)

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
			return
		}
	} else {
		log.Fatalf("Invalid operation: %v", operation)
	}

	// Wrap the processed value in quotes if it was originally quoted
	if strings.HasPrefix(blockContent[targetKey], `"`) || strings.HasPrefix(blockContent[targetKey], `'`) {
		processedValue = fmt.Sprintf(`"%s"`, processedValue)
	}

	if dryRun {
		fmt.Printf("%s = %s\n", targetKey, processedValue)
	} else {
		fmt.Printf("Processed: %s = %s\n", targetKey, processedValue)
	}
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
