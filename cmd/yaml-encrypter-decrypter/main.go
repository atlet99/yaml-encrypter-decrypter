package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
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

// Version is read from the .release-version file
var Version = getVersionFromFile(".release-version")

func main() {
	// Define flags
	flagVersion := flag.Bool("version", false, "Show the version and exit")
	flagKey := flag.String("key", "", "AES key-password for encrypt/decrypt")
	flagEnv := flag.String("env", "dev", "Environment (dev or test)")
	flagDryRun := flag.Bool("dry-run", false, "Output only, no file changes")
	flagFile := flag.String("filename", "", "File to encode/decode")
	var flagEnvBlocks []string
	flag.Func("env-blocks", "Comma-separated YAML blocks to encode/decode", func(s string) error {
		flagEnvBlocks = strings.Split(s, ",")
		return nil
	})
	flagValue := flag.String("value", "", "Single value for encryption/decryption")
	flagOperation := flag.String("operation", "", "Available operations: encrypt, decrypt")

	// Override the default usage function to include the version before displaying usage info
	flag.Usage = func() {
		fmt.Printf("yed version: %s\nUsage:\n", Version)
		flag.PrintDefaults()
	}

	// Parse flags
	flag.Parse()

	// If --version is specified, display version and exit
	if *flagVersion {
		fmt.Printf("yed version: %s\n", Version)
		return
	}

	log.SetFlags(0)

	// Load configuration based on environment
	config, err := loadConfig(*flagEnv)
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	// Override encryption key if provided
	if *flagKey == "" {
		*flagKey = config.Encryption.Key
	}

	if *flagKey == "" {
		log.Fatal("Please specify an encryption key or set it in the config file")
	}

	// Handle a single value for encryption/decryption
	if *flagValue != "" {
		handleValue(flagKey, flagOperation, flagValue)
		return
	}

	if *flagOperation == "" {
		log.Fatal("Please specify operation: encrypt or decrypt")
	}

	// Use env_blocks from config if no env blocks are passed in command-line
	if len(flagEnvBlocks) == 0 {
		flagEnvBlocks = config.Encryption.EnvBlocks
	}

	processYamlFile(*flagFile, flagEnvBlocks, *flagKey, *flagOperation, *flagDryRun)
}

// getVersionFromFile reads the last line from the specified file to set the version
func getVersionFromFile(filename string) string {
	file, err := os.Open(filename)
	if err != nil {
		log.Printf("Warning: Could not read version from %s: %v", filename, err)
		return "dev" // default version if file is not available
	}
	defer file.Close()

	var lastLine string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lastLine = scanner.Text()
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Warning: Error reading %s: %v", filename, err)
		return "dev"
	}

	return lastLine
}

// loadConfig loads environment-specific configuration from YAML files in order
func loadConfig(env string) (*Config, error) {
	baseConfigFile := "configs/values.yaml"
	envConfigFile := fmt.Sprintf("configs/%s.yaml", env)

	var config Config

	files := []string{baseConfigFile, envConfigFile}
	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			log.Printf("Skipping config file %s: %v", file, err)
			continue
		}
		defer f.Close()

		decoder := yaml.NewDecoder(f)
		if err := decoder.Decode(&config); err != nil {
			return nil, fmt.Errorf("could not decode config YAML from %s: %w", file, err)
		}
	}

	return &config, nil
}

// handleValue processes a single value for encryption or decryption based on the flag provided
func handleValue(flagKey, flagOperation, flagValue *string) {
	if strings.HasPrefix(*flagValue, AES) {
		decryptedValue, err := encryption.Decrypt(*flagKey, strings.TrimPrefix(*flagValue, AES))
		if err != nil {
			log.Fatalf("Error decrypting value: %v", err)
		}
		fmt.Println(decryptedValue)
	} else {
		encryptedValue, err := encryption.Encrypt(*flagKey, *flagValue)
		if err != nil {
			log.Fatalf("Error encrypting value: %v", err)
		}
		fmt.Println(AES + encryptedValue)
	}
}

func processYamlFile(filename string, envs []string, key, operation string, dryRun bool) {
	text, err := readFile(filename)
	if err != nil {
		log.Fatalf("Error reading file: %v", err)
	}
	for _, line := range text {
		processYamlLine(line, envs, key, operation, dryRun)
	}
}

// processYamlLine processes each line of the YAML file, either encrypting or decrypting it based on the operation
func processYamlLine(line string, envs []string, key, operation string, dryRun bool) {
	trimmedLine := strings.TrimSpace(line)

	// Check if the line is in the specified environment blocks
	if isEnvBlock(trimmedLine, envs) {
		var processedLine string

		// Check for comments in the line
		commentIndex := strings.Index(trimmedLine, "#")
		var comment string
		if commentIndex != -1 {
			comment = trimmedLine[commentIndex:]
			trimmedLine = strings.TrimSpace(trimmedLine[:commentIndex])
		}

		// Process quoted values for encryption/decryption
		if strings.Contains(trimmedLine, "\"") {
			valueStart := strings.Index(trimmedLine, "\"")
			valueEnd := strings.LastIndex(trimmedLine, "\"")
			if valueStart != valueEnd && valueStart != -1 && valueEnd != -1 {
				value := trimmedLine[valueStart+1 : valueEnd]

				// Encrypt or decrypt based on the operation
				if operation == "encrypt" {
					encryptedValue, err := encryption.Encrypt(key, value)
					if err != nil {
						log.Fatalf("Error encrypting line: %v", err)
					}
					processedLine = trimmedLine[:valueStart+1] + AES + encryptedValue + "\"" + " " + comment
				} else if operation == "decrypt" {
					if strings.HasPrefix(value, AES) {
						decryptedValue, err := encryption.Decrypt(key, strings.TrimPrefix(value, AES))
						if err != nil {
							log.Fatalf("Error decrypting line: %v", err)
						}
						processedLine = trimmedLine[:valueStart+1] + decryptedValue + "\"" + " " + comment
					} else {
						log.Printf("Skipping decryption, value is not encrypted: %s", value)
						processedLine = line
					}
				} else {
					log.Fatalf("Invalid operation: %v", operation)
				}
			}
		}

		// Output the processed line or print it for dry run
		if dryRun {
			fmt.Println(processedLine)
		} else {
			fmt.Println("Processed:", processedLine)
		}
	} else {
		// Default handling for lines outside of env blocks
		if dryRun {
			fmt.Println(line)
		} else {
			fmt.Println("Unprocessed:", line)
		}
	}
}

// isEnvBlock checks if the line belongs to one of the specified YAML blocks
func isEnvBlock(line string, envs []string) bool {
	for _, env := range envs {
		if strings.HasPrefix(line, env) {
			return true
		}
	}
	return false
}

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
