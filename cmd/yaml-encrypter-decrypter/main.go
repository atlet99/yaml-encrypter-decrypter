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
}

// Version will be set during build time using -ldflags
var Version = "dev" // default to "dev" if version is not provided during build

func main() {
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
	flag.Parse()

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

// loadConfig loads environment-specific configuration from YAML file
func loadConfig(env string) (*Config, error) {
	file := fmt.Sprintf("configs/%s.yaml", env)
	f, err := os.Open(file)
	if err != nil {
		return nil, fmt.Errorf("could not open config file: %w", err)
	}
	defer f.Close()

	var config Config
	decoder := yaml.NewDecoder(f)
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("could not decode config YAML: %w", err)
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
