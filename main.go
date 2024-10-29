package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"yaml-encrypter-decrypter/encryption"
)

const AES = "AES256:"

// Version will be set during build time using -ldflags
var Version = "dev" // default to "dev" if version is not provided during build

func main() {

	// Command-line flags
	flagVersion := flag.Bool("version", false, "Show the version and exit")
	flagKey := flag.String("key", "", "AES key-password for encrypt/decrypt")
	flagDryRun := flag.Bool("dry-run", false, "Output only, no file changes")
	flagFile := flag.String("filename", "", "File to encode/decode")
	var flagEnv []string
	flag.Func("env", "Comma-separated YAML blocks to encode/decode", func(s string) error {
		flagEnv = strings.Split(s, ",")
		return nil
	})
	flagValue := flag.String("value", "", "Single value for encryption/decryption")
	flagOperation := flag.String("operation", "", "Available operations: encrypt, decrypt")
	flag.Parse()

	// If --version is specified, display version and exit
	if *flagVersion {
		fmt.Printf("yaml-encrypter-decrypter version: %s\n", Version)
		os.Exit(0)
	}

	log.SetFlags(0) // Disable timestamp in logging output

	if *flagKey == "" {
		log.Fatal("Please specify an environment variable \"YED-PASSWORD\" ")
	}

	// Handle a single value for encryption/decryption
	if *flagValue != "" {
		handleValue(flagKey, flagOperation, flagValue)
		return
	}

	if *flagOperation == "" {
		log.Fatal("Please, specify operation: encrypt or decrypt")
	}

	// Process the YAML file with encryption/decryption
	processYamlFile(*flagFile, flagEnv, *flagKey, *flagOperation, *flagDryRun)
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
	os.Exit(0)
}

// processYamlFile reads and processes a YAML file by encrypting or decrypting lines
func processYamlFile(filename string, envs []string, key, operation string, dryRun bool) {
	text := readFile(filename)
	for _, line := range text {
		processYamlLine(line, envs, key, operation, dryRun)
	}
}

// readFile opens and reads the content of a file, returning its lines
func readFile(filename string) []string {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatalf("failed to open file: %v", err)
	}
	defer file.Close()

	var text []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		text = append(text, scanner.Text())
	}
	return text
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

// processYamlLine processes each line of the YAML file, either encrypting or decrypting it based on the operation
func processYamlLine(line string, envs []string, key, operation string, dryRun bool) {
	trimmedLine := strings.TrimSpace(line)

	// Check if the line is in the specified environment block
	if isEnvBlock(trimmedLine, envs) {
		var processedLine string

		// Check for comments
		commentIndex := strings.Index(trimmedLine, "#")
		var comment string
		if commentIndex != -1 {
			comment = trimmedLine[commentIndex:]
			trimmedLine = strings.TrimSpace(trimmedLine[:commentIndex])
		}

		// Check if line contains quotes and extract the value to encrypt/decrypt
		if strings.Contains(trimmedLine, "\"") {
			valueStart := strings.Index(trimmedLine, "\"")
			valueEnd := strings.LastIndex(trimmedLine, "\"")
			if valueStart != valueEnd && valueStart != -1 && valueEnd != -1 {
				value := trimmedLine[valueStart+1 : valueEnd]

				// Encrypt or decrypt based on operation
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

		// Output the processed line or save it
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
