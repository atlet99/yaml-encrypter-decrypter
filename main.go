package main

import (
	"atlet99/yaml-encrypter-decrypter/encryption"
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
)

const AES = "AES256:"

func main() {
	// Flag parameters
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
		fmt.Println(encryption.Decrypt(*flagKey, strings.TrimPrefix(*flagValue, AES)))
	} else {
		fmt.Println(AES + encryption.Encrypt(*flagKey, *flagValue))
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

// processYamlLine processes each line of the YAML file, either appending it to output or printing it (if dry-run)
func processYamlLine(line string, envs []string, key, operation string, dryRun bool) {
	if isEnvBlock(strings.TrimSpace(line), envs) {
		// Processing the line within the env block
		fmt.Println("Processing env block:", line)
		// Add your encryption/decryption logic here
	} else {
		// Default handling for lines outside of env blocks
		fmt.Println(line)
	}
}
