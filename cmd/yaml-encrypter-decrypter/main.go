package main

import (
	"flag"
	"log"
	"os"
	"path/filepath"

	"github.com/atlet99/yaml-encrypter-decrypter/pkg/encryption"
	"github.com/atlet99/yaml-encrypter-decrypter/pkg/processor"

	"github.com/awnumar/memguard"
)

// Version is set during build time
var Version = "dev"

const (
	// Version parts
	VersionParts = 2
)

func main() {
	// Safe termination when receiving interrupt signal
	memguard.CatchInterrupt()

	// Run main code and exit with returned code
	code := mainWithExitCode()

	// Clean up at the end of execution
	memguard.Purge()

	// Exit with the return code
	os.Exit(code)
}

func mainWithExitCode() int {
	// Parse command line arguments
	flags := parseFlags()

	// Show version if requested
	if flags.showVersion {
		displayVersion()
		return 0
	}

	// Run benchmarks if requested
	if flags.benchmark {
		// If no benchmark file is specified, use console output
		benchFile := flags.benchFile
		return runBenchmarks(benchFile)
	}

	// Get encryption key (from flag or environment)
	key, err := getEncryptionKey(flags.key, flags.debug)
	if err != nil {
		log.Println(err)
		flag.Usage()
		return 1
	}

	// Validate required flags
	if flags.filename == "" || key == "" || flags.operation == "" {
		log.Println("Error: filename, key, and operation are required")
		flag.Usage()
		return 1
	}

	// Validate and set algorithm flag if provided
	keyDerivation, err := encryption.ValidateAlgorithm(flags.algorithm)
	if err != nil {
		log.Println(err)
		return 1
	}

	// Create a secure buffer for the key
	keyBuffer := memguard.NewBufferFromBytes([]byte(key))
	defer keyBuffer.Destroy()

	// Determine the config path
	configFilePath := ".yed_config.yml"
	if flags.configPath != "" {
		configFilePath = flags.configPath
		if flags.debug {
			log.Printf("Using custom config path: %s\n", configFilePath)
		}
	}

	// Convert relative path to absolute path
	if !filepath.IsAbs(configFilePath) {
		absPath, err := filepath.Abs(configFilePath)
		if err == nil {
			configFilePath = absPath
			if flags.debug {
				log.Printf("Using absolute config path: %s\n", configFilePath)
			}
		} else {
			log.Printf("Warning: could not convert %s to absolute path: %v\n", configFilePath, err)
		}
	}

	// Update flags.configPath with the resolved path
	flags.configPath = configFilePath

	// Load rules from config file
	rules, _, err := processor.LoadRules(configFilePath, flags.debug)
	if err != nil {
		log.Printf("Error loading rules: %v\n", err)
		return 1
	}

	// Set the encryption algorithm if specified
	if keyDerivation != "" {
		encryption.SetDefaultAlgorithm(keyDerivation)
	}

	// Process file and handle interruption
	return processFileWithInterruptHandling(flags, keyBuffer, rules)
}
