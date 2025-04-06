package main

import (
	"flag"
	"log"
	"os"

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
	os.Exit(mainWithExitCode())
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
	keyDerivation, err := validateAlgorithm(flags.algorithm)
	if err != nil {
		log.Println(err)
		return 1
	}

	// Initialize memguard
	memguard.CatchInterrupt()
	defer memguard.Purge()

	// Create a secure buffer for the key
	keyBuffer := memguard.NewBufferFromBytes([]byte(key))
	defer keyBuffer.Destroy()

	// Load rules from config file
	rules, _, err := processor.LoadRules(".yed_config.yml", flags.debug)
	if err != nil {
		log.Printf("Error loading rules: %v\n", err)
		return 1
	}

	// Set the encryption algorithm if specified
	if keyDerivation != "" {
		setKeyDerivationAlgorithm(keyDerivation, flags.debug)
	}

	// Process file and handle interruption
	return processFileWithInterruptHandling(flags, keyBuffer, rules)
}
