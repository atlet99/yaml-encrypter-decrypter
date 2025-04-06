package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/atlet99/yaml-encrypter-decrypter/pkg/encryption"
	"github.com/atlet99/yaml-encrypter-decrypter/pkg/processor"

	"github.com/awnumar/memguard"
	"gopkg.in/yaml.v3"
)

// Version is set during build time
var Version = "dev"

const (
	// Version parts
	VersionParts = 2
)

// CLI flags
type appFlags struct {
	filename    string
	key         string
	operation   string
	dryRun      bool
	diff        bool
	debug       bool
	showVersion bool
	algorithm   string
}

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

// parseFlags parses command line arguments and returns an appFlags struct
func parseFlags() appFlags {
	filename := flag.String("file", "", "Path to the YAML file")
	key := flag.String("key", "", "Encryption/decryption key")
	operation := flag.String("operation", "", "Operation to perform (encrypt/decrypt)")
	dryRun := flag.Bool("dry-run", false, "Print the result without modifying the file")
	diff := flag.Bool("diff", false, "Show differences between original and encrypted values")
	debug := flag.Bool("debug", false, "Enable debug logging")
	showVersion := flag.Bool("version", false, "Show version information")
	algorithm := flag.String("algorithm", "", "Key derivation algorithm to use (argon2id, pbkdf2-sha256, pbkdf2-sha512)")
	flag.Parse()

	return appFlags{
		filename:    *filename,
		key:         *key,
		operation:   *operation,
		dryRun:      *dryRun,
		diff:        *diff,
		debug:       *debug,
		showVersion: *showVersion,
		algorithm:   *algorithm,
	}
}

// getEncryptionKey returns the encryption key from flag or environment variable
func getEncryptionKey(flagKey string, debug bool) (string, error) {
	if flagKey != "" {
		return flagKey, nil
	}

	envKey := os.Getenv("YED_ENCRYPTION_KEY")
	if envKey != "" {
		if debug {
			fmt.Println("[DEBUG] Using encryption key from YED_ENCRYPTION_KEY environment variable")
		}
		return envKey, nil
	}

	return "", fmt.Errorf("Error: encryption key not provided")
}

// validateAlgorithm validates the algorithm flag and returns the corresponding KeyDerivationAlgorithm
func validateAlgorithm(algorithm string) (encryption.KeyDerivationAlgorithm, error) {
	if algorithm == "" {
		return "", nil
	}

	switch strings.ToLower(algorithm) {
	case "argon2id":
		return encryption.Argon2idAlgorithm, nil
	case "pbkdf2-sha256":
		return encryption.PBKDF2SHA256Algorithm, nil
	case "pbkdf2-sha512":
		return encryption.PBKDF2SHA512Algorithm, nil
	default:
		return "", fmt.Errorf("Error: invalid algorithm '%s'. Valid options are: argon2id, pbkdf2-sha256, pbkdf2-sha512", algorithm)
	}
}

// setKeyDerivationAlgorithm sets the algorithm for both encryption and processor
func setKeyDerivationAlgorithm(algorithm encryption.KeyDerivationAlgorithm, debug bool) {
	if debug {
		log.Printf("Using key derivation algorithm: %s", algorithm)
	}
	encryption.DefaultKeyDerivationAlgorithm = algorithm
	processor.CurrentKeyDerivationAlgorithm = algorithm
}

// processFileWithInterruptHandling processes the file and handles interruption signals
func processFileWithInterruptHandling(flags appFlags, keyBuffer *memguard.LockedBuffer, rules []processor.Rule) int {
	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Create error channel
	errChan := make(chan error, 1)

	// Process file in a goroutine
	go func() {
		if flags.diff {
			errChan <- processor.ShowDiff(flags.filename, string(keyBuffer.Bytes()), flags.operation, flags.debug)
			return
		}

		if flags.dryRun {
			errChan <- handleDryRun(flags.filename, keyBuffer, flags.operation, rules, flags.debug)
			return
		}

		errChan <- processor.ProcessFile(flags.filename, string(keyBuffer.Bytes()), flags.operation, flags.debug)
	}()

	// Wait for either completion or interruption
	select {
	case err := <-errChan:
		if err != nil {
			log.Printf("Error: %v\n", err)
			return 1
		}
		return 0
	case <-sigChan:
		log.Println("Operation interrupted")
		return 1
	}
}

// handleDryRun processes the file for dry-run mode
func handleDryRun(filename string, keyBuffer *memguard.LockedBuffer, operation string, rules []processor.Rule, debug bool) error {
	content, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("error reading file: %v", err)
	}

	processedPaths := make(map[string]bool)
	node, err := processor.ProcessYAMLContent(content, string(keyBuffer.Bytes()), operation, rules, processedPaths, debug)
	if err != nil {
		return fmt.Errorf("error processing YAML content: %v", err)
	}

	encoder := yaml.NewEncoder(os.Stdout)
	encoder.SetIndent(processor.DefaultIndent)
	if err := encoder.Encode(node); err != nil {
		return fmt.Errorf("error encoding YAML: %v", err)
	}
	return nil
}

// displayVersion prints the version information in a formatted way
func displayVersion() {
	// Check if version contains build information
	if strings.Contains(Version, "(build ") {
		// Extract version part (before the build info)
		parts := strings.Split(Version, " (build ")
		if len(parts) == VersionParts {
			version := parts[0]
			buildNumber := strings.TrimSuffix(parts[1], ")")
			fmt.Printf("Version: %s\n", version)
			fmt.Printf("Build: %s\n", buildNumber)
		} else {
			fmt.Printf("Version: %s\n", Version)
		}
	} else {
		fmt.Printf("Version: %s\n", Version)
	}
}
