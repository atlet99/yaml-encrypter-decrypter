package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/atlet99/yaml-encrypter-decrypter/pkg/encryption"
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
	benchmark   bool
	benchFile   string
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
	benchmark := flag.Bool("benchmark", false, "Run performance benchmarks")
	benchFile := flag.String("bench-file", "", "Path to save benchmark results (default: stdout)")
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
		benchmark:   *benchmark,
		benchFile:   *benchFile,
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
