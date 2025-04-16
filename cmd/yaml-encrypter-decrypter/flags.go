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
	configPath  string
}

// parseFlags parses command line arguments and returns an appFlags struct
func parseFlags() appFlags {
	// Define flags with short and long forms
	var flags appFlags

	// Required flags for main operation
	flag.StringVar(&flags.filename, "file", "", "Path to the YAML file")
	flag.StringVar(&flags.filename, "f", "", "")

	flag.StringVar(&flags.key, "key", "", "Encryption/decryption key")
	flag.StringVar(&flags.key, "k", "", "")

	flag.StringVar(&flags.operation, "operation", "", "Operation to perform (encrypt/decrypt)")
	flag.StringVar(&flags.operation, "o", "", "")

	// Operation control flags
	flag.BoolVar(&flags.dryRun, "dry-run", false, "Print the result without modifying the file")
	flag.BoolVar(&flags.dryRun, "d", false, "")

	flag.BoolVar(&flags.diff, "diff", false, "Show differences between original and encrypted values")
	flag.BoolVar(&flags.diff, "D", false, "")

	// Logging and information flags
	flag.BoolVar(&flags.debug, "debug", false, "Enable debug logging")
	flag.BoolVar(&flags.debug, "v", false, "")

	flag.BoolVar(&flags.showVersion, "version", false, "Show version information")
	flag.BoolVar(&flags.showVersion, "V", false, "")

	// Advanced configuration flags
	flag.StringVar(&flags.algorithm, "algorithm", "", "Key derivation algorithm to use (argon2id, pbkdf2-sha256, pbkdf2-sha512)")
	flag.StringVar(&flags.algorithm, "a", "", "")

	flag.StringVar(&flags.configPath, "config", "", "Path to the .yed_config.yml file (default: .yed_config.yml in current directory)")
	flag.StringVar(&flags.configPath, "c", "", "")

	// Performance analysis flags
	flag.BoolVar(&flags.benchmark, "benchmark", false, "Run performance benchmarks")
	flag.BoolVar(&flags.benchmark, "b", false, "")

	flag.StringVar(&flags.benchFile, "bench-file", "", "Path to save benchmark results (default: stdout)")
	flag.StringVar(&flags.benchFile, "B", "", "")

	// Override default usage
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "Options:")

		// Print flags in organized groups
		fmt.Fprintln(os.Stderr, "  Required for encryption/decryption:")
		fmt.Fprintln(os.Stderr, "    -file, -f string     Path to the YAML file")
		fmt.Fprintln(os.Stderr, "    -key, -k string      Encryption/decryption key")
		fmt.Fprintln(os.Stderr, "    -operation, -o string Operation to perform (encrypt/decrypt)")
		fmt.Fprintln(os.Stderr, "")

		fmt.Fprintln(os.Stderr, "  Operation control:")
		fmt.Fprintln(os.Stderr, "    -dry-run, -d         Print the result without modifying the file")
		fmt.Fprintln(os.Stderr, "    -diff, -D            Show differences between original and encrypted values")
		fmt.Fprintln(os.Stderr, "")

		fmt.Fprintln(os.Stderr, "  Logging and information:")
		fmt.Fprintln(os.Stderr, "    -debug, -v           Enable debug logging")
		fmt.Fprintln(os.Stderr, "    -version, -V         Show version information")
		fmt.Fprintln(os.Stderr, "")

		fmt.Fprintln(os.Stderr, "  Advanced configuration:")
		fmt.Fprintln(os.Stderr, "    -algorithm, -a string Key derivation algorithm (argon2id, pbkdf2-sha256, pbkdf2-sha512)")
		fmt.Fprintln(os.Stderr, "    -config, -c string    Path to the .yed_config.yml file (default: .yed_config.yml)")
		fmt.Fprintln(os.Stderr, "")

		fmt.Fprintln(os.Stderr, "  Performance analysis:")
		fmt.Fprintln(os.Stderr, "    -benchmark, -b       Run performance benchmarks")
		fmt.Fprintln(os.Stderr, "    -bench-file, -B string Path to save benchmark results (default: stdout)")
	}

	flag.Parse()

	return flags
}

// getEncryptionKey returns the encryption key from flag or environment variable
func getEncryptionKey(flagKey string, debug bool) (string, error) {
	var key string

	if flagKey != "" {
		key = flagKey
	} else {
		envKey := os.Getenv("YED_ENCRYPTION_KEY")
		if envKey != "" {
			if debug {
				fmt.Println("[DEBUG] Using encryption key from YED_ENCRYPTION_KEY environment variable")
			}
			key = envKey
		}
	}

	if key == "" {
		return "", fmt.Errorf("error: encryption key not provided")
	}

	// Validate key length
	if len(key) < encryption.PasswordRecommendedLength {
		return "", fmt.Errorf("error: encryption key must be at least %d characters long for adequate security", encryption.PasswordRecommendedLength)
	}

	return key, nil
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
		return "", fmt.Errorf("error: invalid algorithm '%s'. Valid options are: argon2id, pbkdf2-sha256, pbkdf2-sha512", algorithm)
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
