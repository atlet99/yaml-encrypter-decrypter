package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/atlet99/yaml-encrypter-decrypter/pkg/processor"

	"github.com/awnumar/memguard"
)

// Version is set during build time
var Version = "dev"

func main() {
	os.Exit(mainWithExitCode())
}

func mainWithExitCode() int {
	// Parse command line arguments
	filename := flag.String("file", "", "Path to the YAML file")
	key := flag.String("key", "", "Encryption/decryption key")
	operation := flag.String("operation", "", "Operation to perform (encrypt/decrypt)")
	dryRun := flag.Bool("dry-run", false, "Print the result without modifying the file")
	diff := flag.Bool("diff", false, "Show differences between original and encrypted values (only works with --dry-run)")
	debug := flag.Bool("debug", false, "Enable debug logging")
	showVersion := flag.Bool("version", false, "Show version information")
	flag.Parse()

	// Show version if requested
	if *showVersion {
		displayVersion()
		return 0
	}

	// Validate required flags
	if *filename == "" || *key == "" || *operation == "" {
		log.Println("Error: all flags are required")
		flag.Usage()
		return 1
	}

	// Validate diff flag
	if *diff && !*dryRun {
		log.Println("Error: --diff flag can only be used with --dry-run")
		flag.Usage()
		return 1
	}

	// Initialize memguard
	memguard.CatchInterrupt()
	defer memguard.Purge()

	// Run the main logic
	if err := run(*filename, *key, *operation, *dryRun, *debug, *diff); err != nil {
		log.Printf("Error: %v\n", err)
		return 1
	}

	return 0
}

// displayVersion prints the version information in a formatted way
func displayVersion() {
	// Check if version contains build information
	if strings.Contains(Version, "(build ") {
		// Extract version part (before the build info)
		parts := strings.Split(Version, " (build ")
		if len(parts) == 2 {
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

func run(filename, key, operation string, dryRun, debug, diff bool) error {
	// Create a secure buffer for the key
	keyBuffer := memguard.NewBufferFromBytes([]byte(key))
	defer keyBuffer.Destroy()

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Create error channel
	errChan := make(chan error, 1)

	// Process file in a goroutine
	go func() {
		errChan <- processor.ProcessFile(filename, string(keyBuffer.Bytes()), operation, dryRun, debug, diff)
	}()

	// Wait for either completion or interruption
	select {
	case err := <-errChan:
		return err
	case <-sigChan:
		return fmt.Errorf("operation interrupted")
	}
}
