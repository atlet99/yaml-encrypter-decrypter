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
	"gopkg.in/yaml.v3"
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
	filename := flag.String("file", "", "Path to the YAML file")
	key := flag.String("key", "", "Encryption/decryption key")
	operation := flag.String("operation", "", "Operation to perform (encrypt/decrypt)")
	dryRun := flag.Bool("dry-run", false, "Print the result without modifying the file")
	diff := flag.Bool("diff", false, "Show differences between original and encrypted values")
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

	// Initialize memguard
	memguard.CatchInterrupt()
	defer memguard.Purge()

	// Create a secure buffer for the key
	keyBuffer := memguard.NewBufferFromBytes([]byte(*key))
	defer keyBuffer.Destroy()

	// Load rules from config file
	rules, _, err := processor.LoadRules(".yed_config.yml", *debug)
	if err != nil {
		log.Printf("Error loading rules: %v\n", err)
		return 1
	}

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Create error channel
	errChan := make(chan error, 1)

	// Process file in a goroutine
	go func() {
		if *diff {
			errChan <- processor.ShowDiff(*filename, string(keyBuffer.Bytes()), *operation, *debug)
			return
		}

		if *dryRun {
			content, err := os.ReadFile(*filename)
			if err != nil {
				errChan <- fmt.Errorf("error reading file: %v", err)
				return
			}

			processedPaths := make(map[string]bool)
			node, err := processor.ProcessYAMLContent(content, string(keyBuffer.Bytes()), *operation, rules, processedPaths, *debug)
			if err != nil {
				errChan <- fmt.Errorf("error processing YAML content: %v", err)
				return
			}

			encoder := yaml.NewEncoder(os.Stdout)
			encoder.SetIndent(processor.DefaultIndent)
			if err := encoder.Encode(node); err != nil {
				errChan <- fmt.Errorf("error encoding YAML: %v", err)
				return
			}
			errChan <- nil
			return
		}

		errChan <- processor.ProcessFile(*filename, string(keyBuffer.Bytes()), *operation, *debug)
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
