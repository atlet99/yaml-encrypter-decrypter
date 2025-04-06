package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/atlet99/yaml-encrypter-decrypter/pkg/processor"
	"github.com/awnumar/memguard"
	"gopkg.in/yaml.v3"
)

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
