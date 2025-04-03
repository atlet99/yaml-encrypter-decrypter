package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/atlet99/yaml-encrypter-decrypter/pkg/processor"

	"github.com/awnumar/memguard"
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
	debug := flag.Bool("debug", false, "Enable debug logging")
	flag.Parse()

	// Validate required flags
	if *filename == "" || *key == "" || *operation == "" {
		log.Println("Error: all flags are required")
		flag.Usage()
		return 1
	}

	// Initialize memguard
	memguard.CatchInterrupt()
	defer memguard.Purge()

	// Run the main logic
	if err := run(*filename, *key, *operation, *dryRun, *debug); err != nil {
		log.Printf("Error: %v\n", err)
		return 1
	}

	return 0
}

func run(filename, key, operation string, dryRun, debug bool) error {
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
		errChan <- processor.ProcessFile(filename, string(keyBuffer.Bytes()), operation, dryRun, debug)
	}()

	// Wait for either completion or interruption
	select {
	case err := <-errChan:
		return err
	case <-sigChan:
		return nil
	}
}
