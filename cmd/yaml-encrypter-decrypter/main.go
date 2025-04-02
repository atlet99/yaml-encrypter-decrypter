package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"yaml-encrypter-decrypter/pkg/processor"

	"github.com/awnumar/memguard"
)

func main() {
	// Parse command line arguments
	filename := flag.String("file", "", "YAML file to process")
	key := flag.String("key", "", "Encryption key")
	operation := flag.String("operation", "encrypt", "Operation to perform (encrypt/decrypt)")
	dryRun := flag.Bool("dry-run", false, "Show changes without applying them")
	debug := flag.Bool("debug", false, "Enable debug logging")
	flag.Parse()

	// Validate required arguments
	if *filename == "" {
		log.Fatal("Error: -file argument is required")
	}
	if *key == "" {
		log.Fatal("Error: -key argument is required")
	}
	if *operation != "encrypt" && *operation != "decrypt" {
		log.Fatal("Error: -operation must be either 'encrypt' or 'decrypt'")
	}

	// Create a secure buffer for the encryption key
	keyBuffer := memguard.NewBufferFromBytes([]byte(*key))
	defer keyBuffer.Destroy()

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Process the file
	errChan := make(chan error, 1)
	go func() {
		errChan <- processor.ProcessFile(*filename, string(keyBuffer.Bytes()), *operation, *dryRun, *debug)
	}()

	// Wait for either completion or interruption
	select {
	case err := <-errChan:
		if err != nil {
			log.Fatalf("Error processing file: %v", err)
		}
	case <-sigChan:
		log.Println("\nReceived interrupt signal. Cleaning up...")
		// Clean up resources
		keyBuffer.Destroy()
		os.Exit(1)
	}
}
