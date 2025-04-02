package main

import (
	"flag"
	"log"
	"yaml-encrypter-decrypter/pkg/processor"

	"github.com/awnumar/memguard"
)

var debug bool

func init() {
	flag.BoolVar(&debug, "debug", false, "Enable debug mode")
	memguard.CatchInterrupt() // Handle interrupt signals securely
}

func main() {
	defer memguard.Purge() // Purge sensitive data when the program exits

	// Command-line flags
	flagFile := flag.String("filename", "", "YAML file to encode/decode")
	flagOperation := flag.String("operation", "", "Available operations: encrypt, decrypt")
	flagDryRun := flag.Bool("dry-run", false, "Output only, no file changes")

	flag.Parse()

	if *flagFile == "" || *flagOperation == "" {
		log.Fatal("Please specify --filename and --operation (encrypt or decrypt)")
	}

	// Load encryption key securely
	encryptionKey := memguard.NewBufferFromBytes([]byte("your-encryption-key")) // Replace with secure loading
	defer encryptionKey.Destroy()

	// Process YAML file using processor package
	err := processor.ProcessFile(*flagFile, string(encryptionKey.Bytes()), *flagOperation, *flagDryRun, debug)
	if err != nil {
		log.Fatalf("Error processing file: %v", err)
	}
}
