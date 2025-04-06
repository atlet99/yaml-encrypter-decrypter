package main

import (
	"log"

	"github.com/atlet99/yaml-encrypter-decrypter/pkg/encryption"
	"github.com/atlet99/yaml-encrypter-decrypter/pkg/processor"
)

// setKeyDerivationAlgorithm sets the algorithm for both encryption and processor
func setKeyDerivationAlgorithm(algorithm encryption.KeyDerivationAlgorithm, debug bool) {
	if debug {
		log.Printf("Using key derivation algorithm: %s", algorithm)
	}
	encryption.DefaultKeyDerivationAlgorithm = algorithm
	processor.CurrentKeyDerivationAlgorithm = algorithm
}
