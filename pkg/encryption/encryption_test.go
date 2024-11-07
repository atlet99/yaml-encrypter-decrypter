package encryption

import (
	"encoding/base64"
	"testing"
)

// TestEncryptDecrypt checks that encryption and decryption work as expected.
func TestEncryptDecrypt(t *testing.T) {
	password := "strongpassword"
	plaintext := "Powered by YED!"

	encrypted, err := Encrypt(password, plaintext)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	decrypted, err := Decrypt(password, encrypted)
	if err != nil {
		t.Fatalf("failed to decrypt: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("expected %s, got %s", plaintext, decrypted)
	}
}

// TestEmptyPlaintext checks that an error is returned when encrypting an empty plaintext.
func TestEmptyPlaintext(t *testing.T) {
	password := "strongpassword"
	plaintext := ""

	_, err := Encrypt(password, plaintext)
	if err == nil {
		t.Fatal("expected error for empty plaintext, got none")
	}
}

// TestInvalidBase64String checks that an error is returned for an invalid base64 input.
func TestInvalidBase64String(t *testing.T) {
	password := "strongpassword"
	invalidBase64 := "invalid base64 text!"

	_, err := Decrypt(password, invalidBase64)
	if err == nil {
		t.Fatal("expected error for invalid base64 encoded text, got none")
	}
}

// TestIncorrectPassword checks that an error is returned when using the wrong password for decryption.
func TestIncorrectPassword(t *testing.T) {
	password := "strongpassword"
	wrongPassword := "wrongpassword"
	plaintext := "Sensitive data!"

	encrypted, err := Encrypt(password, plaintext)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	_, err = Decrypt(wrongPassword, encrypted)
	if err == nil {
		t.Fatal("expected error for incorrect password, got none")
	}
}

// TestSpecialCharacters checks encryption and decryption of a string with special characters.
func TestSpecialCharacters(t *testing.T) {
	password := "strongpassword"
	plaintext := "Special chars: !@#$%^&*()_+-=[]{}|;':\",./<>?`~"

	encrypted, err := Encrypt(password, plaintext)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	decrypted, err := Decrypt(password, encrypted)
	if err != nil {
		t.Fatalf("failed to decrypt: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("expected %s, got %s", plaintext, decrypted)
	}
}

// TestInvalidCipherTextFormat checks that an error is returned for an invalid ciphertext format.
func TestInvalidCipherTextFormat(t *testing.T) {
	password := "strongpassword"
	invalidCipherText := base64.StdEncoding.EncodeToString([]byte("short"))

	_, err := Decrypt(password, invalidCipherText)
	if err == nil {
		t.Fatal("expected error for invalid ciphertext format, got none")
	}
}

// TestInvalidIVLength checks that an error is returned when IV length is incorrect.
func TestInvalidIVLength(t *testing.T) {
	password := "strongpassword"
	plaintext := "Sample text"

	encrypted, err := Encrypt(password, plaintext)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	// Tamper with the IV by replacing the first 16 bytes
	modifiedEncrypted := "invalidIVinvalidIV" + encrypted[16:]

	_, err = Decrypt(password, modifiedEncrypted)
	if err == nil {
		t.Fatal("expected error for invalid IV, got none")
	}
}

// TestShortAndLongPassword checks encryption and decryption with both short and long passwords.
func TestShortAndLongPassword(t *testing.T) {
	plaintext := "Data with short and long password"

	// Test with a very short password
	shortPassword := "pwd"
	encrypted, err := Encrypt(shortPassword, plaintext)
	if err != nil {
		t.Fatalf("failed to encrypt with short password: %v", err)
	}

	decrypted, err := Decrypt(shortPassword, encrypted)
	if err != nil || decrypted != plaintext {
		t.Fatalf("decryption failed with short password, expected %s got %s", plaintext, decrypted)
	}

	// Test with a very long password
	longPassword := "thisisaveryveryverylongpasswordthatexceedsthirtytwocharacters"
	encrypted, err = Encrypt(longPassword, plaintext)
	if err != nil {
		t.Fatalf("failed to encrypt with long password: %v", err)
	}

	decrypted, err = Decrypt(longPassword, encrypted)
	if err != nil || decrypted != plaintext {
		t.Fatalf("decryption failed with long password, expected %s got %s", plaintext, decrypted)
	}
}

// TestUnpadError checks that unpad returns an error for invalid padding.
func TestUnpadError(t *testing.T) {
	// Invalid padded data that will cause an error in unpad
	invalidPaddedData := []byte{5, 5, 5, 5, 5} // Padding value exceeds data length

	_, err := unpad(invalidPaddedData)
	if err == nil {
		t.Fatal("expected error for invalid padding, got none")
	}

	// Additional invalid padding case where padding is zero
	invalidPaddedDataZero := []byte{1, 2, 3, 0}
	_, err = unpad(invalidPaddedDataZero)
	if err == nil {
		t.Fatal("expected error for zero padding, got none")
	}
}
