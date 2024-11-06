package encryption

import (
	"testing"
)

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

func TestEmptyPlaintext(t *testing.T) {
	password := "strongpassword"
	plaintext := ""

	_, err := Encrypt(password, plaintext)
	if err == nil {
		t.Fatal("expected error for empty plaintext, got none")
	}

	decrypted, err := Decrypt(password, "")
	if err == nil {
		t.Fatal("expected error for empty encrypted text, got none")
	}

	if decrypted != "" {
		t.Errorf("expected empty string, got %s", decrypted)
	}
}

func TestIncorrectPassword(t *testing.T) {
	password := "strongpassword"
	wrongPassword := "wrongpassword"
	plaintext := "Sensitive data!"

	encrypted, err := Encrypt(password, plaintext)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	// Attempt decryption with an incorrect password
	_, err = Decrypt(wrongPassword, encrypted)
	if err == nil {
		t.Fatal("expected error for incorrect password, got none")
	}
}

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

func TestInvalidCipherTextFormat(t *testing.T) {
	password := "strongpassword"
	invalidCipherText := "Invalid base64 text!"

	_, err := Decrypt(password, invalidCipherText)
	if err == nil {
		t.Fatal("expected error for invalid base64 encoded text, got none")
	}
}

func TestInvalidIVLength(t *testing.T) {
	password := "strongpassword"
	plaintext := "Sample text"

	// Encrypt text to generate a valid ciphertext
	encrypted, err := Encrypt(password, plaintext)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	// Modify the IV by changing the first 16 bytes to simulate an invalid IV
	modifiedEncrypted := "invalidIVinvalidIV" + encrypted[16:]

	_, err = Decrypt(password, modifiedEncrypted)
	if err == nil {
		t.Fatal("expected error for invalid IV, got none")
	}
}

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
