package encryption

import (
	"encoding/base64"
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
}

func TestInvalidBase64String(t *testing.T) {
	password := "strongpassword"
	invalidBase64 := "invalid base64 text!"

	_, err := Decrypt(password, invalidBase64)
	if err == nil {
		t.Fatal("expected error for invalid base64 encoded text, got none")
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
	invalidCipherText := base64.StdEncoding.EncodeToString([]byte("short"))

	_, err := Decrypt(password, invalidCipherText)
	if err == nil {
		t.Fatal("expected error for invalid ciphertext format, got none")
	}
}

func TestInvalidIVLength(t *testing.T) {
	password := "strongpassword"
	plaintext := "Sample text"

	encrypted, err := Encrypt(password, plaintext)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	modifiedEncrypted := "invalidIVinvalidIV" + encrypted[16:]

	_, err = Decrypt(password, modifiedEncrypted)
	if err == nil {
		t.Fatal("expected error for invalid IV, got none")
	}
}

func TestShortAndLongPassword(t *testing.T) {
	plaintext := "Data with short and long password"

	shortPassword := "pwd"
	encrypted, err := Encrypt(shortPassword, plaintext)
	if err != nil {
		t.Fatalf("failed to encrypt with short password: %v", err)
	}

	decrypted, err := Decrypt(shortPassword, encrypted)
	if err != nil || decrypted != plaintext {
		t.Fatalf("decryption failed with short password, expected %s got %s", plaintext, decrypted)
	}

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

func TestUnpadError(t *testing.T) {
	// Case 1: Padding byte larger than data length
	invalidPadding := []byte{5, 5, 5, 5, 5}
	_, err := unpad(invalidPadding)
	if err == nil {
		t.Fatal("Expected error for invalid padding length, got none")
	} else {
		t.Logf("Received expected error for invalid padding length: %v", err)
	}

	// Case 2: Zero padding byte at the end, which is invalid in PKCS#7
	invalidZeroPadding := []byte{1, 2, 3, 0}
	_, err = unpad(invalidZeroPadding)
	if err == nil {
		t.Fatal("Expected error for zero padding, got none")
	} else {
		t.Logf("Received expected error for zero padding: %v", err)
	}

	// Case 3: Inconsistent padding bytes (not all padding bytes are the same)
	inconsistentPadding := []byte{1, 2, 3, 2, 4}
	_, err = unpad(inconsistentPadding)
	if err == nil {
		t.Fatal("Expected error for inconsistent padding, got none")
	} else {
		t.Logf("Received expected error for inconsistent padding: %v", err)
	}

	// Case 4: Padding byte larger than actual data length
	excessivePadding := []byte{10, 10, 10}
	_, err = unpad(excessivePadding)
	if err == nil {
		t.Fatal("Expected error for padding exceeding data length, got none")
	} else {
		t.Logf("Received expected error for padding exceeding data length: %v", err)
	}
}
