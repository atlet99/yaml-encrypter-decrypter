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
	// Padding larger than the length of data
	invalidPaddedData := []byte{4, 4, 4, 4}
	_, err := unpad(invalidPaddedData)
	if err == nil {
		t.Fatal("expected error for invalid padding, got none")
	}

	// Zero padding, which is invalid
	invalidPaddedDataZero := []byte{1, 2, 3, 0}
	_, err = unpad(invalidPaddedDataZero)
	if err == nil {
		t.Fatal("expected error for zero padding, got none")
	}

	// Padding value larger than the length of data
	invalidPaddedDataExceedsLength := []byte{10, 10, 10}
	_, err = unpad(invalidPaddedDataExceedsLength)
	if err == nil {
		t.Fatal("expected error for padding exceeding data length, got none")
	}

	// Inconsistent padding bytes
	inconsistentPadding := []byte{1, 2, 3, 2, 4}
	_, err = unpad(inconsistentPadding)
	if err == nil {
		t.Fatal("expected error for inconsistent padding, got none")
	}
}
