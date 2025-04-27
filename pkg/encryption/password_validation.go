package encryption

import (
	"fmt"
	"strings"
	"unicode"
)

const (
	// PasswordMinLength is the minimum recommended password length (NIST SP800-63B)
	PasswordMinLength = 15

	// PasswordMaxLength is the maximum supported password length (NIST SP800-63B)
	// Allowing long passwords for passphrases while preventing DoS attacks
	PasswordMaxLength = 64

	// PasswordRecommendedLength is the recommended minimum password length for enhanced security
	PasswordRecommendedLength = 15

	// PasswordLowStrength represents a password with only one character type
	PasswordLowStrength = "Low"

	// PasswordMediumStrength represents a password with two or three character types
	PasswordMediumStrength = "Medium"

	// PasswordHighStrength represents a password with all character types
	PasswordHighStrength = "High"

	// AllowedSpecialChars contains the set of allowed special characters according to OWASP
	AllowedSpecialChars = "!@#$%^&*()_+-=[]{}|;:,.<>?"

	// CharacterTypeCounts for password strength evaluation
	OneCharType    = 1
	TwoCharTypes   = 2
	ThreeCharTypes = 3
	FourCharTypes  = 4
)

var (
	// Common breached passwords to block (this should be expanded or use an API like Pwned Passwords)
	commonPasswords = map[string]bool{
		"password":          true,
		"123456":            true,
		"qwerty":            true,
		"admin":             true,
		"welcome":           true,
		"123456789":         true,
		"12345678":          true,
		"abc123":            true,
		"password1":         true,
		"password123":       true,
		"iloveyou":          true,
		"1234567":           true,
		"12345":             true,
		"monkey":            true,
		"letmein":           true,
		"dragon":            true,
		"baseball":          true,
		"sunshine":          true,
		"princess":          true,
		"superman":          true,
		"trustno1":          true,
		"1234":              true,
		"password123456789": true,
	}
)

// PasswordStrengthError represents errors related to password strength
type PasswordStrengthError struct {
	Message   string   `json:"message"`
	Problems  []string `json:"problems"`
	Strength  string   `json:"strength"`
	IsCommon  bool     `json:"is_common"`
	MinLength int      `json:"min_length"`
	MaxLength int      `json:"max_length"`
}

// Error returns the error message
func (e *PasswordStrengthError) Error() string {
	return e.Message
}

// ValidatePasswordStrength checks if a password meets strength requirements
func ValidatePasswordStrength(password string) error {
	fmt.Printf("[DEBUG] Validating password strength (length: %d)\n", len(password))

	var problems []string

	// Check for Cyrillic characters
	if containsCyrillic(password) {
		fmt.Printf("[DEBUG] Password contains Cyrillic characters\n")
		problems = append(problems, "Password must not contain Cyrillic characters")
	}

	// Check password length
	if len(password) < PasswordMinLength {
		fmt.Printf("[DEBUG] Password too short (minimum: %d)\n", PasswordMinLength)
		problems = append(problems, fmt.Sprintf("Password must be at least %d characters long", PasswordMinLength))
	}

	if len(password) > PasswordMaxLength {
		fmt.Printf("[DEBUG] Password too long (maximum: %d)\n", PasswordMaxLength)
		problems = append(problems, fmt.Sprintf("Password must not exceed %d characters", PasswordMaxLength))
	}

	// Check for allowed special characters
	var hasAllowedSpecial bool
	for _, char := range password {
		if strings.ContainsRune(AllowedSpecialChars, char) {
			hasAllowedSpecial = true
			break
		}
	}
	if !hasAllowedSpecial {
		fmt.Printf("[DEBUG] Password missing special characters\n")
		problems = append(problems, fmt.Sprintf("Password must contain at least one special character from: %s", AllowedSpecialChars))
	}

	// Check for character types
	var hasUpper, hasLower, hasDigit bool
	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasDigit = true
		}
	}

	if !hasUpper {
		fmt.Printf("[DEBUG] Password missing uppercase letters\n")
		problems = append(problems, "Password must contain at least one uppercase letter")
	}

	if !hasLower {
		fmt.Printf("[DEBUG] Password missing lowercase letters\n")
		problems = append(problems, "Password must contain at least one lowercase letter")
	}

	if !hasDigit {
		fmt.Printf("[DEBUG] Password missing digits\n")
		problems = append(problems, "Password must contain at least one digit")
	}

	// Check for character sequences
	if hasCharacterSequence(password) {
		fmt.Printf("[DEBUG] Password contains character sequences\n")
		problems = append(problems, "Password must not contain character sequences (e.g., abc, 123)")
	}

	// Check if it's a common password
	if isCommonPassword(password) {
		fmt.Printf("[DEBUG] Password is too common\n")
		problems = append(problems, "Password is too common and easily guessable")
	}

	strength := calculatePasswordStrength(password)
	fmt.Printf("[DEBUG] Password strength: %s\n", strength)

	// If we found problems, return them
	if len(problems) > 0 {
		fmt.Printf("[DEBUG] Password validation failed with %d problems\n", len(problems))
		return &PasswordStrengthError{
			Message:   "Password does not meet strength requirements",
			Problems:  problems,
			Strength:  strength,
			IsCommon:  isCommonPassword(password),
			MinLength: PasswordMinLength,
			MaxLength: PasswordMaxLength,
		}
	}

	fmt.Printf("[DEBUG] Password validation successful\n")
	return nil
}

// containsCyrillic checks if the string contains any Cyrillic characters
func containsCyrillic(s string) bool {
	for _, r := range s {
		if (r >= 'а' && r <= 'я') || (r >= 'А' && r <= 'Я') || r == 'ё' || r == 'Ё' {
			return true
		}
	}
	return false
}

// hasCharacterSequence checks if the password contains character sequences
func hasCharacterSequence(password string) bool {
	// Check for sequences of 3 or more consecutive characters
	for i := 0; i < len(password)-2; i++ {
		// Check for ascending sequences (e.g., abc, 123)
		if password[i]+1 == password[i+1] && password[i+1]+1 == password[i+2] {
			return true
		}
		// Check for descending sequences (e.g., cba, 321)
		if password[i]-1 == password[i+1] && password[i+1]-1 == password[i+2] {
			return true
		}
	}
	return false
}

// calculatePasswordStrength rates the password strength
func calculatePasswordStrength(password string) string {
	if len(password) < PasswordMinLength {
		return PasswordLowStrength
	}

	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasDigit = true
		case strings.ContainsRune(AllowedSpecialChars, char):
			hasSpecial = true
		}
	}

	// Count character types
	charTypes := 0
	if hasUpper {
		charTypes++
	}
	if hasLower {
		charTypes++
	}
	if hasDigit {
		charTypes++
	}
	if hasSpecial {
		charTypes++
	}

	// Rate the password based on number of character types
	switch charTypes {
	case OneCharType:
		return PasswordLowStrength
	case TwoCharTypes:
		return PasswordMediumStrength
	case ThreeCharTypes, FourCharTypes:
		return PasswordHighStrength
	default:
		return PasswordLowStrength
	}
}

// isCommonPassword checks if a password is in our list of common passwords
// This separate function avoids direct reference to the password in logs or error messages
func isCommonPassword(password string) bool {
	// Check both full password and its parts
	if commonPasswords[strings.ToLower(password)] {
		return true
	}

	// Check password parts
	for commonPass := range commonPasswords {
		if strings.Contains(strings.ToLower(password), commonPass) {
			return true
		}
	}

	return false
}

// IsPasswordBreached checks if a password is in a known breach database
// This is a placeholder that should be replaced with an actual API call to Pwned Passwords or similar service
func IsPasswordBreached(password string) (bool, error) {
	// For actual implementation, integrate with haveibeenpwned API or self-hosted pwned passwords database
	// Example API: https://haveibeenpwned.com/API/v3

	// This is a simplified implementation that just checks against our common passwords list
	return isCommonPassword(password), nil
}

// SuggestPasswordImprovement provides suggestions to improve password strength
func SuggestPasswordImprovement(password string) []string {
	var suggestions []string

	if len(password) < PasswordMinLength {
		suggestions = append(suggestions, fmt.Sprintf("Increase password length to at least %d characters", PasswordMinLength))
	}

	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasDigit = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	if !hasUpper {
		suggestions = append(suggestions, "Add uppercase letters")
	}

	if !hasLower {
		suggestions = append(suggestions, "Add lowercase letters")
	}

	if !hasDigit {
		suggestions = append(suggestions, "Add numbers")
	}

	if !hasSpecial {
		suggestions = append(suggestions, "Add special characters (e.g., !@#$%^&*)")
	}

	if len(password) < PasswordRecommendedLength {
		suggestions = append(suggestions, "Consider using a longer passphrase for better security")
	}

	return suggestions
}
