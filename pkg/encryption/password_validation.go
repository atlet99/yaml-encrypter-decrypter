package encryption

import (
	"fmt"
	"strings"
	"unicode"
)

const (
	// PasswordMinLength is the minimum recommended password length (NIST SP800-63B)
	PasswordMinLength = 8

	// PasswordMaxLength is the maximum supported password length (NIST SP800-63B)
	// Allowing long passwords for passphrases while preventing DoS attacks
	PasswordMaxLength = 64

	// PasswordRecommendedLength is the recommended minimum password length for enhanced security
	PasswordRecommendedLength = 16

	// PasswordLowStrength represents a password with only one character type
	PasswordLowStrength = "Low"

	// PasswordMediumStrength represents a password with two or three character types
	PasswordMediumStrength = "Medium"

	// PasswordHighStrength represents a password with all character types
	PasswordHighStrength = "High"
)

var (
	// Common breached passwords to block (this should be expanded or use an API like Pwned Passwords)
	commonPasswords = map[string]bool{
		"password":    true,
		"123456":      true,
		"qwerty":      true,
		"admin":       true,
		"welcome":     true,
		"123456789":   true,
		"12345678":    true,
		"abc123":      true,
		"password1":   true,
		"password123": true,
		"iloveyou":    true,
		"1234567":     true,
		"12345":       true,
		"monkey":      true,
		"letmein":     true,
		"dragon":      true,
		"baseball":    true,
		"sunshine":    true,
		"princess":    true,
		"superman":    true,
		"trustno1":    true,
		"1234":        true,
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
	var problems []string

	// Check password length
	if len(password) < PasswordMinLength {
		problems = append(problems, fmt.Sprintf("Password must be at least %d characters long", PasswordMinLength))
	}

	if len(password) > PasswordMaxLength {
		problems = append(problems, fmt.Sprintf("Password must not exceed %d characters", PasswordMaxLength))
	}

	// Check if it's a common password
	if commonPasswords[strings.ToLower(password)] {
		problems = append(problems, "Password is too common and easily guessable")
	}

	strength := calculatePasswordStrength(password)

	// If we found problems, return them
	if len(problems) > 0 {
		return &PasswordStrengthError{
			Message:   "Password does not meet strength requirements",
			Problems:  problems,
			Strength:  strength,
			IsCommon:  commonPasswords[strings.ToLower(password)],
			MinLength: PasswordMinLength,
			MaxLength: PasswordMaxLength,
		}
	}

	return nil
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
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
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

	// Rate the password
	switch {
	case charTypes == 4 && len(password) >= PasswordMinLength*2:
		return PasswordHighStrength
	case charTypes >= 2 && len(password) >= PasswordMinLength:
		return PasswordMediumStrength
	default:
		return PasswordLowStrength
	}
}

// IsPasswordBreached checks if a password is in a known breach database
// This is a placeholder that should be replaced with an actual API call to Pwned Passwords or similar service
func IsPasswordBreached(password string) (bool, error) {
	// For actual implementation, integrate with haveibeenpwned API or self-hosted pwned passwords database
	// Example API: https://haveibeenpwned.com/API/v3

	// This is a simplified implementation that just checks against our common passwords list
	return commonPasswords[strings.ToLower(password)], nil
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
