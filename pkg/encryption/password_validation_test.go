package encryption

import (
	"testing"
)

func TestValidatePasswordStrength(t *testing.T) {
	tests := []struct {
		name          string
		password      string
		expectError   bool
		checkProblems bool
		problems      []string
	}{
		{
			name:        "valid password with mixed characters",
			password:    "SecureP@ssw0rd",
			expectError: false,
		},
		{
			name:        "valid complex password",
			password:    "This-Is-A-V3ry-L0ng&Complex-Passw0rd!",
			expectError: false,
		},
		{
			name:          "too short password",
			password:      "abc123",
			expectError:   true,
			checkProblems: true,
			problems:      []string{"Password must be at least 8 characters long"},
		},
		{
			name:          "too long password",
			password:      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()_+",
			expectError:   true,
			checkProblems: true,
			problems:      []string{"Password must not exceed 64 characters"},
		},
		{
			name:          "common password",
			password:      "password123",
			expectError:   true,
			checkProblems: true,
			problems:      []string{"Password is too common and easily guessable"},
		},
		{
			name:        "non-common password with minimal strength",
			password:    "uncommon12345",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePasswordStrength(tt.password)

			if tt.expectError && err == nil {
				t.Errorf("ValidatePasswordStrength() expected error for password '%s', got nil", tt.password)
				return
			}

			if !tt.expectError && err != nil {
				t.Errorf("ValidatePasswordStrength() unexpected error for password '%s': %v", tt.password, err)
				return
			}

			if tt.checkProblems && err != nil {
				passwordErr, ok := err.(*PasswordStrengthError)
				if !ok {
					t.Errorf("Expected PasswordStrengthError, got different error type: %T", err)
					return
				}

				// Check if all expected problems are present
				for _, problem := range tt.problems {
					found := false
					for _, errProblem := range passwordErr.Problems {
						if errProblem == problem {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("Expected problem '%s' not found in error", problem)
					}
				}
			}
		})
	}
}

func TestCalculatePasswordStrength(t *testing.T) {
	tests := []struct {
		name     string
		password string
		want     string
	}{
		{
			name:     "high strength password",
			password: "SecureP@ssw0rd123",
			want:     PasswordHighStrength,
		},
		{
			name:     "medium strength password",
			password: "Securepassword",
			want:     PasswordMediumStrength,
		},
		{
			name:     "low strength password",
			password: "onlyletters",
			want:     PasswordLowStrength,
		},
		{
			name:     "short password",
			password: "abc",
			want:     PasswordLowStrength,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := calculatePasswordStrength(tt.password)
			if got != tt.want {
				t.Errorf("calculatePasswordStrength() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSuggestPasswordImprovement(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantAny  []string
	}{
		{
			name:     "missing uppercase",
			password: "password123!",
			wantAny:  []string{"Add uppercase letters"},
		},
		{
			name:     "missing lowercase",
			password: "PASSWORD123!",
			wantAny:  []string{"Add lowercase letters"},
		},
		{
			name:     "missing digits",
			password: "Password!",
			wantAny:  []string{"Add numbers"},
		},
		{
			name:     "missing special chars",
			password: "Password123",
			wantAny:  []string{"Add special characters"},
		},
		{
			name:     "short but complex",
			password: "P@ss1",
			wantAny:  []string{"Increase password length"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SuggestPasswordImprovement(tt.password)

			for _, wantSuggestion := range tt.wantAny {
				found := false
				for _, suggestion := range got {
					if suggestion != "" && willFind(suggestion, wantSuggestion) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("SuggestPasswordImprovement() should contain '%s', got %v", wantSuggestion, got)
				}
			}
		})
	}
}

// willFind checks if a string contains another string
func willFind(s, substr string) bool {
	return s == substr || contains(s, substr)
}

// contains checks if a string contains another string
func contains(s, substr string) bool {
	for i := 0; i < len(s); i++ {
		if i+len(substr) <= len(s) && s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
