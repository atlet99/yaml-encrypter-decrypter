package encryption

import (
	"strings"
	"testing"
)

func TestValidatePasswordStrength(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{
			name:     "valid password",
			password: "P@ssw0rd_Str0ng!T3st#2024",
			wantErr:  false,
		},
		{
			name:     "too short password",
			password: "short",
			wantErr:  true,
		},
		{
			name:     "too long password",
			password: strings.Repeat("a", 65),
			wantErr:  true,
		},
		{
			name:     "common password",
			password: "password123456789",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePasswordStrength(tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePasswordStrength() error = %v, wantErr %v", err, tt.wantErr)
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
			name:     "low strength password",
			password: "password123456789",
			want:     PasswordLowStrength,
		},
		{
			name:     "medium strength password",
			password: "P@ssw0rd12345678",
			want:     PasswordMediumStrength,
		},
		{
			name:     "high strength password",
			password: "P@ssw0rd_Str0ng!T3st#2024",
			want:     PasswordHighStrength,
		},
		{
			name:     "short password",
			password: "P@ss1",
			want:     PasswordLowStrength,
		},
		{
			name:     "long password with two types",
			password: "PasswordPasswordPassword",
			want:     PasswordMediumStrength,
		},
		{
			name:     "password with three types",
			password: "P@ssw0rd12345678",
			want:     PasswordHighStrength,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := calculatePasswordStrength(tt.password); got != tt.want {
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
			password: "password123456789!",
			wantAny:  []string{"Add uppercase letters"},
		},
		{
			name:     "missing lowercase",
			password: "PASSWORD123456789!",
			wantAny:  []string{"Add lowercase letters"},
		},
		{
			name:     "missing digits",
			password: "Password!Password!",
			wantAny:  []string{"Add numbers"},
		},
		{
			name:     "missing special chars",
			password: "Password123456789",
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
