package socks

import (
	"regexp"
	"testing"
)

func TestDynamicUsernameGenerator(t *testing.T) {
	gen := NewDynamicUsernameGenerator()

	// Test cases for dynamic username generation
	testCases := []struct {
		template string
		expected string // regex pattern to match expected result
	}{
		{
			template: "X_us_{sid-8}",
			expected: `^X_us_[a-zA-Z0-9]{8}$`,
		},
		{
			template: "user_{sid-4}_test_{sid-6}",
			expected: `^user_[a-zA-Z0-9]{4}_test_[a-zA-Z0-9]{6}$`,
		},
		{
			template: "static_username",
			expected: `^static_username$`,
		},
		{
			template: "{sid-12}",
			expected: `^[a-zA-Z0-9]{12}$`,
		},
		{
			template: "prefix_{sid-0}_suffix",   // Edge case: 0 length
			expected: `^prefix_{sid-0}_suffix$`, // Should remain unchanged
		},
	}

	for _, tc := range testCases {
		t.Run(tc.template, func(t *testing.T) {
			result := gen.GenerateUsername(tc.template)
			matched, err := regexp.MatchString(tc.expected, result)
			if err != nil {
				t.Fatalf("Invalid regex pattern: %v", err)
			}
			if !matched {
				t.Errorf("Generated username '%s' doesn't match expected pattern '%s'", result, tc.expected)
			}

			// Test that multiple generations produce different results for dynamic patterns
			if gen.HasDynamicPattern(tc.template) && tc.template != "prefix_{sid-0}_suffix" {
				result2 := gen.GenerateUsername(tc.template)
				if result == result2 {
					t.Logf("Warning: Two consecutive generations produced the same result: %s", result)
					// This is theoretically possible but very unlikely, so we just log it
				}
			}
		})
	}
}

func TestHasDynamicPattern(t *testing.T) {
	gen := NewDynamicUsernameGenerator()

	testCases := []struct {
		username string
		expected bool
	}{
		{"X_us_{sid-8}", true},
		{"user_{sid-4}", true},
		{"static_username", false},
		{"{sid-12}", true},
		{"user_with_braces_{not-sid}", false},
		{"multiple_{sid-4}_patterns_{sid-6}", true},
	}

	for _, tc := range testCases {
		t.Run(tc.username, func(t *testing.T) {
			result := gen.HasDynamicPattern(tc.username)
			if result != tc.expected {
				t.Errorf("HasDynamicPattern('%s') = %v, expected %v", tc.username, result, tc.expected)
			}
		})
	}
}

func TestAccountGetEffectiveUsername(t *testing.T) {
	testCases := []struct {
		username      string
		expectDynamic bool
	}{
		{"X_us_{sid-8}", true},
		{"static_user", false},
		{"proxy_{sid-6}_test", true},
	}

	for _, tc := range testCases {
		t.Run(tc.username, func(t *testing.T) {
			account := &Account{
				Username: tc.username,
				Password: "testpass",
			}

			result := account.GetEffectiveUsername()

			if tc.expectDynamic {
				// For dynamic usernames, result should be different from template
				if result == tc.username {
					t.Errorf("Expected dynamic username generation for '%s', but got same result", tc.username)
				}

				// Verify the pattern is correctly replaced
				gen := NewDynamicUsernameGenerator()
				expectedPattern := gen.pattern.ReplaceAllString(tc.username, "[a-zA-Z0-9]+")
				matched, err := regexp.MatchString("^"+expectedPattern+"$", result)
				if err != nil {
					t.Fatalf("Invalid regex pattern: %v", err)
				}
				if !matched {
					t.Errorf("Generated username '%s' doesn't match expected pattern '%s'", result, expectedPattern)
				}
			} else {
				// For static usernames, result should be the same
				if result != tc.username {
					t.Errorf("Expected static username '%s', but got '%s'", tc.username, result)
				}
			}
		})
	}
}

func BenchmarkDynamicUsernameGeneration(b *testing.B) {
	gen := NewDynamicUsernameGenerator()
	template := "X_us_{sid-8}"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		gen.GenerateUsername(template)
	}
}

func BenchmarkAccountGetEffectiveUsername(b *testing.B) {
	account := &Account{
		Username: "X_us_{sid-8}",
		Password: "testpass",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		account.GetEffectiveUsername()
	}
}
