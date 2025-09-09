package socks

import (
	"regexp"
	"strings"
	"testing"
	"time"
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

func TestKeepAliveUsernameGeneration(t *testing.T) {
	gen := NewDynamicUsernameGenerator()

	testCases := []struct {
		name     string
		template string
		expected string // regex pattern to match expected result
	}{
		{
			name:     "keep alive 30 seconds",
			template: "brd-customer-hl_cf5708be-zone-novamed-country-us-session-{sid-8}{kp-30}",
			expected: `^brd-customer-hl_cf5708be-zone-novamed-country-us-session-[a-zA-Z0-9]{8}$`,
		},
		{
			name:     "keep alive 60 seconds",
			template: "user_{sid-4}{kp-60}",
			expected: `^user_[a-zA-Z0-9]{4}$`,
		},
		{
			name:     "no keep alive",
			template: "user_{sid-6}",
			expected: `^user_[a-zA-Z0-9]{6}$`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// First generation
			result1 := gen.GenerateUsername(tc.template)
			matched, err := regexp.MatchString(tc.expected, result1)
			if err != nil {
				t.Fatalf("Invalid regex pattern: %v", err)
			}
			if !matched {
				t.Errorf("Generated username '%s' doesn't match expected pattern '%s'", result1, tc.expected)
			}

			// Second generation immediately after
			result2 := gen.GenerateUsername(tc.template)

			if strings.Contains(tc.template, "{kp-") {
				// Should return the same cached username
				if result1 != result2 {
					t.Errorf("Expected cached username '%s', but got different username '%s'", result1, result2)
				}
			} else {
				// Should generate different username each time
				if result1 == result2 {
					t.Logf("Warning: Two consecutive generations produced the same result for non-cached template: %s", result1)
				}
			}
		})
	}
}

func TestKeepAliveExpiration(t *testing.T) {
	gen := NewDynamicUsernameGenerator()
	template := "test_{sid-4}{kp-1}" // 1 second keep alive

	// Generate first username
	result1 := gen.GenerateUsername(template)

	// Should get the same username immediately
	result2 := gen.GenerateUsername(template)
	if result1 != result2 {
		t.Errorf("Expected cached username '%s', but got '%s'", result1, result2)
	}

	// Wait for expiration (1.1 seconds to be sure)
	time.Sleep(1100 * time.Millisecond)

	// Should generate a new username after expiration
	result3 := gen.GenerateUsername(template)
	if result1 == result3 {
		t.Errorf("Expected different username after expiration, but got the same: %s", result1)
	}
}

func TestExtractKeepDuration(t *testing.T) {
	gen := NewDynamicUsernameGenerator()

	testCases := []struct {
		template string
		expected int
	}{
		{"user_{sid-8}{kp-30}", 30},
		{"user_{sid-8}{kp-60}", 60},
		{"user_{sid-8}", 0},
		{"user_{kp-invalid}", 0},
		{"user_{kp-0}", 0},
		{"user_{sid-8}{kp-120}", 120},
	}

	for _, tc := range testCases {
		t.Run(tc.template, func(t *testing.T) {
			result := gen.extractKeepDuration(tc.template)
			if result != tc.expected {
				t.Errorf("Expected duration %d, got %d for template '%s'", tc.expected, result, tc.template)
			}
		})
	}
}

func TestCacheCleanup(t *testing.T) {
	gen := NewDynamicUsernameGenerator()
	template := "test_{sid-4}{kp-30}"

	// Generate a username to populate cache
	gen.GenerateUsername(template)

	// Check cache size
	if gen.GetCacheSize() != 1 {
		t.Errorf("Expected cache size 1, got %d", gen.GetCacheSize())
	}

	// Cleanup should not remove recent entries
	gen.CleanupExpiredCache()
	if gen.GetCacheSize() != 1 {
		t.Errorf("Expected cache size 1 after cleanup, got %d", gen.GetCacheSize())
	}
}
