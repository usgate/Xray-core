package username

import (
	"testing"
)

func TestIPBasedUsernameGeneration(t *testing.T) {
	gen := NewDynamicUsernameGenerator()

	// Test IP-based patterns
	testCases := []struct {
		template string
		clientIP string
		expected string // We'll check consistency instead of exact value
	}{
		{"user_{ip-sid-8}", "192.168.1.100", ""},
		{"user_{ip-did-6}", "192.168.1.100", ""},
		{"prefix_{ip-sid-4}_suffix", "10.0.0.1", ""},
		{"test_{ip-did-3}_{ip-sid-2}", "172.16.0.1", ""},
	}

	for _, tc := range testCases {
		// Generate username multiple times for the same IP
		result1 := gen.GenerateUsernameWithIP(tc.template, tc.clientIP)
		result2 := gen.GenerateUsernameWithIP(tc.template, tc.clientIP)
		result3 := gen.GenerateUsernameWithIP(tc.template, tc.clientIP)

		// Should be consistent for the same IP
		if result1 != result2 || result2 != result3 {
			t.Errorf("Username generation not consistent for IP %s with template %s: %s != %s != %s",
				tc.clientIP, tc.template, result1, result2, result3)
		}

		// Should be different for different IPs
		differentIP := "1.1.1.1"
		result4 := gen.GenerateUsernameWithIP(tc.template, differentIP)
		if result1 == result4 {
			t.Errorf("Username should be different for different IPs. Template: %s, IP1: %s (%s), IP2: %s (%s)",
				tc.template, tc.clientIP, result1, differentIP, result4)
		}

		t.Logf("Template: %s, IP: %s, Generated: %s", tc.template, tc.clientIP, result1)
	}
}

func TestIPBasedPatternValidation(t *testing.T) {
	gen := NewDynamicUsernameGenerator()

	// Test {ip-sid-N} pattern - should generate alphanumeric
	result := gen.GenerateUsernameWithIP("user_{ip-sid-8}", "192.168.1.1")
	if len(result) != len("user_")+8 {
		t.Errorf("Expected length %d, got %d for ip-sid-8 pattern", len("user_")+8, len(result))
	}

	// Test {ip-did-N} pattern - should generate digits only
	result2 := gen.GenerateUsernameWithIP("user_{ip-did-6}", "192.168.1.1")
	if len(result2) != len("user_")+6 {
		t.Errorf("Expected length %d, got %d for ip-did-6 pattern", len("user_")+6, len(result2))
	}

	// Extract the generated part and validate
	generated := result2[len("user_"):]
	for _, char := range generated {
		if char < '0' || char > '9' {
			t.Errorf("ip-did pattern should only generate digits, but got: %s", generated)
			break
		}
	}
}

func TestMixedPatterns(t *testing.T) {
	gen := NewDynamicUsernameGenerator()

	// Test mixing IP-based and regular patterns
	template := "user_{ip-sid-4}_{sid-3}_{ip-did-2}"
	clientIP := "10.0.0.100"

	result1 := gen.GenerateUsernameWithIP(template, clientIP)
	result2 := gen.GenerateUsernameWithIP(template, clientIP)

	// IP-based parts should be the same
	// Regular parts might be different (depending on implementation)
	t.Logf("Mixed pattern result for IP %s: %s", clientIP, result1)
	t.Logf("Mixed pattern result for IP %s: %s", clientIP, result2)

	// Test that it's not empty
	if result1 == "" || result2 == "" {
		t.Error("Generated username should not be empty")
	}
}

func TestFallbackToRegularGeneration(t *testing.T) {
	gen := NewDynamicUsernameGenerator()

	// Test template without IP-based patterns
	template := "user_{sid-8}"
	clientIP := "192.168.1.1"

	result := gen.GenerateUsernameWithIP(template, clientIP)

	// Should work even without IP patterns
	if len(result) != len("user_")+8 {
		t.Errorf("Expected length %d for fallback generation, got %d", len("user_")+8, len(result))
	}

	t.Logf("Fallback generation result: %s", result)
}

func TestHasIPBasedPattern(t *testing.T) {
	gen := NewDynamicUsernameGenerator()

	testCases := []struct {
		template string
		expected bool
	}{
		{"user_{ip-sid-8}", true},
		{"user_{ip-did-6}", true},
		{"user_{ip-sid-4}_{ip-did-2}", true},
		{"user_{sid-8}", false},
		{"user_{did-6}", false},
		{"user_static", false},
		{"user_{kp-30}", false},
	}

	for _, tc := range testCases {
		result := gen.hasIPBasedPattern(tc.template)
		if result != tc.expected {
			t.Errorf("hasIPBasedPattern(%s) = %t, expected %t", tc.template, result, tc.expected)
		}
	}
}

func TestDeterministicGeneration(t *testing.T) {
	// Test that the same IP always generates the same username part
	gen := NewDynamicUsernameGenerator()

	template := "test_{ip-sid-10}"
	ip1 := "192.168.1.100"
	ip2 := "10.0.0.1"

	// Generate multiple times for each IP
	results_ip1 := make([]string, 5)
	results_ip2 := make([]string, 5)

	for i := 0; i < 5; i++ {
		results_ip1[i] = gen.GenerateUsernameWithIP(template, ip1)
		results_ip2[i] = gen.GenerateUsernameWithIP(template, ip2)
	}

	// All results for the same IP should be identical
	for i := 1; i < 5; i++ {
		if results_ip1[0] != results_ip1[i] {
			t.Errorf("Non-deterministic generation for IP %s: %s != %s", ip1, results_ip1[0], results_ip1[i])
		}
		if results_ip2[0] != results_ip2[i] {
			t.Errorf("Non-deterministic generation for IP %s: %s != %s", ip2, results_ip2[0], results_ip2[i])
		}
	}

	// Results for different IPs should be different
	if results_ip1[0] == results_ip2[0] {
		t.Errorf("Same username generated for different IPs: %s and %s both produced %s",
			ip1, ip2, results_ip1[0])
	}

	t.Logf("IP %s consistently generates: %s", ip1, results_ip1[0])
	t.Logf("IP %s consistently generates: %s", ip2, results_ip2[0])
}
