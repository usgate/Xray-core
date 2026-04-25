package username

import (
	"regexp"
	"testing"
	"time"
)

func TestGenerateBoundUsernameReusesValueForSameKey(t *testing.T) {
	gen := NewDynamicUsernameGenerator()
	template := "user_{sid-12}"

	first := gen.GenerateBoundUsername(template, "203.0.113.10|residential-out")
	second := gen.GenerateBoundUsername(template, "203.0.113.10|residential-out")

	if first != second {
		t.Fatalf("expected bound username to be stable, got %q and %q", first, second)
	}

	matched, err := regexp.MatchString(`^user_[a-zA-Z0-9]{12}$`, first)
	if err != nil {
		t.Fatalf("invalid regex: %v", err)
	}
	if !matched {
		t.Fatalf("generated username %q does not match expected pattern", first)
	}
}

func TestGenerateBoundUsernameSeparatesDifferentKeys(t *testing.T) {
	gen := NewDynamicUsernameGenerator()
	template := "user_{did-16}"

	first := gen.GenerateBoundUsername(template, "203.0.113.10|residential-out")
	second := gen.GenerateBoundUsername(template, "203.0.113.11|residential-out")

	if first == second {
		t.Fatalf("expected different binding keys to produce different usernames, got %q", first)
	}

	matched, err := regexp.MatchString(`^user_[0-9]{16}$`, first)
	if err != nil {
		t.Fatalf("invalid regex: %v", err)
	}
	if !matched {
		t.Fatalf("generated username %q does not match expected pattern", first)
	}
}

func TestGenerateBoundUsernameIgnoresKeepAliveRotation(t *testing.T) {
	gen := NewDynamicUsernameGenerator()
	template := "user_{sid-8}{kp-1}"

	first := gen.GenerateBoundUsername(template, "203.0.113.10|residential-out")
	time.Sleep(1100 * time.Millisecond)
	second := gen.GenerateBoundUsername(template, "203.0.113.10|residential-out")

	if first != second {
		t.Fatalf("expected keep-alive not to rotate bound username, got %q and %q", first, second)
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
				t.Errorf("expected duration %d, got %d for template %q", tc.expected, result, tc.template)
			}
		})
	}
}

func TestCleanupOldEntries(t *testing.T) {
	gen := NewDynamicUsernameGenerator()
	baseTemplate := "test_{sid-4}"

	gen.mutex.Lock()
	gen.cache[baseTemplate] = &UsernameCache{
		username:    "testABCD",
		generatedAt: time.Now().Add(-15 * time.Minute),
	}
	gen.mutex.Unlock()

	if gen.GetCacheSize() != 1 {
		t.Fatalf("expected cache size 1 before cleanup, got %d", gen.GetCacheSize())
	}

	gen.CleanupExpiredCache()

	if gen.GetCacheSize() != 0 {
		t.Fatalf("expected cache size 0 after cleanup, got %d", gen.GetCacheSize())
	}
}
