package socks

import (
	"crypto/rand"
	"regexp"
	"strconv"
	"strings"
)

// DynamicUsernameGenerator handles dynamic username generation for SOCKS5 proxy
type DynamicUsernameGenerator struct {
	pattern *regexp.Regexp
}

// NewDynamicUsernameGenerator creates a new dynamic username generator
func NewDynamicUsernameGenerator() *DynamicUsernameGenerator {
	// Pattern to match {sid-N} where N is the number of characters
	pattern := regexp.MustCompile(`\{sid-(\d+)\}`)
	return &DynamicUsernameGenerator{
		pattern: pattern,
	}
}

// GenerateUsername generates a dynamic username based on the template
// Template format: "X_us_{sid-8}" -> "X_us_A1b2C3d4"
func (g *DynamicUsernameGenerator) GenerateUsername(template string) string {
	return g.pattern.ReplaceAllStringFunc(template, func(match string) string {
		// Extract the number from {sid-N}
		matches := g.pattern.FindStringSubmatch(match)
		if len(matches) != 2 {
			return match // Return original if parsing fails
		}

		length, err := strconv.Atoi(matches[1])
		if err != nil || length <= 0 {
			return match // Return original if invalid length
		}

		return generateRandomString(length)
	})
}

// HasDynamicPattern checks if the username contains dynamic pattern
func (g *DynamicUsernameGenerator) HasDynamicPattern(username string) bool {
	return g.pattern.MatchString(username)
}

// generateRandomString generates a random alphanumeric string of specified length
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)

	// Use crypto/rand for secure random generation
	if _, err := rand.Read(b); err != nil {
		// Fallback to a simple implementation if crypto/rand fails
		return strings.Repeat("X", length)
	}

	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}

	return string(b)
}
